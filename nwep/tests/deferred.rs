// deferred responses and notify pushes NW000017 NW060200. a frontend
// server defers a request, fetches from a backend origin, then relays the origin
// response verbatim onto the parked stream (the nwproxy pattern)  -  and also
// answers a second route with a re-signed deferred respond. plus a server -> client
// notify push.

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

// a tiny origin server answering /thing, used as the proxy's backend.
fn spawn_origin() -> (
    nwep::NodeId,
    u16,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let handle = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(|req, res| match req.path() {
                Some("/thing") => res.ok(b"from-origin"),
                _ => res.not_found(),
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let (node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    (node, port, stop, handle)
}

#[test]
fn frontend_defers_then_relays_origin_and_respond() {
    let (origin_node, origin_port, origin_stop, origin_thread) = spawn_origin();

    // parked requests waiting for the loop to answer: (conn, stream, path).
    let parked: Arc<Mutex<Vec<(u64, u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let parked_h = parked.clone();

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let frontend = std::thread::spawn(move || {
        // the frontend's own backend client to the origin, on this thread.
        let backend = Client::builder()
            .identity(Identity::generate().unwrap())
            .connect(&origin_node, &Address::loopback(origin_port))
            .unwrap();

        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                // defer every request; the loop answers it out of band.
                let path = req.path().unwrap_or("").to_owned();
                parked_h
                    .lock()
                    .unwrap()
                    .push((req.conn_id(), req.stream_id(), path));
                res.defer()
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();

        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            for (conn, stream, path) in parked.lock().unwrap().drain(..) {
                match path.as_str() {
                    // relay: fetch the origin response and pass it through verbatim.
                    "/proxy" => {
                        let origin = backend.send(Method::Read, "/thing", &[]).unwrap();
                        server.respond(conn, stream).relay(&origin).unwrap();
                    }
                    // respond: answer with a fresh, server-signed message + header.
                    _ => {
                        server
                            .respond(conn, stream)
                            .header("x-served-by", "frontend")
                            .send(Status::Ok, b"deferred-ok")
                            .unwrap();
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    let (frontend_node, frontend_port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&frontend_node, &Address::loopback(frontend_port))
        .unwrap();

    // a relayed request returns the ORIGIN body verbatim.
    let relayed = client.send(Method::Read, "/proxy", &[]).unwrap();
    assert_eq!(relayed.status(), Some(Status::Ok));
    assert_eq!(relayed.into_body(), b"from-origin");

    // a re-signed deferred respond returns the frontend's body + header.
    let answered = client.send(Method::Read, "/direct", &[]).unwrap();
    assert_eq!(answered.status(), Some(Status::Ok));
    assert_eq!(answered.body(), b"deferred-ok");
    assert_eq!(answered.header("x-served-by"), Some("frontend"));

    stop.store(true, Ordering::Relaxed);
    origin_stop.store(true, Ordering::Relaxed);
    frontend.join().unwrap();
    origin_thread.join().unwrap();
}

#[test]
fn server_pushes_a_notify_the_client_polls() {
    let client_id = Identity::generate().unwrap();
    let client_node = *client_id.node_id();

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    // the handler records the conn so the loop can push a notify onto it.
    let conn = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let conn_h = conn.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                conn_h.store(req.conn_id(), Ordering::Relaxed);
                res.ok(b"hi")
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();
        let mut pushed = false;
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            let c = conn.load(Ordering::Relaxed);
            if !pushed && c != u64::MAX {
                server.notify(c, "build.done", b"v2").unwrap();
                pushed = true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    let (server_node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let client = Client::builder()
        .identity(client_id)
        .connect(&server_node, &Address::loopback(port))
        .unwrap();
    let _ = client_node;
    // a request establishes the connection (so the handler learns conn_id).
    client.send(Method::Read, "/x", &[]).unwrap();

    // poll for the pushed notify; it arrives within a few pumps.
    let mut event = None;
    for _ in 0..2000 {
        if let Some(n) = client.poll_notify() {
            event = n.header(":event").map(|s| s.to_owned());
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(event.as_deref(), Some("build.done"));

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
