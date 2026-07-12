// proves the managed client keeps requests concurrently in flight on one
// connection. the server parks every /wait request and releases them only once
// TWO are parked at the same time. a client that serialized requests would never
// reach two parked (it would wait for the first reply before sending the second)
// and deadlock; the concurrent managed client keeps both in flight, so the server
// reaches two and answers both. a timeout turns the serial-deadlock into a clean
// failure.
#![cfg(feature = "runtime")]

use nwep::{Address, Client, Identity, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

#[tokio::test]
async fn managed_client_keeps_two_requests_in_flight() {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let server_thread = std::thread::spawn(move || {
        // parked (conn, stream) of every deferred /wait request.
        let parked: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let parked_h = parked.clone();
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                if req.path() == Some("/wait") {
                    parked_h
                        .lock()
                        .unwrap()
                        .push((req.conn_id(), req.stream_id()));
                    res.defer()
                } else {
                    res.not_found()
                }
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            // release ALL parked requests once at least two are waiting together.
            let mut q = parked.lock().unwrap();
            if q.len() >= 2 {
                for (conn, stream) in q.drain(..) {
                    let _ = server.respond(conn, stream).send(Status::Ok, b"released");
                }
            }
            drop(q);
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let (node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect_async(&node, &Address::loopback(port))
        .await
        .unwrap();

    // two requests awaited concurrently. a serial client would deadlock here.
    let a = client.send(nwep::Method::Read, "/wait", &[]);
    let b = client.send(nwep::Method::Read, "/wait", &[]);
    let (ra, rb) = tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(a, b) })
        .await
        .expect("concurrent requests must not deadlock (a serial client would)");

    let ra = ra.expect("request a");
    let rb = rb.expect("request b");
    assert_eq!(ra.status(), Some(Status::Ok));
    assert_eq!(rb.status(), Some(Status::Ok));
    assert_eq!(ra.into_body(), b"released");
    assert_eq!(rb.into_body(), b"released");

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
