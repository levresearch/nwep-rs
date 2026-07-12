// a real over-the-wire round trip, the proof that the server and client slices
// talk to each other through the actual c transport (not a mock). the server
// runs its driven tick loop on a background thread (where it is built, since the
// handle is !Send and never crosses a thread boundary) and a blocking client on
// the main thread connects, sends, and checks the answer. mirrors the
// nwcurl-against-nwserve proof from the sandbox, in process.

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, SystemTime};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[test]
fn server_answers_a_client_request_over_the_wire() {
    let server_id = Identity::generate().unwrap();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();

    // the server is built and driven entirely on this thread, so the !Send
    // handle never moves across a boundary NWG0900.
    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(|req, res| match req.path() {
                Some("/hello") => res.ok(b"hi there"),
                _ => res.not_found(),
            })
            .build()
            .unwrap();

        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();

        // driven loop: a real reactor would wait on server.fd() until
        // server.next_timeout(); a 1ms tick is plenty for a test.
        while !stop_for_thread.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    let (server_node, port) = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("server start");

    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&server_node, &Address::loopback(port))
        .expect("connect");

    let hello = client
        .send(Method::Read, "/hello", &[])
        .expect("send /hello");
    assert_eq!(hello.status(), Some(Status::Ok));
    assert_eq!(hello.into_body(), b"hi there");

    // an unknown path takes the handler's not_found branch.
    let missing = client.send(Method::Read, "/nope", &[]).expect("send /nope");
    assert_eq!(missing.status(), Some(Status::NotFound));

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
