// the response frame fast-path NW060900 NW000017. a server builds a
// response once, captures the signed frame, and on the next identical request
// blits the cached frame verbatim  -  no re-encode, no re-sign. the client gets
// byte-identical, still-verifiable responses both times. mirrors the nwproxy
// frame cache.

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

#[test]
fn capture_then_blit_a_cached_frame() {
    let server_id = Identity::generate().unwrap();
    let server_node = *server_id.node_id();
    let server_pubkey = *server_id.public_key();

    // a one-entry frame cache the handler fills on the first /cached request and
    // blits on the rest. blit_count tracks how often the fast path ran.
    let frame: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let frame_h = frame.clone();
    let blit_count = Arc::new(AtomicU64::new(0));
    let blit_h = blit_count.clone();

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                if req.path() != Some("/cached") {
                    return res.not_found();
                }
                // the frame is codec-specific; this single client keeps one codec
                // for the connection's life, so a cached frame is safe to blit.
                let _ = req.compression();
                let cached = frame_h.lock().unwrap().clone();
                match cached {
                    // fast path: blit the cached frame verbatim, no re-encode.
                    Some(f) => {
                        blit_h.fetch_add(1, Ordering::Relaxed);
                        res.blit(&f)
                    }
                    // slow path: build the response and capture its frame.
                    None => {
                        let (reply, f) = res.capturing().ok(b"cached-body");
                        *frame_h.lock().unwrap() = Some(f);
                        reply
                    }
                }
            })
            .build()
            .unwrap();
        tx.send(server.local_port()).unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    let port = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&server_node, &Address::loopback(port))
        .unwrap();

    // first request builds + captures; later ones blit the cached frame.
    let first = client.send(Method::Read, "/cached", &[]).unwrap();
    assert_eq!(first.status(), Some(Status::Ok));
    assert_eq!(first.body(), b"cached-body");
    first.verify(&server_pubkey, "/cached", 0).unwrap();
    let first_body = first.into_body();

    for _ in 0..3 {
        let r = client.send(Method::Read, "/cached", &[]).unwrap();
        assert_eq!(r.status(), Some(Status::Ok));
        // a blitted frame is byte-identical and still verifies (same signature).
        assert_eq!(r.body(), &first_body[..]);
        r.verify(&server_pubkey, "/cached", 0).unwrap();
    }
    assert!(
        blit_count.load(Ordering::Relaxed) >= 1,
        "the blit fast path ran"
    );

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
