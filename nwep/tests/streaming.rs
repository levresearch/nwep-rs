// streamed responses end to end NW060200. a server streams a body larger than
// one chunk across ticks (back-pressure aware), and a client receives it chunk by
// chunk, reassembles it byte-exact, and verifies the trailer signature. this is
// the http-class large-transfer path nwserve and nwdrop want. mirrors nwcurl
// --stream.

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

#[test]
fn server_streams_a_large_body_a_client_reassembles_and_verifies() {
    // a body well over a single send, to force chunked streaming + back-pressure.
    let body: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
    let body_for_thread = body.clone();

    let server_id = Identity::generate().unwrap();
    let server_node = *server_id.node_id();
    let server_pubkey = *server_id.public_key();

    // the handler stashes (conn, stream) of each /big request; the tick loop
    // drains them, streaming the body and ending. one owner thread, so a plain
    // Arc<Mutex<...>> bridges the Send handler closure and the loop.
    let pending: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let pending_handler = pending.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                if req.path() == Some("/big") {
                    pending_handler
                        .lock()
                        .unwrap()
                        .push((req.conn_id(), req.stream_id()));
                    res.stream(
                        "/big",
                        Status::Ok,
                        &[("content-type", "application/octet-stream")],
                    )
                } else {
                    res.not_found()
                }
            })
            .build()
            .unwrap();
        ready_tx.send(server.local_port()).unwrap();

        // active streams with their send progress, advanced each tick.
        let mut active: Vec<(u64, u64, usize)> = Vec::new();
        loop {
            server.tick(now_ms()).unwrap();
            for (conn, stream) in pending.lock().unwrap().drain(..) {
                active.push((conn, stream, 0));
            }
            active.retain_mut(|(conn, stream, sent)| {
                while *sent < body_for_thread.len() {
                    let n = server
                        .stream_send(*conn, *stream, &body_for_thread[*sent..])
                        .unwrap();
                    *sent += n;
                    if n == 0 {
                        return true; // back-pressure, resume next tick
                    }
                }
                server.stream_end(*conn, *stream).unwrap();
                false // finished, drop it
            });
            if stop_thread.load(Ordering::Relaxed) && active.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    let port = ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&server_node, &Address::loopback(port))
        .unwrap();

    let stream = client.open_stream(Method::Read, "/big").unwrap();
    let meta = stream.response().unwrap();
    assert_eq!(meta.status(), Some(Status::Ok));
    assert_eq!(
        meta.header("content-type"),
        Some("application/octet-stream")
    );

    let mut received = Vec::with_capacity(body.len());
    let mut buf = [0u8; 65536];
    loop {
        let (n, ended) = stream.recv(&mut buf).unwrap();
        received.extend_from_slice(&buf[..n]);
        if ended {
            break;
        }
    }
    assert_eq!(received.len(), body.len());
    assert_eq!(received, body);

    // the streamed response carries a verifiable trailer signature NW060900.
    stream.verify(&server_pubkey).unwrap();

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
