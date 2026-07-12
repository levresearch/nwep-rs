// the managed AsyncStream: pull a streamed body chunk by chunk, fully async, no
// tick loop or fd in the test. the dedicated stream connection + owner thread
// live behind AsyncStream; reaching the end (recv -> None) means the trailer
// signature verified against the peer, so the body is authentic. mirrors the
// nwcurl --stream / nwdrop large-transfer path on the managed surface.
#![cfg(feature = "runtime")]

use nwep::{Address, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

#[tokio::test]
async fn async_stream_pulls_a_large_body() {
    // a body well over one chunk, to force chunked streaming + back-pressure.
    let body: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
    let body_for_thread = body.clone();

    let server_id = Identity::generate().unwrap();
    let server_node = *server_id.node_id();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    // a driven server that streams /big across ticks (the embedder owns its loop).
    let server_thread = std::thread::spawn(move || {
        let pending: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let pending_h = pending.clone();
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                if req.path() == Some("/big") {
                    pending_h
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
        tx.send(server.local_port()).unwrap();
        let mut active: Vec<(u64, u64, usize)> = Vec::new();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            active.extend(pending.lock().unwrap().drain(..).map(|(c, s)| (c, s, 0)));
            active.retain_mut(|(c, s, sent)| {
                while *sent < body_for_thread.len() {
                    let n = server
                        .stream_send(*c, *s, &body_for_thread[*sent..])
                        .unwrap();
                    *sent += n;
                    if n == 0 {
                        return true;
                    }
                }
                server.stream_end(*c, *s).unwrap();
                false
            });
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let port = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    // open a managed async stream and pull the body chunk by chunk.
    let mut stream = nwep::Client::builder()
        .identity(Identity::generate().unwrap())
        .stream(Method::Read, "/big", &server_node, &Address::loopback(port))
        .await
        .expect("open async stream");
    assert_eq!(stream.status(), Status::Ok);
    assert_eq!(
        stream.header("content-type"),
        Some("application/octet-stream")
    );

    let mut received = Vec::with_capacity(body.len());
    // recv -> Some(chunk) while streaming; None at the verified end.
    while let Some(chunk) = stream.recv().await.expect("stream chunk") {
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received.len(), body.len());
    assert_eq!(received, body, "the streamed body is byte-exact");
    // reaching None means the trailer signature verified against the peer.

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
