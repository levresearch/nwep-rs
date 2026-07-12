// the managed streaming quickstart. pull a body too large for one message chunk
// by chunk, fully async  -  no tick loop, no manual reassembly. requires the
// default "runtime" feature. a driven server streams /big across ticks (on its
// own thread). the client side is the point.

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

#[tokio::main]
async fn main() -> nwep::Result<()> {
    let body: Vec<u8> = (0..250_000u32).map(|i| (i % 251) as u8).collect();
    let body_for_thread = body.clone();

    let server_id = Identity::generate()?;
    let server_node = *server_id.node_id();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

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

    // open the managed stream and pull the body chunk by chunk.
    let mut stream = Client::builder()
        .identity(Identity::generate()?)
        .stream(Method::Read, "/big", &server_node, &Address::loopback(port))
        .await?;
    println!(
        "stream open -> {} ({})",
        stream.status(),
        stream.header("content-type").unwrap_or("?")
    );

    let mut total = 0usize;
    let mut chunks = 0usize;
    // recv yields Some(chunk) while streaming, None at the verified end.
    while let Some(chunk) = stream.recv().await? {
        total += chunk.len();
        chunks += 1;
    }
    println!("received {total} bytes in {chunks} chunks, trailer signature verified");

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
    Ok(())
}
