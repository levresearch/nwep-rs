// nwcurl, a curl/httpie for web/1 (mirrors sandbox/003-nwcurl). drives the full
// client surface: a unary read printing status + every header (like curl -i) and
// verifying the response against the connected peer, then a streamed read
// reassembled and signature-verified. a tiny server makes it self-contained; the
// point is the client side.

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

fn main() -> nwep::Result<()> {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let big: Vec<u8> = (0..120_000u32).map(|i| (i % 251) as u8).collect();
    let big_for_thread = big.clone();

    let server_thread = std::thread::spawn(move || {
        // streamed requests stash (conn, stream) for the loop to feed.
        let pending: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let pending_h = pending.clone();
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(move |req, res| match req.path() {
                Some("/hello") => res
                    .header("x-served-by", "nwcurl-demo")
                    .ok(b"hi from web/1"),
                Some("/big") => {
                    pending_h
                        .lock()
                        .unwrap()
                        .push((req.conn_id(), req.stream_id()));
                    res.stream(
                        "/big",
                        Status::Ok,
                        &[("content-type", "application/octet-stream")],
                    )
                }
                _ => res.not_found(),
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();
        let mut active: Vec<(u64, u64, usize)> = Vec::new();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            active.extend(pending.lock().unwrap().drain(..).map(|(c, s)| (c, s, 0)));
            active.retain_mut(|(c, s, sent)| {
                while *sent < big_for_thread.len() {
                    let n = server
                        .stream_send(*c, *s, &big_for_thread[*sent..])
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
    let (node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    let client = Client::builder()
        .identity(Identity::generate()?)
        .connect(&node, &Address::loopback(port))?;

    // -i: a unary read, printing the status line and every response header.
    let resp = client.send(Method::Read, "/hello", &[])?;
    println!("READ /hello -> {}", resp.status().unwrap_or(Status::Error));
    for (name, value) in resp.headers() {
        println!("  {name}: {value}");
    }
    println!("  body: {:?}", String::from_utf8_lossy(resp.body()));
    // -k: the response verifies against the connected peer's own key NW060900.
    client.verify_response(&resp, "/hello", 0)?;
    println!("  signature verifies against the peer key");

    // --stream: a streamed read, reassembled and trailer-verified.
    let peer = client.peer_pubkey()?;
    let stream = client.open_stream(Method::Read, "/big")?;
    let meta = stream.response()?;
    println!(
        "READ /big   -> {} ({})",
        meta.status().unwrap_or(Status::Error),
        meta.header("content-type").unwrap_or("?")
    );
    let mut got = 0usize;
    let mut buf = [0u8; 65536];
    loop {
        let (n, ended) = stream.recv(&mut buf)?;
        got += n;
        if ended {
            break;
        }
    }
    stream.verify(&peer)?;
    println!("  streamed {got} bytes, trailer signature verifies");

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
    Ok(())
}
