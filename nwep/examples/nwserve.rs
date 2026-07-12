// nwserve, a static content server (mirrors sandbox/001-nwserve). serves a
// resource with an etag, byte ranges NW060800, and conditional reads NW060700  -  the content path nginx-style serving rests on. a client fetches the
// whole resource, a sub-range, an out-of-bounds range, and a fresh conditional
// read, printing each outcome. an in-memory resource keeps the example
// self-contained.

use nwep::{Address, Client, Identity, Method, RangeOutcome, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

const PAGE: &[u8] = b"the quick brown fox jumps over the lazy dog";
const ETAG: &str = "\"v1\"";

fn main() -> nwep::Result<()> {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(|req, res| {
                if req.path() != Some("/page") {
                    return res.not_found();
                }
                // a fresh conditional read short-circuits to not-modified NW060700.
                if req.is_fresh(ETAG) {
                    return res.not_modified(ETAG);
                }
                let total = PAGE.len() as u64;
                match req.range(total, Some(ETAG)) {
                    Ok(RangeOutcome::Ranges(rs)) => {
                        res.header("etag", ETAG).partial(PAGE, &rs, "text/plain")
                    }
                    Ok(RangeOutcome::Unsatisfiable) => res.range_not_satisfiable(total),
                    _ => res.header("etag", ETAG).ok(PAGE),
                }
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

    let client = Client::builder()
        .identity(Identity::generate()?)
        .connect(&node, &Address::loopback(port))?;

    // a full read returns the whole resource and its etag.
    let full = client.send(Method::Read, "/page", &[])?;
    let etag = full.header("etag").unwrap_or("?").to_owned();
    println!(
        "full read   -> {} {:?} (etag {})",
        full.status().unwrap_or(Status::Error),
        String::from_utf8_lossy(full.body()),
        etag
    );

    // a sub-range returns partial-content with exactly those bytes.
    let part = client
        .request(Method::Read, "/page")
        .header("range", "bytes=4-8")
        .send()?;
    println!(
        "range 4-8   -> {} {:?}",
        part.status().unwrap_or(Status::Error),
        String::from_utf8_lossy(part.body())
    );

    // a range past the end is range-not-satisfiable.
    let over = client
        .request(Method::Read, "/page")
        .header("range", "bytes=999-1099")
        .send()?;
    println!("range 999-  -> {}", over.status().unwrap_or(Status::Error));

    // a conditional read whose etag still matches gets not-modified, no body.
    let fresh = client
        .request(Method::Read, "/page")
        .header("if-none-match", ETAG)
        .send()?;
    println!(
        "if-none-match-> {} (body {} bytes)",
        fresh.status().unwrap_or(Status::Error),
        fresh.body().len()
    );

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
    Ok(())
}
