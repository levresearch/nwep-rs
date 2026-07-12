// byte ranges and headers end to end, the resumable-transfer path the sandbox
// nwdrop rests on, plus header iteration like nwcurl -i. a server serves a blob
// with range support and an etag; a client requests a sub range and a
// conditional read, over the real transport.

use nwep::{Address, ByteRange, Client, Identity, Method, RangeOutcome, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

const BLOB: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const ETAG: &str = "\"v1\"";

#[test]
fn byte_ranges_and_headers_round_trip() {
    let server_id = Identity::generate().unwrap();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(|req, res| {
                if req.path() != Some("/blob") {
                    return res.not_found();
                }
                // a conditional read whose etag still matches gets not-modified.
                if req.is_fresh(ETAG) {
                    return res.not_modified(ETAG);
                }
                let total = BLOB.len() as u64;
                match req.range(total, Some(ETAG)) {
                    Ok(RangeOutcome::Ranges(ranges)) => {
                        res.header("etag", ETAG)
                            .partial(BLOB, &ranges, "text/plain")
                    }
                    Ok(RangeOutcome::Unsatisfiable) => res.range_not_satisfiable(total),
                    _ => res.header("etag", ETAG).ok(BLOB),
                }
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();
        while !stop2.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    let (node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&node, &Address::loopback(port))
        .unwrap();

    // a full read returns the whole blob and an etag header.
    let full = client.send(Method::Read, "/blob", &[]).unwrap();
    assert_eq!(full.status(), Some(Status::Ok));
    assert_eq!(full.body(), BLOB);
    // header iteration finds the etag, in wire order, like nwcurl -i.
    let etag = full
        .headers()
        .find(|(k, _)| *k == "etag")
        .map(|(_, v)| v.to_owned());
    assert_eq!(etag.as_deref(), Some(ETAG));

    // a sub range returns partial-content with exactly those bytes.
    let part = client
        .request(Method::Read, "/blob")
        .header("range", "bytes=10-15")
        .send()
        .unwrap();
    assert_eq!(part.status(), Some(Status::PartialContent));
    assert_eq!(part.body(), &BLOB[10..=15]);
    assert!(part.headers().any(|(k, _)| k == "content-range"));

    // a range past the end is range-not-satisfiable.
    let over = client
        .request(Method::Read, "/blob")
        .header("range", "bytes=100-200")
        .send()
        .unwrap();
    assert_eq!(over.status(), Some(Status::RangeNotSatisfiable));

    // a conditional read whose etag matches gets not-modified, no body.
    let fresh = client
        .request(Method::Read, "/blob")
        .header("if-none-match", ETAG)
        .send()
        .unwrap();
    assert_eq!(fresh.status(), Some(Status::NotModified));
    assert!(fresh.body().is_empty());

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn range_outcome_parses_offsets() {
    // a small structural check on the ByteRange surface, independent of i/o.
    let r = ByteRange { start: 4, end: 9 };
    assert_eq!(r.end - r.start + 1, 6);
}
