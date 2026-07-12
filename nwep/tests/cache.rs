// the shared signed cache + response verification NW060700 NW060900. a server
// serves a public, signed response; a client fetches and verifies it (both the
// connection-sourced and explicit-pubkey ways), then a shared cache stores it
// and serves the same bytes back to a later lookup. mirrors the nwproxy cache.

use nwep::{Address, Cache, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

const NOW: u64 = 1_700_000_000;

#[test]
fn verify_and_shared_cache_round_trip() {
    let server_id = Identity::generate().unwrap();
    let server_node = *server_id.node_id();
    let server_pubkey = *server_id.public_key();

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(|req, res| match req.path() {
                // a shareable origin must opt into caching with cache-control public.
                Some("/page") => res.header("cache-control", "public").ok(b"page-body"),
                _ => res.not_found(),
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

    let resp = client.send(Method::Read, "/page", &[]).unwrap();
    assert_eq!(resp.status(), Some(Status::Ok));
    assert_eq!(resp.body(), b"page-body");

    // the response verifies both ways: against the connection peer, and against
    // the explicit origin pubkey NW060900. pass now=0 to skip the freshness gate.
    client.verify_response(&resp, "/page", 0).unwrap();
    resp.verify(&server_pubkey, "/page", 0).unwrap();
    // a wrong path must not verify.
    assert!(resp.verify(&server_pubkey, "/other", 0).is_err());

    // a shared cache stores the verified response, then serves it back.
    let mut cache = Cache::new(1 << 20, 64).unwrap();
    cache
        .put_signed(Method::Read, "/page", &resp, &server_pubkey, NOW)
        .unwrap();
    assert_eq!(cache.stats().stores, 1);

    // serving the same resource back returns the stored bytes  -  the cache hit.
    // (the hits/misses counters track the client-attached cache path, not this
    // explicit get_signed proxy surface, so we assert on the served bytes.)
    let hit = cache
        .get_signed(Method::Read, "/page", &server_pubkey, NOW)
        .expect("cache hit");
    assert_eq!(hit.status(), Some(Status::Ok));
    assert_eq!(hit.body(), b"page-body");

    // a path that was never stored is a miss.
    assert!(cache
        .get_signed(Method::Read, "/missing", &server_pubkey, NOW)
        .is_none());

    // clearing drops the entry, so the next lookup misses.
    cache.clear();
    assert!(cache
        .get_signed(Method::Read, "/page", &server_pubkey, NOW)
        .is_none());

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn cache_refuses_an_unsigned_or_private_response() {
    // a non-public response cannot be stored in a shared cache NW060900. serve
    // one without cache-control public and confirm put_signed rejects it.
    let server_id = Identity::generate().unwrap();
    let server_node = *server_id.node_id();
    let server_pubkey = *server_id.public_key();

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(|_req, res| res.ok(b"private"))
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
    let resp = client.send(Method::Read, "/x", &[]).unwrap();

    let mut cache = Cache::new(1 << 20, 64).unwrap();
    assert!(cache
        .put_signed(Method::Read, "/x", &resp, &server_pubkey, NOW)
        .is_err());

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}
