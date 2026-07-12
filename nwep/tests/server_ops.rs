// the server observability + lifecycle ops. a server answers a request. the
// handler reads the connection's peer node_id and codec straight off the request,
// then after serving we scrape metrics, check the load gauge, and drain. plus the
// static helpers.

use nwep::{
    cid_shard_id, reuse_port_supported, Address, Client, Compression, Identity, Method, Server,
    Status,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

#[test]
fn metrics_peer_id_compression_load_and_drain() {
    let client_id = Identity::generate().unwrap();
    let client_node = *client_id.node_id();

    // the handler asserts the request's peer node_id is the client's, and that
    // the codec reads back as a known variant  -  both straight off Request.
    let peer_ok = Arc::new(AtomicBool::new(false));
    let peer_ok_h = peer_ok.clone();

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let server_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .max_parked(64)
            .on_request(move |req, res| {
                if req
                    .peer_node_id()
                    .map(|n| n == client_node)
                    .unwrap_or(false)
                    && req.compression() != Compression::Unknown
                {
                    peer_ok_h.store(true, Ordering::Relaxed);
                }
                res.ok(b"ok")
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();

        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }

        // after serving, the metrics + load + drain surface is exercised on the
        // owner thread (the !Send handle never leaves it).
        let m = server.metrics();
        assert!(m.connections_accepted >= 1, "accepted a connection");
        assert!(m.requests_dispatched >= 1, "dispatched a request");
        assert!(m.datagrams_received >= 1);
        assert!((0..=100).contains(&server.load()));

        server.set_overloaded(true);
        server.set_overloaded(false);
        assert!(server.last_handshake_error().is_none());

        server.drain().unwrap();
        // pump until the drain settles (the closing connection clears); loopback
        // is fast but a closing quic connection lingers briefly.
        for _ in 0..600 {
            server.tick(now_ms()).unwrap();
            if server.is_drained() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            server.is_drained(),
            "server drained after connections closed (active={})",
            server.metrics().connections_active
        );
    });

    let (server_node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    {
        let client = Client::builder()
            .identity(client_id)
            .connect(&server_node, &Address::loopback(port))
            .unwrap();
        let resp = client.send(Method::Read, "/x", &[]).unwrap();
        assert_eq!(resp.status(), Some(Status::Ok));
    } // client dropped -> connection closes, so the server can finish draining

    assert!(
        peer_ok.load(Ordering::Relaxed),
        "handler saw the client's peer node_id + a known codec"
    );

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn static_helpers_do_not_panic() {
    // reuse_port_supported is a plain bool on this platform.
    let _ = reuse_port_supported();
    // a too-short or non-shard cid yields none, never a panic.
    assert_eq!(cid_shard_id(&[0u8; 4]), None);
    assert_eq!(cid_shard_id(&[]), None);
}

#[test]
fn compression_variants_are_distinct() {
    assert_ne!(Compression::None, Compression::Zstd);
    assert_ne!(Compression::Zstd, Compression::Unknown);
}
