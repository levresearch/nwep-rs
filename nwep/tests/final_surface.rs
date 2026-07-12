// the final surface. server fd-adoption, sync in-handler relay, client cache +
// request-done callback, and the trust verify/anchor-change/peer-partial-sig
// path. these complete the 159-symbol coverage.
#![cfg(all(feature = "trust", unix))]

use nwep::trust::{self, bls::BlsKeypair, AnchorNode, TrustStore};
use nwep::{Address, Cache, Client, Identity, Method, Server, Status};
use std::net::UdpSocket;
use std::os::fd::IntoRawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn server_adopts_a_socket_and_relays_in_handler() {
    // an origin that answers /thing, used as the relay source.
    let origin_id = Identity::generate().unwrap();
    let origin_node = *origin_id.node_id();
    let (otx, orx) = mpsc::channel();
    let ostop = Arc::new(AtomicBool::new(false));
    let ostop_t = ostop.clone();
    let origin = std::thread::spawn(move || {
        let s = Server::builder()
            .identity(origin_id)
            .bind(Address::loopback(0))
            .on_request(|req, res| match req.path() {
                Some("/thing") => res.ok(b"origin-bytes"),
                _ => res.not_found(),
            })
            .build()
            .unwrap();
        otx.send(s.local_port()).unwrap();
        while !ostop_t.load(Ordering::Relaxed) {
            s.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let origin_port = orx.recv_timeout(Duration::from_secs(3)).unwrap();

    // the frontend adopts a caller-owned socket and relays the origin response
    // verbatim, in-handler.
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let frontend = std::thread::spawn(move || {
        let sock = UdpSocket::bind("[::1]:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let fd = sock.into_raw_fd();
        // fetch the origin response once up front; Response is Send, so the
        // handler can capture and relay it (a real proxy fetches per request from
        // its loop, proven in tests/deferred.rs  -  here we focus on relay-in-handler).
        let backend = Client::builder()
            .identity(Identity::generate().unwrap())
            .connect(&origin_node, &Address::loopback(origin_port))
            .unwrap();
        let origin_resp = backend.send(Method::Read, "/thing", &[]).unwrap();
        drop(backend);
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .on_request(move |_req, res| res.relay(&origin_resp))
            .build_from_fd(fd, None)
            .unwrap();
        tx.send((server.node_id().unwrap(), port)).unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let (frontend_node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&frontend_node, &Address::loopback(port))
        .unwrap();
    let resp = client.send(Method::Read, "/proxied", &[]).unwrap();
    assert_eq!(resp.status(), Some(Status::Ok));
    // the in-handler relay preserves the origin body verbatim (its end-to-end
    // signature is verified against the origin key in tests/deferred.rs).
    assert_eq!(resp.into_body(), b"origin-bytes");

    stop.store(true, Ordering::Relaxed);
    ostop.store(true, Ordering::Relaxed);
    frontend.join().unwrap();
    origin.join().unwrap();
}

#[test]
fn client_cache_attach_and_request_done_callback() {
    let server_id = Identity::generate().unwrap();
    let server_node = *server_id.node_id();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let server_thread = std::thread::spawn(move || {
        let s = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(|req, res| match req.path() {
                Some("/p") => res.header("cache-control", "public").ok(b"p-body"),
                _ => res.not_found(),
            })
            .build()
            .unwrap();
        tx.send(s.local_port()).unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            s.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let port = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&server_node, &Address::loopback(port))
        .unwrap();

    // a shared cache can be attached (and shared by Rc) and detached.
    let cache = Rc::new(Cache::new(1 << 20, 16).unwrap());
    client.set_cache(Some(cache.clone())).unwrap();
    client.set_cache(None).unwrap();
    client.set_cache(Some(cache)).unwrap();

    // a request-done callback fires from tick when a submitted request completes.
    let done = Arc::new(AtomicU64::new(0));
    let done_h = done.clone();
    client.on_request_done(move |_id, result| {
        if result.map(|r| r.into_body() == b"p-body").unwrap_or(false) {
            done_h.fetch_add(1, Ordering::Relaxed);
        }
    });

    let _handle = client.request(Method::Read, "/p").submit().unwrap();
    for _ in 0..2000 {
        client.tick(now_ms()).unwrap();
        if done.load(Ordering::Relaxed) >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        done.load(Ordering::Relaxed),
        1,
        "the done callback fired once"
    );

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
}

#[test]
fn anchor_peer_partial_sig_exchange() {
    // a responder anchor answers a coordinator's /anchor/partial-sig over the
    // wire (dispatch <-> request_partial_sig), and the gathered partial finishes
    // a checkpoint that verifies.
    const EPOCH: u64 = 1;
    const LOG_SIZE: u64 = 64;
    let root = [0x5Au8; 32];

    // the responder anchor: its web/1 identity + bls share.
    let peer_id = Identity::generate().unwrap();
    let peer_node = *peer_id.node_id();
    let peer_bls = BlsKeypair::generate().unwrap();
    let peer_bls_pub = *peer_bls.public_key();

    // the coordinator must itself be a member of the anchor set (dispatch only
    // answers peers in the set, spec 12.9), so create its identity up front.
    let coord_id = Identity::generate().unwrap();
    let coord_node = *coord_id.node_id();

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let anchor_thread = std::thread::spawn(move || {
        let mut anchor =
            AnchorNode::new(&peer_id, &peer_bls, 1, Duration::from_secs(3300)).unwrap();
        anchor
            .collect_log_root(EPOCH, &root, LOG_SIZE, &root)
            .unwrap();
        let anchor_ids = vec![peer_node, coord_node];
        let server = Server::builder()
            .identity(peer_id)
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                let requester = req.peer_node_id().unwrap();
                match anchor.dispatch(&requester, &anchor_ids, req, res, now_secs()) {
                    nwep::DispatchOutcome::Handled(reply) => reply,
                    nwep::DispatchOutcome::NotMine(res) => res.not_found(),
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
    let (anchor_node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    // the coordinator (an anchor-set member) dials the peer and requests its partial.
    let coord = Client::builder()
        .identity(coord_id)
        .connect(&anchor_node, &Address::loopback(port))
        .unwrap();
    let partial =
        trust::request_partial_sig(&coord, EPOCH, &root, LOG_SIZE, &peer_bls_pub).unwrap();
    assert_eq!(partial.index(), 1);

    // the single partial (threshold 1) finishes a checkpoint that verifies.
    let checkpoint =
        trust::finish_checkpoint(EPOCH, &root, LOG_SIZE, &[partial], &[peer_bls_pub]).unwrap();
    let mut store = TrustStore::new().unwrap();
    store.load_genesis_anchors(&[peer_bls_pub]).unwrap();
    assert!(store
        .verify_checkpoint(&checkpoint, EPOCH as i64 * 3600)
        .is_ok());

    stop.store(true, Ordering::Relaxed);
    anchor_thread.join().unwrap();
}

#[test]
fn verify_key_binding_and_apply_anchor_change_reject_garbage() {
    // these are wrapped + reachable; their positive paths need a full proof
    // bundle / a quorum-signed AnchorChange entry (covered by the C e2e tests
    // and src/nwep_trust unit tests). here we exercise the error paths.
    let store = TrustStore::new().unwrap();
    let node = *Identity::generate().unwrap().node_id();

    // no checkpoint installed -> a key-binding bundle cannot be verified.
    let err = store.verify_key_binding(&node, &[0u8; 32], &[0u8; 200], now_secs());
    assert!(err.is_err());

    // a malformed anchor-change entry is rejected, not applied.
    let mut store2 = TrustStore::new().unwrap();
    assert!(store2.apply_anchor_change(&[0xFFu8; 10], 1).is_err());
}
