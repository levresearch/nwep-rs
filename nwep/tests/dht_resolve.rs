// discover a peer by node_id through the dht, the protocol's no-dns headline.
// mirrors the sandbox nwdrop flow in process: a rendezvous node, an announcing
// server, and a resolver that dials the server with only its node_id. each node
// owns its !Send server + dht on its own thread (built there, never crossing a
// boundary). the resolver uses the blocking connect_by_node_id, which drives its
// own server and dht while it resolves.

use nwep::{Address, Bootstrap, Client, Dht, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// pumps a server + its attached dht until stop, the driven loop a real reactor
// would run with a poll instead of a sleep.
fn pump(server: &Server, dht: &Dht, stop: &AtomicBool, announce: Option<Address>) {
    let mut announced_at = 0u64;
    while !stop.load(Ordering::Relaxed) {
        server.tick(now_ms()).unwrap();
        let secs = now_secs();
        dht.tick(secs).unwrap();
        if let Some(addr) = announce {
            if announced_at == 0 || secs - announced_at >= 30 {
                let _ = dht.announce(&addr, secs);
                announced_at = secs;
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn resolve_a_node_id_through_the_dht() {
    // node R, the rendezvous. self-bootstraps and just routes.
    let r_id = Identity::generate().unwrap();
    let (r_tx, r_rx) = mpsc::channel();
    let r_stop = Arc::new(AtomicBool::new(false));
    let r_stop2 = r_stop.clone();
    let r_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(r_id)
            .bind(Address::loopback(0))
            .build()
            .unwrap();
        let port = server.local_port();
        let node = server.node_id().unwrap();
        // a root node lists itself, satisfying the non-empty bootstrap rule.
        let self_contact = Bootstrap::new(&node, &Address::loopback(port));
        let dht = Dht::builder(&server)
            .bootstrap(self_contact)
            .attach()
            .unwrap();
        dht.join(now_secs()).unwrap();
        r_tx.send((node, port)).unwrap();
        pump(&server, &dht, &r_stop2, None);
    });
    let (r_node, r_port) = r_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let r_contact = Bootstrap::new(&r_node, &Address::loopback(r_port));

    // node A, the server we will dial by node_id. announces itself to R.
    let a_id = Identity::generate().unwrap();
    let (a_tx, a_rx) = mpsc::channel();
    let a_stop = Arc::new(AtomicBool::new(false));
    let a_stop2 = a_stop.clone();
    let a_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(a_id)
            .bind(Address::loopback(0))
            .on_request(|req, res| match req.path() {
                Some("/ping") => res.ok(b"pong"),
                _ => res.not_found(),
            })
            .build()
            .unwrap();
        let port = server.local_port();
        let node = server.node_id().unwrap();
        let dht = Dht::builder(&server).bootstrap(r_contact).attach().unwrap();
        dht.join(now_secs()).unwrap();
        a_tx.send(node).unwrap();
        pump(&server, &dht, &a_stop2, Some(Address::loopback(port)));
    });
    let a_node = a_rx.recv_timeout(Duration::from_secs(3)).unwrap();

    // give A a moment to register its announce with R.
    std::thread::sleep(Duration::from_millis(800));

    // the resolver: stands up its own server + dht, joins, then dials A by
    // node_id alone. connect_by_node_id drives its server + dht while resolving.
    let resolver = Server::builder()
        .identity(Identity::generate().unwrap())
        .bind(Address::loopback(0))
        .build()
        .unwrap();
    let r2_contact = Bootstrap::new(&r_node, &Address::loopback(r_port));
    let dht = Dht::builder(&resolver)
        .bootstrap(r2_contact)
        .attach()
        .unwrap();
    dht.join(now_secs()).unwrap();

    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect_by_node_id(&a_node, &dht, Duration::from_secs(8))
        .expect("resolve + connect by node_id");

    let resp = client.send(Method::Read, "/ping", &[]).expect("send /ping");
    assert_eq!(resp.status(), Some(Status::Ok));
    assert_eq!(resp.into_body(), b"pong");

    // the resolution moved real datagrams through the dht.
    assert!(dht.metrics().datagrams_received > 0);

    a_stop.store(true, Ordering::Relaxed);
    r_stop.store(true, Ordering::Relaxed);
    a_thread.join().unwrap();
    r_thread.join().unwrap();
}
