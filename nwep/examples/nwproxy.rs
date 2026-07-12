// nwproxy, a caching reverse proxy (mirrors sandbox/004-nwproxy). a frontend
// defers each request, fetches from an origin on its loop, relays the origin
// response verbatim (preserving the origin's end-to-end signature, spec 6.9), and
// caches public responses to serve later hits without re-contacting the origin.
// origin, proxy, and client all run in one process.

use nwep::{Address, Cache, Client, Identity, Method, Server, Status};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn spawn_origin(
    hits: Arc<AtomicU64>,
) -> (
    nwep::NodeId,
    [u8; 32],
    u16,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let id = Identity::generate().unwrap();
    let node = *id.node_id();
    let pubkey = *id.public_key();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();
    let handle = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(id)
            .bind(Address::loopback(0))
            .on_request(move |req, res| match req.path() {
                Some("/doc") => {
                    hits.fetch_add(1, Ordering::Relaxed);
                    // public so a shared cache may store it NW060900.
                    res.header("cache-control", "public")
                        .ok(b"the origin document")
                }
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
    (node, pubkey, port, stop, handle)
}

fn main() -> nwep::Result<()> {
    let origin_hits = Arc::new(AtomicU64::new(0));
    let (origin_node, origin_pubkey, origin_port, origin_stop, origin_thread) =
        spawn_origin(origin_hits.clone());

    let parked: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let parked_h = parked.clone();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    let frontend = std::thread::spawn(move || {
        let backend = Client::builder()
            .identity(Identity::generate().unwrap())
            .connect(&origin_node, &Address::loopback(origin_port))
            .unwrap();
        // the cache lives only on this loop thread, so it needs no sharing.
        let mut cache = Cache::new(1 << 20, 64).unwrap();
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                parked_h
                    .lock()
                    .unwrap()
                    .push((req.conn_id(), req.stream_id()));
                res.defer()
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            for (conn, stream) in parked.lock().unwrap().drain(..) {
                // serve from cache if we have a fresh copy, else fetch + relay + store.
                if let Some(hit) =
                    cache.get_signed(Method::Read, "/doc", &origin_pubkey, now_secs())
                {
                    server.respond(conn, stream).relay(&hit).unwrap();
                } else {
                    let origin = backend.send(Method::Read, "/doc", &[]).unwrap();
                    let _ =
                        cache.put_signed(Method::Read, "/doc", &origin, &origin_pubkey, now_secs());
                    server.respond(conn, stream).relay(&origin).unwrap();
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let (proxy_node, proxy_port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    let client = Client::builder()
        .identity(Identity::generate()?)
        .connect(&proxy_node, &Address::loopback(proxy_port))?;

    // three identical requests; the origin is contacted once, the rest are cache hits.
    for i in 1..=3 {
        let r = client.send(Method::Read, "/doc", &[])?;
        println!(
            "request {i} -> {} {:?}",
            r.status().unwrap_or(Status::Error),
            String::from_utf8_lossy(r.body())
        );
    }
    println!(
        "origin contacted {} time(s) for 3 requests",
        origin_hits.load(Ordering::Relaxed)
    );

    stop.store(true, Ordering::Relaxed);
    origin_stop.store(true, Ordering::Relaxed);
    frontend.join().unwrap();
    origin_thread.join().unwrap();
    Ok(())
}
