// nwdrop, a decentralized resumable file drop (mirrors sandbox/005-nwdrop). the
// protocol's no-dns headline. a node is dialed by node_id alone, resolved through
// the dht, then a body is pulled with resumable byte ranges. a rendezvous node, a
// sender that announces a file, and a getter that resolves + downloads all run in
// one process. each node has a distinct loopback ip so they do not share one dht
// budget (the per-source-ip rate limit + token are keyed on ip).

use nwep::{Address, Bootstrap, Client, Dht, Identity, Method, RangeOutcome, Server, Status};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
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

// a node bound to a distinct 127.0.0.x loopback ip (web/1 carries it ipv4-mapped).
fn lo(octet: u8, port: u16) -> Address {
    Address::ipv4_mapped(127, 0, 0, octet, port)
}

const FILE: &[u8] = b"the entire contents of a small file moved by node_id alone";

fn main() -> nwep::Result<()> {
    // node R: the rendezvous, self-bootstraps and just routes.
    let r_id = Identity::generate()?;
    let (r_tx, r_rx) = mpsc::channel();
    let r_stop = Arc::new(AtomicBool::new(false));
    let r_stop2 = r_stop.clone();
    let r_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(r_id)
            .bind(lo(1, 0))
            .build()
            .unwrap();
        let node = server.node_id().unwrap();
        let port = server.local_port();
        let dht = Dht::builder(&server)
            .bootstrap(Bootstrap::new(&node, &lo(1, port)))
            .attach()
            .unwrap();
        dht.join(now_secs()).unwrap();
        r_tx.send((node, port)).unwrap();
        pump(&server, &dht, &r_stop2, None);
    });
    let (r_node, r_port) = r_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let r_contact = Bootstrap::new(&r_node, &lo(1, r_port));

    // node A: announces a file and serves it with byte ranges.
    let a_id = Identity::generate()?;
    let (a_tx, a_rx) = mpsc::channel();
    let a_stop = Arc::new(AtomicBool::new(false));
    let a_stop2 = a_stop.clone();
    let a_thread = std::thread::spawn(move || {
        let server = Server::builder()
            .identity(a_id)
            .bind(lo(2, 0))
            .on_request(|req, res| {
                if req.path() != Some("/blob") {
                    return res.not_found();
                }
                let total = FILE.len() as u64;
                match req.range(total, None) {
                    Ok(RangeOutcome::Ranges(rs)) => {
                        res.partial(FILE, &rs, "application/octet-stream")
                    }
                    Ok(RangeOutcome::Unsatisfiable) => res.range_not_satisfiable(total),
                    _ => res.ok(FILE),
                }
            })
            .build()
            .unwrap();
        let port = server.local_port();
        let node = server.node_id().unwrap();
        let dht = Dht::builder(&server).bootstrap(r_contact).attach().unwrap();
        dht.join(now_secs()).unwrap();
        a_tx.send(node).unwrap();
        pump(&server, &dht, &a_stop2, Some(lo(2, port)));
    });
    let a_node = a_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    println!("sender announced as node {a_node}");

    // give A a moment to register its announce with R.
    std::thread::sleep(Duration::from_millis(800));

    // the getter: resolves A by node_id through the dht, then downloads /blob in
    // 16-byte range windows (resumable  -  a partial file resumes from its size).
    let getter = Server::builder()
        .identity(Identity::generate()?)
        .bind(lo(3, 0))
        .build()?;
    let dht = Dht::builder(&getter)
        .bootstrap(Bootstrap::new(&r_node, &lo(1, r_port)))
        .attach()?;
    dht.join(now_secs())?;

    println!("resolving {a_node} via the dht...");
    let client = Client::builder()
        .identity(Identity::generate()?)
        .connect_by_node_id(&a_node, &dht, Duration::from_secs(8))?;

    let mut have: u64 = 0;
    let mut downloaded: Vec<u8> = Vec::new();
    loop {
        let range = format!("bytes={}-{}", have, have + 15);
        let resp = client
            .request(Method::Read, "/blob")
            .header("range", &range)
            .send()?;
        if resp.status() == Some(Status::RangeNotSatisfiable) {
            break;
        }
        let chunk = resp.into_body();
        if chunk.is_empty() {
            break;
        }
        have += chunk.len() as u64;
        let last = chunk.len() < 16;
        downloaded.extend_from_slice(&chunk);
        if last {
            break;
        }
    }
    println!(
        "downloaded {} bytes by node_id, match = {}",
        downloaded.len(),
        downloaded == FILE
    );

    a_stop.store(true, Ordering::Relaxed);
    r_stop.store(true, Ordering::Relaxed);
    a_thread.join().unwrap();
    r_thread.join().unwrap();
    Ok(())
}

// pumps a server + its dht until stop, re-announcing service periodically.
fn pump(server: &Server, dht: &Dht, stop: &AtomicBool, announce: Option<Address>) {
    let mut announced = 0u64;
    while !stop.load(Ordering::Relaxed) {
        server.tick(now_ms()).unwrap();
        let secs = now_secs();
        dht.tick(secs).unwrap();
        if let Some(addr) = announce {
            if announced == 0 || secs - announced >= 30 {
                let _ = dht.announce(&addr, secs);
                announced = secs;
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
