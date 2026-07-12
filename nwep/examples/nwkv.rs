// nwkv, a key-value service with notify pushes (mirrors sandbox/000-nwkv). a
// server stores values under paths via write, serves them via read, removes them
// via delete, and pushes a notify on each change. a client drives the whole
// lifecycle in one process and prints what it observes.

use nwep::{Address, Client, Identity, Method, Server, Status};
use std::collections::HashMap;
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

    let server_thread = std::thread::spawn(move || {
        let store: HashMap<String, Vec<u8>> = HashMap::new();
        let store = Arc::new(Mutex::new(store));
        // the handler stashes (conn) of each write; the loop pushes a notify to
        // them after tick (a handler holds no Server, so notify runs from the loop).
        let to_notify: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));

        let store_h = store.clone();
        let notify_h = to_notify.clone();
        let server = Server::builder()
            .identity(Identity::generate().unwrap())
            .bind(Address::loopback(0))
            .on_request(move |req, res| {
                let path = req.path().unwrap_or("").to_owned();
                let method = req.header(":method").unwrap_or("read").to_owned();
                let mut kv = store_h.lock().unwrap();
                match method.as_str() {
                    "write" => {
                        kv.insert(path, req.body().to_vec());
                        notify_h.lock().unwrap().push(req.conn_id());
                        res.status(Status::Created, b"")
                    }
                    "delete" => {
                        if kv.remove(&path).is_some() {
                            res.status(Status::NoContent, b"")
                        } else {
                            res.not_found()
                        }
                    }
                    _ => match kv.get(&path) {
                        Some(v) => res.ok(v),
                        None => res.not_found(),
                    },
                }
            })
            .build()
            .unwrap();
        tx.send((server.node_id().unwrap(), server.local_port()))
            .unwrap();
        while !stop_t.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            for conn in to_notify.lock().unwrap().drain(..) {
                let _ = server.notify(conn, "kv.changed", &[]);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let (node, port) = rx.recv_timeout(Duration::from_secs(3)).unwrap();

    let client = Client::builder()
        .identity(Identity::generate()?)
        .connect(&node, &Address::loopback(port))?;

    // write a value, then watch the change notification arrive.
    let w = client.send(Method::Write, "/greeting", b"hello kv")?;
    println!(
        "write /greeting  -> {}",
        w.status().unwrap_or(Status::Error)
    );
    for _ in 0..1000 {
        client.tick(now_ms())?;
        if let Some(n) = client.poll_notify() {
            println!("notify           -> {}", n.header(":event").unwrap_or("?"));
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // read it back, delete it, then confirm it is gone.
    let r = client.send(Method::Read, "/greeting", &[])?;
    println!(
        "read /greeting   -> {} {:?}",
        r.status().unwrap_or(Status::Error),
        String::from_utf8_lossy(r.body())
    );
    let d = client.send(Method::Delete, "/greeting", &[])?;
    println!(
        "delete /greeting -> {}",
        d.status().unwrap_or(Status::Error)
    );
    let g = client.send(Method::Read, "/greeting", &[])?;
    println!(
        "read /greeting   -> {} (gone)",
        g.status().unwrap_or(Status::Error)
    );

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
    Ok(())
}
