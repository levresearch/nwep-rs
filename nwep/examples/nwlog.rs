// nwlog, a transparency-log node (mirrors sandbox/002-nwlog). a real in-memory
// merkle log runs behind a quic server via the log-server router; a client builds
// its own signed key-binding entry and submits it over write /log/entry, which the
// server verifies and appends (the on-append hook fires). the entry decodes back
// to the same fields. this is the producer + log-node story; verifying others'
// entries against a bls checkpoint is the trust feature (see the trust tests).

use nwep::log::{self, EntryType, KeyBinding};
use nwep::{Address, Client, DispatchOutcome, Identity, Log, LogServer, Method, Server, Status};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn main() -> nwep::Result<()> {
    // the submitter builds its own signed key-binding entry NW120300.
    let submitter = Identity::generate()?;
    let key_binding = log::key_binding(&submitter, &[0x11; 32], now_secs() as u64)?;
    // it decodes back to the same fields, before we ever submit it.
    let decoded = KeyBinding::decode(&key_binding)?;
    println!("entry type    : {:?}", EntryType::of(&key_binding)?);
    println!("entry node_id : {}", decoded.node_id);
    println!(
        "matches signer: {}",
        &decoded.node_id == submitter.node_id()
    );

    let appended = Arc::new(AtomicU64::new(0));
    let appended_h = appended.clone();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = stop.clone();

    // the log node: a Log + LogServer behind the quic server. the log-server
    // identity is the quic identity, so a signed assertion's server-id matches
    // the connection peer.
    let server_thread = std::thread::spawn(move || {
        let server_id = Identity::generate().unwrap();
        let mut log_server = LogServer::new(&server_id, Log::new().unwrap()).unwrap();
        log_server.on_append(move |_bytes, index| {
            appended_h.store(index + 1, Ordering::Relaxed);
        });
        let server = Server::builder()
            .identity(server_id)
            .bind(Address::loopback(0))
            .on_request(
                move |req, res| match log_server.dispatch(req, res, now_secs()) {
                    DispatchOutcome::Handled(reply) => reply,
                    DispatchOutcome::NotMine(res) => res.not_found(),
                },
            )
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

    // submit the key binding over write /log/entry; the node verifies + appends it.
    let resp = client
        .request(Method::Write, "/log/entry")
        .body(key_binding)
        .send()?;
    println!("submit entry  : {}", resp.status().unwrap_or(Status::Error));
    println!("log size now  : {}", appended.load(Ordering::Relaxed));

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
    Ok(())
}
