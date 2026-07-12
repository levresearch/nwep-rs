// the networked trust-verify path end to end. a real log server (Log +
// LogServer) runs behind a quic server, routing /log/* through dispatch; a client
// submits a key-binding entry (the on_append hook fires), and a trust store
// verifies the node's revocation status over the connection. mirrors the sandbox
// nwlog verify path in process. only built with the trust feature (verify_key).
#![cfg(feature = "trust")]

use nwep::trust::{KeyStatus, TrustStore};
use nwep::{
    log, Address, Client, DispatchOutcome, Identity, Log, LogServer, Method, Server, Status,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    Instant::now().elapsed().as_millis() as i64
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn log_server_serves_and_verify_key_confirms_not_revoked() {
    // the log server's identity is also the quic server's, so a signed
    // assertion's server-id matches the connection's peer.
    let server_id = Identity::generate().unwrap();
    let server_node = *server_id.node_id();

    let appended = Arc::new(AtomicU64::new(0));
    let appended_thread = appended.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();

    // a submitter publishes its own key binding; we verify that node's status.
    let submitter = Identity::generate().unwrap();
    let submitter_node = *submitter.node_id();
    let key_binding = log::key_binding(&submitter, &[0x22; 32], now_secs() as u64).unwrap();
    let kb_for_thread = key_binding.clone();

    let server_thread = std::thread::spawn(move || {
        // build the log server (owns its log) on this thread, then capture it in
        // the handler that routes /log/* and falls through otherwise.
        let mut log_server = LogServer::new(&server_id, Log::new().unwrap()).unwrap();
        log_server.on_append(move |_entry, _index| {
            appended_thread.fetch_add(1, Ordering::Relaxed);
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
        ready_tx.send(server.local_port()).unwrap();
        while !stop_thread.load(Ordering::Relaxed) {
            server.tick(now_ms()).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });

    let port = ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let client = Client::builder()
        .identity(Identity::generate().unwrap())
        .connect(&server_node, &Address::loopback(port))
        .unwrap();

    // submit the key binding over write /log/entry; the server accepts it.
    let resp = client
        .request(Method::Write, "/log/entry")
        .body(kb_for_thread)
        .send()
        .unwrap();
    assert_eq!(resp.status(), Some(Status::Created));
    assert_eq!(appended.load(Ordering::Relaxed), 1, "on_append fired once");

    // the trust store verifies the submitter's key is not revoked, over the wire.
    let mut store = TrustStore::new().unwrap();
    let status = store
        .verify_key(&client, &submitter_node, None, now_secs())
        .unwrap();
    assert_eq!(status, KeyStatus::NotRevoked);

    stop.store(true, Ordering::Relaxed);
    server_thread.join().unwrap();
    let _ = key_binding; // keep the original alive until here
}
