//! nwep managed runtime, the layer 2 that owns the event loop for you NWG0200 NWG0600.
//!
//! the c handles are single threaded and caller driven, so they cannot be
//! awaited across a multi threaded executor. instead each managed handle is
//! pinned to one dedicated owner thread that runs the real tick and poll loop,
//! and the async surface talks to it by message passing (the actor bridge,
//! NWG0600). the owner thread does exactly what a driven loop does, the async
//! api is a thin, Send safe bridge over it.
//!
//! built entirely on the public driven api ([crate::ServerBuilder::build],
//! [crate::Client]), so it adds convenience without a parallel implementation
//! and the driven layer stays reachable underneath (no cliffs, NWG0200).

use crate::address::Address;
use crate::client::{ClientBuilder, Response};
use crate::dht::{Dht, DhtMetrics};
use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::poll::{wait_readable, wait_readable2, Waker};
use crate::server::ServerBuilder;
use crate::wire::Method;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};

/// the owner loop caps its poll wait at this many ms, so a shutdown request is
/// noticed within one interval even when no transport timer is pending.
const POLL_CAP_MS: u32 = 200;

/// the managed dht re-announces its service address at least this often (seconds).
const ANNOUNCE_INTERVAL_SECS: u64 = 30;

/// returns a monotonic millisecond clock for tick, counted from first use.
///
/// the value is only required to be monotonic and in milliseconds, which the
/// process start instant gives without wall clock dependence.
fn now_ms() -> i64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

/// returns the unix-seconds wall clock the dht uses for its timers.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// managed server NWG0200

/// a command the server owner thread runs, with a channel for the reply. these
/// only exist when a managed dht is attached.
enum ServerCommand {
    Resolve {
        target: NodeId,
        timeout: Duration,
        reply: oneshot::Sender<Result<Address>>,
    },
    DhtMetrics {
        reply: oneshot::Sender<DhtMetrics>,
    },
}

/// RunningServer is a [crate::Server] whose loop is owned by the runtime NWG0200.
///
/// the server runs on its own thread, dispatching requests to the handler, until
/// this handle is dropped or [RunningServer::shutdown] is called. when built with
/// [crate::ServerBuilder::dht] it also owns a discovery dht on that thread, which
/// [RunningServer::resolve] queries.
pub struct RunningServer {
    node_id: NodeId,
    port: u16,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    // some only when a managed dht is attached; talks to the owner thread.
    cmd: Option<mpsc::Sender<ServerCommand>>,
}

impl RunningServer {
    /// returns the running server's own node_id NW040200.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// returns the bound udp port, useful after binding port 0.
    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// resolves a peer's node_id to an address through the managed dht NW110800.
    ///
    /// the managed counterpart of an iterative find_value lookup: the owner thread
    /// runs it while ticking, so this future resolves without blocking the async
    /// runtime. requires the server was built with [crate::ServerBuilder::dht].
    ///
    /// returns the resolved [Address].
    /// errors [Error::ConfigMissing] when no managed dht is attached,
    /// [Error::IdentityNotFound] when the lookup times out, and
    /// [Error::NetworkClosed] when the server has stopped.
    pub async fn resolve(&self, target: &NodeId, timeout: Duration) -> Result<Address> {
        let cmd = self.cmd.as_ref().ok_or(Error::ConfigMissing)?;
        let (reply, rx) = oneshot::channel();
        cmd.send(ServerCommand::Resolve {
            target: *target,
            timeout,
            reply,
        })
        .await
        .map_err(|_| Error::NetworkClosed)?;
        rx.await.map_err(|_| Error::NetworkClosed)?
    }

    /// returns a snapshot of the managed dht's traffic counters, or none if no dht.
    pub async fn dht_metrics(&self) -> Option<DhtMetrics> {
        let cmd = self.cmd.as_ref()?;
        let (reply, rx) = oneshot::channel();
        cmd.send(ServerCommand::DhtMetrics { reply }).await.ok()?;
        rx.await.ok()
    }

    /// stops the server and waits for its thread to finish.
    ///
    /// signals the owner loop to exit and joins it, so the socket is closed by
    /// the time this returns. dropping the handle stops the server too, but does
    /// not wait.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        // signal stop and detach. the owner thread exits within one poll
        // interval and closes the server there, so we never block in drop.
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ServerBuilder {
    /// builds the server and runs its loop on a dedicated thread NWG0200 NWG0600.
    ///
    /// the managed terminal of the builder. the server is built on the owner
    /// thread (the handle never crosses a boundary), then driven there with a
    /// real poll until the returned [RunningServer] is dropped or shut down. the
    /// on_request handler runs synchronously on that thread.
    ///
    /// returns the [RunningServer] once it is bound and listening.
    /// errors [Error::ConfigMissing] for an unset identity or bind address, and
    /// any bind error from the transport.
    pub async fn serve(mut self) -> Result<RunningServer> {
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(NodeId, u16)>>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();

        // the command channel exists only when a managed dht is attached; the
        // owner thread services it inside the tick loop.
        let dht_cfg = self.take_managed_dht();
        let has_dht = dht_cfg.is_some();
        let (cmd_tx, cmd_rx) = mpsc::channel::<ServerCommand>(32);

        let join = std::thread::Builder::new()
            .name("nwep-server".into())
            .spawn(move || {
                let server = match self.build() {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                // the dht borrows the server, so both live in this frame.
                let mut announce = None;
                let dht = match dht_cfg {
                    Some((contacts, ann, seq)) => {
                        announce = ann;
                        match attach_managed_dht(&server, contacts, seq) {
                            Ok(d) => Some(d),
                            Err(e) => {
                                let _ = ready_tx.send(Err(e));
                                return;
                            }
                        }
                    }
                    None => None,
                };
                let info = server.node_id().map(|n| (n, server.local_port()));
                let info = match info {
                    Ok(i) => i,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                if ready_tx.send(Ok(info)).is_err() {
                    return; // the caller went away before listening began.
                }
                run_server_loop(&server, dht.as_ref(), &announce, cmd_rx, &stop_for_thread);
                // server (and dht) drop here on the owner thread, closing the socket.
            })
            .map_err(|_| Error::Internal)?;

        match ready_rx.await {
            Ok(Ok((node_id, port))) => Ok(RunningServer {
                node_id,
                port,
                stop,
                join: Some(join),
                cmd: has_dht.then_some(cmd_tx),
            }),
            Ok(Err(e)) => {
                let _ = join.join();
                Err(e)
            }
            Err(_) => {
                let _ = join.join();
                Err(Error::Internal)
            }
        }
    }
}

/// attaches a dht to the just-built server and joins the network (owner thread).
fn attach_managed_dht(
    server: &crate::Server,
    contacts: Vec<crate::Bootstrap>,
    initial_seq: u64,
) -> Result<Dht<'_>> {
    let dht = Dht::builder(server)
        .bootstraps(contacts)
        .initial_seq(initial_seq)
        .attach()?;
    dht.join(now_secs())?;
    Ok(dht)
}

/// the server owner loop: ticks the server (and dht), re-announces, services dht
/// commands, and waits on the socket until the next timer or a wakeup.
fn run_server_loop(
    server: &crate::Server,
    dht: Option<&Dht<'_>>,
    announce: &Option<Address>,
    mut cmd_rx: mpsc::Receiver<ServerCommand>,
    stop: &AtomicBool,
) {
    let mut announced_at = 0u64;
    while !stop.load(Ordering::Relaxed) {
        if server.tick(now_ms()).is_err() {
            break;
        }
        if let Some(dht) = dht {
            let secs = now_secs();
            let _ = dht.tick(secs);
            if let Some(addr) = announce {
                if announced_at == 0 || secs - announced_at >= ANNOUNCE_INTERVAL_SECS {
                    let _ = dht.announce(addr, secs);
                    announced_at = secs;
                }
            }
            // service any pending dht commands (resolve / metrics). a resolve
            // drives its own lookup synchronously here, on the owner thread.
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    ServerCommand::Resolve {
                        target,
                        timeout,
                        reply,
                    } => {
                        let _ = reply.send(resolve_on_thread(server, dht, &target, timeout));
                    }
                    ServerCommand::DhtMetrics { reply } => {
                        let _ = reply.send(dht.metrics());
                    }
                }
            }
        }
        // the server and dht share the same socket; one fd covers both. fold the
        // dht's next timer into the poll wait so its retransmits stay timely.
        let mut wait = server.next_timeout(now_ms()).unwrap_or(POLL_CAP_MS);
        if let Some(dht) = dht {
            if let Some(d) = dht.next_timeout(now_secs()) {
                wait = wait.min(d);
            }
        }
        wait_readable(server.fd(), wait.min(POLL_CAP_MS));
    }
}

/// runs an iterative find_value lookup to completion on the owner thread, pumping
/// the shared socket and the dht timers until the record resolves or times out.
fn resolve_on_thread(
    server: &crate::Server,
    dht: &Dht<'_>,
    target: &NodeId,
    timeout: Duration,
) -> Result<Address> {
    // a record already in the local store resolves immediately.
    if let Some(rec) = dht.lookup_result(target) {
        return Ok(rec.address());
    }
    dht.start_lookup(target, now_secs())?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        server.tick(now_ms())?;
        let secs = now_secs();
        dht.tick(secs)?;
        if let Some(rec) = dht.lookup_result(target) {
            return Ok(rec.address());
        }
        let wait = dht.next_timeout(secs).unwrap_or(20).min(20);
        wait_readable(server.fd(), wait);
    }
    Err(Error::IdentityNotFound)
}

// managed client NWG0200 NWG0600

/// one request for the client owner thread to run, with a channel for the reply.
enum ClientCommand {
    Send {
        method: Method,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        reply: oneshot::Sender<Result<Response>>,
    },
}

/// AsyncClient is a [crate::Client] driven on its own thread, with an async api NWG0600.
///
/// requests are forwarded to the owner thread, which submits each one without
/// blocking and polls all of them from one tick loop  -  so many requests on a
/// single connection are serviced **concurrently**, not one at a time. dropping
/// the client stops its thread and fails any in flight requests.
pub struct AsyncClient {
    // option so Drop can drop the sender (disconnecting the channel) before
    // signalling the wakeup, so the owner sees the disconnect immediately.
    cmd: Option<mpsc::Sender<ClientCommand>>,
    wake: Arc<Waker>,
    _join: JoinHandle<()>,
}

impl ClientBuilder {
    /// opens a connection on a dedicated thread and returns an async client NWG0600.
    ///
    /// the managed counterpart of [crate::ClientBuilder::connect]. the blocking
    /// handshake runs on the owner thread, and this future resolves once it is
    /// connected. the owner thread then runs a tick loop that keeps many requests
    /// in flight at once.
    ///
    /// returns the connected [AsyncClient].
    /// errors [Error::ConfigMissing] for an unset identity, and a transport error
    /// (for example [Error::NetworkTimeout]) when the connection fails.
    pub async fn connect_async(self, target: &NodeId, addr: &Address) -> Result<AsyncClient> {
        let target = *target;
        let addr = *addr;
        let wake = Arc::new(Waker::new().map_err(|_| Error::Internal)?);
        let wake_owner = wake.clone();
        let (ready_tx, ready_rx) = oneshot::channel::<Result<()>>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<ClientCommand>(64);

        let join = std::thread::Builder::new()
            .name("nwep-client".into())
            .spawn(move || {
                let client = match self.connect(&target, &addr) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                run_client_loop(&client, cmd_rx, &wake_owner);
                // client drops here on the owner thread, closing the connection.
            })
            .map_err(|_| Error::Internal)?;

        match ready_rx.await {
            Ok(Ok(())) => Ok(AsyncClient {
                cmd: Some(cmd_tx),
                wake,
                _join: join,
            }),
            Ok(Err(e)) => {
                let _ = join.join();
                Err(e)
            }
            Err(_) => {
                let _ = join.join();
                Err(Error::Internal)
            }
        }
    }
}

impl Drop for AsyncClient {
    fn drop(&mut self) {
        // drop the sender first so the owner's try_recv sees the channel closed,
        // then wake it so it notices immediately rather than after a poll cap.
        self.cmd.take();
        self.wake.wake();
    }
}

/// the client owner loop: submits each requested command (non blocking), polls
/// all in flight requests every tick, and fires the reply of each that finished.
/// the eventfd wakes it the instant a new command is enqueued.
fn run_client_loop(
    client: &crate::Client,
    mut cmd_rx: mpsc::Receiver<ClientCommand>,
    wake: &Waker,
) {
    use tokio::sync::mpsc::error::TryRecvError;

    let cfd = client.fd();
    let wfd = wake.raw();
    // (request id, where to deliver its response).
    let mut pending: Vec<(crate::RequestId, oneshot::Sender<Result<Response>>)> = Vec::new();

    loop {
        // drain newly enqueued commands, submitting each request non blocking.
        loop {
            match cmd_rx.try_recv() {
                Ok(ClientCommand::Send {
                    method,
                    path,
                    headers,
                    body,
                    reply,
                }) => match client.submit_request(method, &path, &headers, &body) {
                    Ok(id) => pending.push((id, reply)),
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // the AsyncClient is gone; fail any in flight work and exit.
                    for (_, reply) in pending.drain(..) {
                        let _ = reply.send(Err(Error::NetworkClosed));
                    }
                    return;
                }
            }
        }

        // a terminally closed connection cannot recover; fail in flight requests
        // and exit. the owner thread returning drops cmd_rx, so a caller's next
        // send (or a pending await) resolves to NetworkClosed too.
        if client.tick(now_ms()).is_err() || !client.is_alive() {
            for (_, reply) in pending.drain(..) {
                let _ = reply.send(Err(Error::NetworkClosed));
            }
            return;
        }

        // poll every in flight request; deliver completions, drop them.
        let mut i = 0;
        while i < pending.len() {
            match client.poll_request(pending[i].0) {
                Ok(Some(resp)) => {
                    let (_, reply) = pending.swap_remove(i);
                    let _ = reply.send(Ok(resp));
                }
                Ok(None) => i += 1,
                Err(e) => {
                    let (_, reply) = pending.swap_remove(i);
                    let _ = reply.send(Err(e));
                }
            }
        }

        // wait for socket activity, a request timer, or a new command (eventfd).
        let wait = if pending.is_empty() {
            POLL_CAP_MS
        } else {
            client
                .next_timeout(now_ms())
                .unwrap_or(POLL_CAP_MS)
                .min(POLL_CAP_MS)
        };
        wait_readable2(cfd, wfd, wait);
        wake.drain();
    }
}

impl AsyncClient {
    /// starts an [AsyncRequestBuilder] for a request with headers or a body NWG0300.
    ///
    /// for example client.request(Method::Read, "/blob").header("range", "bytes=0-").send().await
    pub fn request(&self, method: Method, path: &str) -> AsyncRequestBuilder<'_> {
        AsyncRequestBuilder {
            client: self,
            method,
            path: path.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// sends one request with an optional body and no extra headers NW060000.
    ///
    /// the shortcut for the common case, equivalent to self.request(method, path).body(body).send().await
    ///
    /// returns the decoded [Response].
    /// errors [Error::NetworkClosed] when the connection thread has stopped, and
    /// any transport error the request itself produces.
    pub async fn send(&self, method: Method, path: &str, body: &[u8]) -> Result<Response> {
        self.request(method, path).body(body).send().await
    }

    /// forwards an assembled request to the owner thread and awaits its reply.
    ///
    /// the owner submits it without blocking and polls it alongside any other in
    /// flight requests, so awaiting two sends concurrently runs them in parallel
    /// on the one connection.
    async fn dispatch(
        &self,
        method: Method,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Response> {
        let cmd = self.cmd.as_ref().ok_or(Error::NetworkClosed)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        cmd.send(ClientCommand::Send {
            method,
            path,
            headers,
            body,
            reply: reply_tx,
        })
        .await
        .map_err(|_| Error::NetworkClosed)?;
        // wake the owner so it submits this request immediately, not after a poll.
        self.wake.wake();
        reply_rx.await.map_err(|_| Error::NetworkClosed)?
    }
}

/// AsyncRequestBuilder assembles a request with headers and a body, then awaits it NWG0300.
pub struct AsyncRequestBuilder<'c> {
    client: &'c AsyncClient,
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl AsyncRequestBuilder<'_> {
    /// adds a request header NW060300.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// sets the request body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// sends the request and awaits the response NW060000.
    ///
    /// returns the decoded [Response].
    /// errors [Error::NetworkClosed] when the connection thread has stopped, and
    /// any transport error the request itself produces.
    pub async fn send(self) -> Result<Response> {
        self.client
            .dispatch(self.method, self.path, self.headers, self.body)
            .await
    }
}

// managed streaming NW060200 NWG0200

/// the chunk channel item: a body chunk, or the end (Ok(None)) once the trailer
/// signature has verified, or an error.
type StreamItem = Result<Option<Vec<u8>>>;

/// a body chunk size for the owner thread's reads.
const STREAM_CHUNK: usize = 64 * 1024;

/// AsyncStream is a streamed response received over a dedicated connection NW060200.
///
/// the managed counterpart of [crate::Stream]: a body too large for one message
/// is pulled chunk by chunk with [AsyncStream::recv], without the caller writing
/// a loop. it runs on its own owner thread (and its own connection), so awaiting
/// chunks never blocks the async runtime. the stream is verified against the
/// peer's key when it ends, so reaching the end means the body was authentic.
pub struct AsyncStream {
    status: crate::Status,
    headers: Vec<(String, String)>,
    chunks: mpsc::Receiver<StreamItem>,
    _join: JoinHandle<()>,
}

impl AsyncStream {
    /// returns the streamed response's status, from its leading frame NW080000.
    pub fn status(&self) -> crate::Status {
        self.status
    }

    /// borrows a response header value, or none when it is absent NW060300.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// iterates the streamed response's headers in wire order NW060300.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// awaits the next body chunk, or none once the stream ends NW060200.
    ///
    /// the owner thread reads the body and delivers each chunk here. once it
    /// returns none the body is complete and its trailer signature has verified
    /// against the connection peer NW060900  -  an authentic, whole body.
    ///
    /// returns some chunk while streaming, or none at the verified end.
    /// errors a transport [Error] mid-stream, or [Error::CryptoVerify] when the
    /// trailer signature does not verify.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        match self.chunks.recv().await {
            Some(item) => item,
            None => Ok(None), // the owner thread ended without an explicit close.
        }
    }
}

impl ClientBuilder {
    /// opens a streamed response over a dedicated connection, fully async NW060200.
    ///
    /// the managed terminal for receiving a body too large for one message: it
    /// connects on its own owner thread, opens the stream, reads the metadata
    /// frame, and returns an [AsyncStream] whose [AsyncStream::recv] yields the
    /// body chunk by chunk. the connection is dedicated to this stream and closes
    /// when the stream drops.
    ///
    /// returns the open [AsyncStream] (its status + headers already read).
    /// errors [Error::ConfigMissing] for an unset identity, and a transport error
    /// when the connection or stream cannot open.
    pub async fn stream(
        self,
        method: Method,
        path: &str,
        target: &NodeId,
        addr: &Address,
    ) -> Result<AsyncStream> {
        let target = *target;
        let addr = *addr;
        let path = path.to_owned();
        let (ready_tx, ready_rx) =
            oneshot::channel::<Result<(crate::Status, Vec<(String, String)>)>>();
        let (chunk_tx, chunk_rx) = mpsc::channel::<StreamItem>(8);

        let join = std::thread::Builder::new()
            .name("nwep-stream".into())
            .spawn(move || {
                // connect, open the stream, and read its metadata, all on this thread.
                let client = match self.connect(&target, &addr) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let stream = match client.open_stream(method, &path) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let meta = match stream.response() {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let status = meta.status().unwrap_or(crate::Status::Error);
                let headers: Vec<(String, String)> = meta
                    .headers()
                    .map(|(n, v)| (n.to_owned(), v.to_owned()))
                    .collect();
                if ready_tx.send(Ok((status, headers))).is_err() {
                    return; // the caller dropped the future before metadata arrived.
                }
                let peer = client.peer_pubkey().unwrap_or([0u8; 32]);

                // pull the body chunk by chunk; deliver each, then verify at end.
                let mut buf = vec![0u8; STREAM_CHUNK];
                loop {
                    match stream.recv(&mut buf) {
                        Ok((n, ended)) => {
                            if n > 0 && chunk_tx.blocking_send(Ok(Some(buf[..n].to_vec()))).is_err()
                            {
                                return; // the consumer dropped the AsyncStream.
                            }
                            if ended {
                                let end = match stream.verify(&peer) {
                                    Ok(()) => Ok(None),
                                    Err(e) => Err(e),
                                };
                                let _ = chunk_tx.blocking_send(end);
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = chunk_tx.blocking_send(Err(e));
                            return;
                        }
                    }
                }
                // stream + client drop here, closing the dedicated connection.
            })
            .map_err(|_| Error::Internal)?;

        match ready_rx.await {
            Ok(Ok((status, headers))) => Ok(AsyncStream {
                status,
                headers,
                chunks: chunk_rx,
                _join: join,
            }),
            Ok(Err(e)) => {
                let _ = join.join();
                Err(e)
            }
            Err(_) => {
                let _ = join.join();
                Err(Error::Internal)
            }
        }
    }
}
