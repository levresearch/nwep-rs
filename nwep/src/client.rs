//! nwep client, the outbound half of a web/1 node NW070000.
//!
//! Client opens one connection to a peer and sends requests over it. this slice
//! is the blocking surface, connect and send drive their own socket internally
//! and return when complete (the async, event loop driven surface is layered on
//! later, NWG0600). the handle is single threaded, which the raw pointer field
//! encodes as !Send and !Sync NWG0900.
//!
//! # example
//!
//! ```no_run
//! use nwep::{Address, Client, Identity, Method, NodeId};
//!
//! # let peer: NodeId = unimplemented!();
//! let client = Client::builder()
//!     .identity(Identity::generate()?)
//!     .connect(&peer, &Address::loopback(443))?;
//! let body = client.send(Method::Read, "/hello", &[])?.into_body();
//! # Ok::<(), nwep::Error>(())
//! ```

use crate::address::Address;
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::message::Headers;
use crate::raw::RawSocket;
use crate::server::Compression;
use crate::wire::{Method, Status};
use core::cell::Cell;
use core::ffi::{c_char, c_void, CStr};
use core::ptr;
use nwep_sys as sys;
use std::ffi::CString;
use std::rc::Rc;

/// ClientMetrics is one client's observability snapshot NW000017.
///
/// cumulative counters plus two gauges (requests_inflight, alive) and the
/// connection's smoothed rtt. pull model, scrape it whenever.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientMetrics {
    /// submitted but not yet terminal (gauge).
    pub requests_inflight: u64,
    /// requests finished with a response (cumulative).
    pub requests_completed: u64,
    /// requests timed out, closed, or errored (cumulative).
    pub requests_failed: u64,
    /// ngtcp2 smoothed rtt in microseconds, 0 if the connection is down.
    pub smoothed_rtt_us: u64,
    /// whether the connection is usable (gauge).
    pub alive: bool,
}

// response NW060000

/// Response is an owned decoded response from a [Client] request NW060000.
///
/// it owns the underlying message and frees it on drop. its borrowed strings and
/// body live as long as the Response.
pub struct Response {
    msg: *mut sys::nwep_message,
}

impl Response {
    /// returns the response status NW080000.
    ///
    /// an unknown status token degrades to [Status::Error] per spec 8. returns
    /// none only when the message carries no status, which a valid response
    /// always does.
    pub fn status(&self) -> Option<Status> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let p = unsafe { sys::nwep_message_get_status(self.msg) };
        if p.is_null() {
            return None;
        }
        // SAFETY: the library writes nul-terminated strings into its own memory; the null check above guarantees non-null.
        let token = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("error");
        Some(Status::from_token(token))
    }

    /// borrows the value of header name, or none when it is absent.
    pub fn header(&self, name: &str) -> Option<&str> {
        let cname = std::ffi::CString::new(name).ok()?;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let p = unsafe { sys::nwep_message_get_header(self.msg, cname.as_ptr()) };
        if p.is_null() {
            return None;
        }
        // SAFETY: the library writes nul-terminated strings into its own memory; the null check above guarantees non-null.
        unsafe { CStr::from_ptr(p) }.to_str().ok()
    }

    /// borrows the response body, empty when there is none.
    pub fn body(&self) -> &[u8] {
        let mut len = 0usize;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let p = unsafe { sys::nwep_message_get_body(self.msg, &mut len) };
        if p.is_null() || len == 0 {
            &[]
        } else {
            // SAFETY: the library owns the body buffer; the null check and len are consistent from the same call.
            unsafe { core::slice::from_raw_parts(p, len) }
        }
    }

    /// iterates every response header in wire order NW060300.
    pub fn headers(&self) -> Headers<'_> {
        Headers::new(self.msg)
    }

    /// consumes the response and returns its body as an owned vector.
    pub fn into_body(self) -> Vec<u8> {
        self.body().to_vec()
    }

    /// borrows the raw c message, for a verbatim relay onto a parked stream.
    pub(crate) fn as_raw(&self) -> *const sys::nwep_message {
        self.msg
    }

    /// wraps a raw c message returned by a lower layer (a cache hit).
    pub(crate) fn from_raw(msg: *mut sys::nwep_message) -> Response {
        Response { msg }
    }

    /// verifies this response's signature against an origin pubkey for path NW060900.
    ///
    /// the explicit-pubkey check, for a shared cache or any consumer that knows
    /// the origin's key out of band. now_secs is unix seconds, and if the response
    /// carries cache-control max-age the signature is rejected once stale (pass 0
    /// to skip the freshness gate). use [Client::verify_response] to source the
    /// pubkey from the connection instead.
    ///
    /// returns unit when the signature is valid (and fresh).
    /// errors [Error::ProtoInvalidHeader] for a missing signature and
    /// [Error::CryptoVerify] for a bad or stale one.
    pub fn verify(&self, origin_pubkey: &[u8; 32], path: &str, now_secs: u64) -> Result<()> {
        let cpath = CString::new(path).map_err(|_| Error::ProtoInvalidHeader)?;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_response_verify(self.msg, origin_pubkey.as_ptr(), cpath.as_ptr(), now_secs)
        })
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_message_free(self.msg) };
    }
}

// a Response uniquely owns its message pointer (no aliasing) and the c allocator
// that frees it is thread safe, so it is sound to move a Response between
// threads. this lets the managed runtime return one across its actor boundary
// NWG0600. it stays !Sync, the c accessors are not safe to call concurrently.
unsafe impl Send for Response {}

// client builder NW070000 NWG0300

/// ClientBuilder configures and opens a [Client] NWG0300.
#[derive(Default)]
pub struct ClientBuilder {
    identity: Option<Identity>,
}

impl ClientBuilder {
    /// sets the identity this client proves ownership of NW090000.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// opens a blocking connection to a peer at a known address NW070000.
    ///
    /// drives the handshake internally and returns once connected. to resolve a
    /// node_id through the dht instead, use [ClientBuilder::connect_by_node_id].
    ///
    /// returns the connected [Client].
    /// errors [Error::ConfigMissing] when the identity is unset, and a transport
    /// error (for example [Error::NetworkTimeout]) when the connection fails.
    pub fn connect(self, target: &NodeId, addr: &Address) -> Result<Client> {
        let identity = self.identity.ok_or(Error::ConfigMissing)?;
        let mut raw: *mut sys::nwep_client = ptr::null_mut();
        identity.with_keypair(|kp| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_client_connect(&mut raw, kp, &target.raw(), addr.as_raw())
            })
        })?;
        Ok(Client::wrap(raw))
    }

    /// starts a non-blocking connection to a peer, for an event loop NW070000.
    ///
    /// returns immediately with a [Connecting] you drive to readiness from your
    /// loop ([Connecting::tick] + [Connecting::poll]). to adopt your own socket
    /// instead, use [ClientBuilder::start_connect_fd].
    ///
    /// returns the [Connecting] handle.
    /// errors [Error::ConfigMissing] when the identity is unset, and a transport
    /// error when the connect cannot start.
    pub fn start_connect(self, target: &NodeId, addr: &Address) -> Result<Connecting> {
        let identity = self.identity.ok_or(Error::ConfigMissing)?;
        let mut raw: *mut sys::nwep_client = ptr::null_mut();
        identity.with_keypair(|kp| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_client_connect_async(&mut raw, kp, &target.raw(), addr.as_raw())
            })
        })?;
        Ok(Connecting { raw })
    }

    /// opens a blocking connection adopting a caller-owned udp socket NW070000.
    ///
    /// ownership of fd transfers to the client (closed on drop). the socket must
    /// be an af_inet6 udp socket. the primitive for multi-reactor scale-out.
    ///
    /// returns the connected [Client].
    /// errors [Error::ConfigMissing] when the identity is unset, and a transport
    /// error when the connection fails.
    pub fn connect_fd(self, target: &NodeId, addr: &Address, fd: RawSocket) -> Result<Client> {
        let identity = self.identity.ok_or(Error::ConfigMissing)?;
        let fd = crate::raw::to_c(fd);
        let mut raw: *mut sys::nwep_client = ptr::null_mut();
        identity.with_keypair(|kp| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_client_connect_fd(&mut raw, kp, &target.raw(), addr.as_raw(), fd)
            })
        })?;
        Ok(Client::wrap(raw))
    }

    /// starts a non-blocking connection adopting a caller-owned socket NW070000.
    ///
    /// the async counterpart of [ClientBuilder::connect_fd]; fd ownership
    /// transfers to the returned [Connecting].
    ///
    /// returns the [Connecting] handle.
    /// errors [Error::ConfigMissing] when the identity is unset, and a transport
    /// error when the connect cannot start.
    pub fn start_connect_fd(
        self,
        target: &NodeId,
        addr: &Address,
        fd: RawSocket,
    ) -> Result<Connecting> {
        let identity = self.identity.ok_or(Error::ConfigMissing)?;
        let fd = crate::raw::to_c(fd);
        let mut raw: *mut sys::nwep_client = ptr::null_mut();
        identity.with_keypair(|kp| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_client_connect_fd_async(&mut raw, kp, &target.raw(), addr.as_raw(), fd)
            })
        })?;
        Ok(Connecting { raw })
    }

    /// resolves target through the dht and connects, blocking up to timeout NW110800.
    ///
    /// the headline of the protocol, dial a peer by node_id alone with no dns. it
    /// reads the dht's local store first, then runs an iterative find_value lookup
    /// NW110800, driving the dht's server and timers itself while it waits.
    /// must not run while another thread ticks that same server.
    ///
    /// returns the connected [Client].
    /// errors [Error::ConfigMissing] when the identity is unset,
    /// [Error::IdentityNotFound] when the lookup times out with no record, and a
    /// transport error once the address is known.
    pub fn connect_by_node_id(
        self,
        target: &NodeId,
        dht: &crate::Dht,
        timeout: std::time::Duration,
    ) -> Result<Client> {
        let identity = self.identity.ok_or(Error::ConfigMissing)?;
        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let mut raw: *mut sys::nwep_client = ptr::null_mut();
        identity.with_keypair(|kp| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_client_connect_by_nodeid(&mut raw, kp, &target.raw(), dht.as_ptr(), ms)
            })
        })?;
        Ok(Client::wrap(raw))
    }
}

// client NW070000

/// the boxed request-completion callback, owned by the Client at a stable address.
type DoneHook = Box<dyn FnMut(RequestId, Result<Response>)>;

/// Client is an open connection to one peer NW070000.
pub struct Client {
    raw: *mut sys::nwep_client,
    // a borrowed cache kept alive for the connection (set_cache); shared by Rc so
    // several clients can use one cache on the same thread.
    cache: Cell<Option<Rc<crate::Cache>>>,
    // the request-done callback box, or null (set_request_done).
    done: Cell<*mut DoneHook>,
}

impl Client {
    /// starts a [ClientBuilder].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// wraps a freshly connected raw client with empty cache/callback slots.
    fn wrap(raw: *mut sys::nwep_client) -> Client {
        Client {
            raw,
            cache: Cell::new(None),
            done: Cell::new(ptr::null_mut()),
        }
    }

    /// starts a [RequestBuilder] for a request with headers or a body NWG0300.
    ///
    /// for example client.request(Method::Read, "/blob").header("range", "bytes=0-").send()
    pub fn request(&self, method: Method, path: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method,
            path: path.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// sends one request with an optional body and no extra headers NW060000.
    ///
    /// the shortcut for the common case, equivalent to self.request(method, path).body(body).send()
    ///
    /// returns the decoded [Response].
    /// errors [Error::ProtoInvalidHeader] when path is malformed, and a transport
    /// error when the exchange fails.
    pub fn send(&self, method: Method, path: &str, body: &[u8]) -> Result<Response> {
        self.request(method, path).body(body).send()
    }

    /// opens a streamed response for a body too large for one message NW060200.
    ///
    /// sends a body-less request and returns a [Stream] to read the metadata then
    /// the body chunks. blocking, like [Client::send].
    ///
    /// returns the open [Stream].
    /// errors [Error::ProtoInvalidHeader] when path is malformed, and a transport
    /// error when the stream cannot open.
    pub fn open_stream(&self, method: Method, path: &str) -> Result<Stream<'_>> {
        let cpath = CString::new(path).map_err(|_| Error::ProtoInvalidHeader)?;
        let mut id = 0u64;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_client_open_stream(
                self.raw,
                method.code(),
                cpath.as_ptr(),
                ptr::null(),
                &mut id,
            )
        })?;
        Ok(Stream { client: self, id })
    }

    /// verifies a response's signature against this connection's peer NW060900.
    ///
    /// sources the origin pubkey from the authenticated peer, so there is no key
    /// to pass. path is the request path the response answers (bound into the
    /// signed form). now_secs is unix seconds (0 to skip the freshness gate).
    ///
    /// returns unit when the signature is valid.
    /// errors [Error::ProtoInvalidHeader] for a missing signature and
    /// [Error::CryptoVerify] for a bad or stale one.
    pub fn verify_response(&self, response: &Response, path: &str, now_secs: u64) -> Result<()> {
        let cpath = CString::new(path).map_err(|_| Error::ProtoInvalidHeader)?;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_client_verify_response(self.raw, response.as_raw(), cpath.as_ptr(), now_secs)
        })
    }

    /// returns whether the connection is still usable NW070000.
    ///
    /// false once it has terminally closed (idle timeout, peer close, or a fatal
    /// quic error). poll it to drive reconnection of a persistent connection. a
    /// closed client ticks as a no-op and reports no timer, so an event loop
    /// never busy-spins on a dead connection.
    pub fn is_alive(&self) -> bool {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_client_is_alive(self.raw) == 1 }
    }

    /// returns the codec this connection negotiated NW000017.
    pub fn compression(&self) -> Compression {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        match unsafe { sys::nwep_client_compression(self.raw) } {
            0 => Compression::None,
            1 => Compression::Zstd,
            _ => Compression::Unknown,
        }
    }

    /// returns the connected server's ed25519 public key, learned in the handshake.
    ///
    /// the key [Response::verify] checks a signed response against NW090000 NW060900.
    ///
    /// returns the 32-byte peer public key.
    /// errors [Error::NetworkClosed] when the connection is not established.
    pub fn peer_pubkey(&self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_client_peer_pubkey(self.raw, out.as_mut_ptr()) })?;
        Ok(out)
    }

    /// returns a snapshot of this client's observability counters NW000017.
    pub fn metrics(&self) -> ClientMetrics {
        let mut m = sys::nwep_client_metrics {
            requests_inflight: 0,
            requests_completed: 0,
            requests_failed: 0,
            smoothed_rtt_us: 0,
            alive: 0,
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_client_metrics_get(self.raw, &mut m) };
        ClientMetrics {
            requests_inflight: m.requests_inflight,
            requests_completed: m.requests_completed,
            requests_failed: m.requests_failed,
            smoothed_rtt_us: m.smoothed_rtt_us,
            alive: m.alive == 1,
        }
    }

    /// advances client state, the driven event-loop primitive NW070000.
    ///
    /// reads datagrams, runs quic timers, completes in-flight work, and flushes
    /// output. call it on each [Client::fd] wakeup and timer expiry. now_ms is a
    /// monotonic millisecond clock. the blocking send/connect calls drive this
    /// themselves, so it is only needed for hand-rolled loops.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the tick fails.
    pub fn tick(&self, now_ms: i64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_client_tick(self.raw, now_ms) })
    }

    /// returns the udp socket descriptor, to register with a poller NW070000.
    pub fn fd(&self) -> RawSocket {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        crate::raw::from_c(unsafe { sys::nwep_client_fd(self.raw) })
    }

    /// returns milliseconds until the next required [Client::tick], or none NW070000.
    ///
    /// none means block on the socket alone (no timer pending); a returned zero
    /// means tick now. fold it into your poll timeout.
    pub fn next_timeout(&self, now_ms: i64) -> Option<u32> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let ms = unsafe { sys::nwep_client_next_timeout_ms(self.raw, now_ms) };
        if ms < 0 {
            None
        } else {
            Some(ms as u32)
        }
    }

    /// attaches a shared cache to this client, or detaches with none NW060700.
    ///
    /// a client-attached cache is consulted transparently by cache-aware sends.
    /// the cache is shared by [Rc] so several clients on this thread can use one;
    /// the client holds its [Rc] for the connection's life, so the cache always
    /// outlives the borrow the c side keeps.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the attach fails.
    pub fn set_cache(&self, cache: Option<Rc<crate::Cache>>) -> Result<()> {
        let ptr = cache.as_ref().map_or(ptr::null_mut(), |c| c.as_ptr());
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_client_set_cache(self.raw, ptr) })?;
        // hold (or release) the cache so it outlives the borrow; the old one, if
        // any, drops only after this returns, while still attached for the call.
        self.cache.set(cache);
        Ok(())
    }

    /// registers a callback fired the instant a submitted request completes NW060000.
    ///
    /// the push counterpart of [RequestHandle::poll]: the closure runs inside
    /// [Client::tick] with the request id and its result. it runs on the client's
    /// thread and must not block or re-enter tick. pass a closure to set it,
    /// replacing any previous one.
    pub fn on_request_done(&self, hook: impl FnMut(RequestId, Result<Response>) + 'static) {
        // free any previous hook before installing the new one.
        let prev = self.done.replace(ptr::null_mut());
        if !prev.is_null() {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            drop(unsafe { Box::from_raw(prev) });
        }
        let boxed: *mut DoneHook = Box::into_raw(Box::new(Box::new(hook)));
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe {
            sys::nwep_client_set_request_done(self.raw, Some(done_trampoline), boxed as *mut c_void)
        };
        self.done.set(boxed);
    }

    /// pumps the connection and returns the next queued notify push NW060200.
    ///
    /// returns some [Response] carrying the notify (read its event from the
    /// ":event" header), or none when none is pending. call repeatedly to drain.
    pub fn poll_notify(&self) -> Option<Response> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let msg = unsafe { sys::nwep_client_poll_notify(self.raw) };
        if msg.is_null() {
            None
        } else {
            Some(Response { msg })
        }
    }

    /// submits a request by value and returns just its id, no borrow NW060000.
    ///
    /// the borrow-free form the managed runtime uses to keep many requests in
    /// flight: it returns an owned [RequestId] rather than a borrowing
    /// [RequestHandle], so the runtime can hold the id alongside the client and
    /// poll it with [Client::poll_request]. the body and headers are copied.
    ///
    /// returns the in-flight request's id.
    /// errors [Error::ProtoInvalidHeader] for a bad path/header, and
    /// [Error::ProtoMaxStreams] at the connection's concurrent-stream limit.
    #[cfg(feature = "runtime")]
    pub(crate) fn submit_request(
        &self,
        method: Method,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<RequestId> {
        let cpath = CString::new(path).map_err(|_| Error::ProtoInvalidHeader)?;
        let mut cstrings: Vec<(CString, CString)> = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let n = CString::new(name.as_str()).map_err(|_| Error::ProtoInvalidHeader)?;
            let v = CString::new(value.as_str()).map_err(|_| Error::ProtoInvalidHeader)?;
            cstrings.push((n, v));
        }
        let mut array: Vec<sys::nwep_header> = cstrings
            .iter()
            .map(|(n, v)| sys::nwep_header {
                name: n.as_ptr(),
                value: v.as_ptr(),
            })
            .collect();
        array.push(sys::nwep_header {
            name: ptr::null(),
            value: ptr::null(),
        });
        let (bptr, blen) = if body.is_empty() {
            (ptr::null(), 0)
        } else {
            (body.as_ptr(), body.len())
        };
        let mut id = 0u64;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_client_request_submit(
                self.raw,
                method.code(),
                cpath.as_ptr(),
                array.as_ptr(),
                bptr,
                blen,
                &mut id,
            )
        })?;
        Ok(id)
    }

    /// polls a request previously submitted with [Client::submit_request] NW060000.
    ///
    /// returns some response when complete, none while still in flight; the id is
    /// retired on completion or error.
    #[cfg(feature = "runtime")]
    pub(crate) fn poll_request(&self, id: RequestId) -> Result<Option<Response>> {
        let mut out: *mut sys::nwep_message = ptr::null_mut();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_client_request_poll(self.raw, id, &mut out) };
        match rc {
            0 => Ok(Some(Response { msg: out })),
            c if c == Error::WouldBlock.code() => Ok(None),
            other => Err(Error::from_code(other)),
        }
    }

    /// borrows the raw c client handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_client {
        self.raw
    }
}

// streamed response NW060200

/// Stream is a streamed response being received from a [Client] NW060200.
///
/// read the metadata with [Stream::response], then the body chunk by chunk with
/// [Stream::recv] until it ends, and optionally [Stream::verify] the signature.
/// it releases its bookkeeping on drop.
pub struct Stream<'c> {
    client: &'c Client,
    id: u64,
}

impl Stream<'_> {
    /// reads the leading metadata frame, the status and headers NW060200.
    ///
    /// blocks until it arrives. call once, before [Stream::recv].
    ///
    /// returns the metadata [Response] (no body).
    /// errors a transport [Error] when the frame cannot be read.
    pub fn response(&self) -> Result<Response> {
        let mut resp: *mut sys::nwep_message = ptr::null_mut();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_client_stream_response(self.client.raw, self.id, &mut resp)
        })?;
        Ok(Response { msg: resp })
    }

    /// reads the next body chunk into buf, blocking until data or the end NW060200.
    ///
    /// returns the number of bytes written to buf and whether the stream has
    /// ended. stop once ended is true.
    ///
    /// returns (bytes_written, ended).
    /// errors a transport [Error] when the read fails.
    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0usize;
        let mut ended: core::ffi::c_int = 0;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_client_stream_recv(
                self.client.raw,
                self.id,
                buf.as_mut_ptr(),
                buf.len(),
                &mut len,
                &mut ended,
            )
        })?;
        Ok((len, ended != 0))
    }

    /// verifies the fully-received stream's signature against pubkey NW060900.
    ///
    /// call after [Stream::recv] reports the stream ended.
    ///
    /// returns unit when the signature is valid.
    /// errors [Error::CryptoVerify] on a missing, invalid, or truncated signature.
    pub fn verify(&self, pubkey: &[u8; 32]) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_client_stream_verify(self.client.raw, self.id, pubkey.as_ptr())
        })
    }
}

impl Drop for Stream<'_> {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_client_stream_close(self.client.raw, self.id) };
    }
}

// request builder NW060000 NWG0300

/// RequestBuilder assembles a request with headers and a body, then sends it NWG0300.
pub struct RequestBuilder<'c> {
    client: &'c Client,
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl<'c> RequestBuilder<'c> {
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

    /// sends the request and blocks for the response NW060000.
    ///
    /// returns the decoded [Response].
    /// errors [Error::ProtoInvalidHeader] when the path or a header holds an
    /// interior nul, and a transport error when the exchange fails.
    pub fn send(self) -> Result<Response> {
        let client = self.client;
        let method = self.method.code();
        self.with_c(|cpath, headers, bptr, blen| {
            let mut resp: *mut sys::nwep_message = ptr::null_mut();
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_client_send(client.raw, method, cpath, headers, bptr, blen, &mut resp)
            })?;
            Ok(Response { msg: resp })
        })
    }

    /// submits the request without blocking, for an event loop NW060000.
    ///
    /// returns immediately with a [RequestHandle] to poll. the body and headers
    /// are copied, so nothing here needs to outlive the call. drive completion
    /// with [Client::tick] + [RequestHandle::poll].
    ///
    /// returns the in-flight [RequestHandle].
    /// errors [Error::ProtoInvalidHeader] for a bad path/header, and
    /// [Error::ProtoMaxStreams] at the connection's concurrent-stream limit
    /// (apply backpressure and retry).
    pub fn submit(self) -> Result<RequestHandle<'c>> {
        let client = self.client;
        let method = self.method.code();
        let id = self.with_c(|cpath, headers, bptr, blen| {
            let mut id = 0u64;
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_client_request_submit(
                    client.raw, method, cpath, headers, bptr, blen, &mut id,
                )
            })?;
            Ok(id)
        })?;
        Ok(RequestHandle {
            client,
            id,
            done: false,
        })
    }

    /// builds the c path, header array, and body pointers and runs f with them.
    ///
    /// the c strings and array live for the closure's duration, so a call that
    /// borrows their pointers must finish inside f (both send and submit do).
    fn with_c<R>(
        self,
        f: impl FnOnce(*const c_char, *const sys::nwep_header, *const u8, usize) -> Result<R>,
    ) -> Result<R> {
        let cpath = CString::new(self.path).map_err(|_| Error::ProtoInvalidHeader)?;
        let mut cstrings: Vec<(CString, CString)> = Vec::with_capacity(self.headers.len());
        for (name, value) in self.headers {
            let n = CString::new(name).map_err(|_| Error::ProtoInvalidHeader)?;
            let v = CString::new(value).map_err(|_| Error::ProtoInvalidHeader)?;
            cstrings.push((n, v));
        }
        let mut header_array: Vec<sys::nwep_header> = cstrings
            .iter()
            .map(|(n, v)| sys::nwep_header {
                name: n.as_ptr(),
                value: v.as_ptr(),
            })
            .collect();
        // a null-name entry terminates the array (the c sentinel).
        header_array.push(sys::nwep_header {
            name: ptr::null(),
            value: ptr::null(),
        });
        let (bptr, blen) = if self.body.is_empty() {
            (ptr::null(), 0)
        } else {
            (self.body.as_ptr(), self.body.len())
        };
        f(cpath.as_ptr(), header_array.as_ptr(), bptr, blen)
    }
}

/// the c request-done callback. rebuilds (id, Result<Response>) and runs the
/// user hook. it cannot unwind into c, so a panic is swallowed NWG0900.
unsafe extern "C" fn done_trampoline(
    _client: *mut sys::nwep_client,
    id: u64,
    status: core::ffi::c_int,
    resp: *mut sys::nwep_message,
    ud: *mut c_void,
) {
    // SAFETY: ud is a valid DoneHook pointer installed by set_request_done, alive for this callback.
    let hook = unsafe { &mut *(ud as *mut DoneHook) };
    // status 0 hands us an owned message; a negative status leaves resp null.
    let result = if status == 0 {
        Ok(Response { msg: resp })
    } else {
        Err(Error::from_code(status))
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(id, result)));
}

impl Drop for Client {
    fn drop(&mut self) {
        // close the connection first so no callback can fire, then free the
        // callback box; the cache Rc drops last (its Cell), after the borrow has
        // certainly ended.
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_client_close(self.raw) };
        let done = self.done.replace(ptr::null_mut());
        if !done.is_null() {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            drop(unsafe { Box::from_raw(done) });
        }
    }
}

// async connect NW070000

/// Connecting is an in-progress non-blocking connection NW070000.
///
/// drive it from your loop: [Connecting::tick] then [Connecting::poll] until it
/// reports ready, then [Connecting::into_client]. it exposes [Connecting::fd] and
/// [Connecting::next_timeout] for the poll wait. dropping it before completion
/// closes the connection.
pub struct Connecting {
    raw: *mut sys::nwep_client,
}

impl Connecting {
    /// advances the handshake; call before [Connecting::poll] NW070000.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the tick fails.
    pub fn tick(&self, now_ms: i64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_client_tick(self.raw, now_ms) })
    }

    /// polls the handshake's progress NW070000.
    ///
    /// tick first, then poll. once it returns true, take the [Client] with
    /// [Connecting::into_client].
    ///
    /// returns true when the handshake is complete, false while it is in progress.
    /// errors a transport [Error] when the handshake fails (the handle is spent).
    pub fn poll(&self) -> Result<bool> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        match unsafe { sys::nwep_client_connect_poll(self.raw) } {
            1 => Ok(true),
            0 => Ok(false),
            other => Err(Error::from_code(other)),
        }
    }

    /// returns the udp socket descriptor, to register with a poller NW070000.
    pub fn fd(&self) -> RawSocket {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        crate::raw::from_c(unsafe { sys::nwep_client_fd(self.raw) })
    }

    /// returns milliseconds until the next required [Connecting::tick], or none.
    pub fn next_timeout(&self, now_ms: i64) -> Option<u32> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let ms = unsafe { sys::nwep_client_next_timeout_ms(self.raw, now_ms) };
        if ms < 0 {
            None
        } else {
            Some(ms as u32)
        }
    }

    /// takes the connected [Client] once [Connecting::poll] reported ready.
    ///
    /// calling it before the handshake completes yields a client that is not yet
    /// usable for requests; poll to readiness first.
    pub fn into_client(self) -> Client {
        let raw = self.raw;
        // do not close the connection in Connecting::drop, the Client owns it now.
        core::mem::forget(self);
        Client::wrap(raw)
    }
}

impl Drop for Connecting {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_client_close(self.raw) };
    }
}

// async requests NW060000

/// RequestId is an opaque token for a submitted async request NW060000.
pub type RequestId = u64;

/// RequestHandle is a submitted, in-flight request being driven to completion NW060000.
///
/// poll it with [RequestHandle::poll] after [Client::tick] until it yields a
/// response. dropping it cancels the request. it borrows its client, so it
/// cannot outlive it.
pub struct RequestHandle<'c> {
    client: &'c Client,
    id: RequestId,
    done: bool,
}

impl RequestHandle<'_> {
    /// returns this request's id NW060000.
    pub fn id(&self) -> RequestId {
        self.id
    }

    /// checks for completion without blocking NW060000.
    ///
    /// drive [Client::tick] between polls. once it yields some response (or an
    /// error), the request is retired and further polls are meaningless.
    ///
    /// returns some [Response] when complete, or none while still in flight.
    /// errors the request's transport [Error] on failure (the request is retired).
    pub fn poll(&mut self) -> Result<Option<Response>> {
        let mut out: *mut sys::nwep_message = ptr::null_mut();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_client_request_poll(self.client.raw, self.id, &mut out) };
        match rc {
            0 => {
                self.done = true;
                Ok(Some(Response { msg: out }))
            }
            c if c == Error::WouldBlock.code() => Ok(None),
            other => {
                self.done = true;
                Err(Error::from_code(other))
            }
        }
    }

    /// cancels the request, retiring it NW060000.
    pub fn cancel(mut self) {
        self.cancel_inner();
    }

    fn cancel_inner(&mut self) {
        if !self.done {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            unsafe { sys::nwep_client_request_cancel(self.client.raw, self.id) };
            self.done = true;
        }
    }
}

impl Drop for RequestHandle<'_> {
    fn drop(&mut self) {
        // a still-in-flight request is cancelled so the client does not keep
        // driving work whose result no one will read.
        self.cancel_inner();
    }
}
