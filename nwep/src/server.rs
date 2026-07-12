//! nwep server, the listening half of a web/1 node NW070000.
//!
//! Server owns a bound udp socket, runs the quic handshake per connection, and
//! dispatches each decoded request to a handler. it is the driven layer, the
//! caller owns the loop, advancing it with [Server::tick] and waking on
//! [Server::fd] until [Server::next_timeout]. a managed runtime that owns the
//! loop is layered on top later NWG0200 NWG0600.
//!
//! the handle is single threaded and not thread safe NWG0900, which the raw
//! pointer field encodes as !Send and !Sync, so the compiler keeps it on one
//! thread for you.
//!
//! # example
//!
//! ```no_run
//! use nwep::{Address, Identity, Server};
//!
//! let server = Server::builder()
//!     .identity(Identity::generate()?)
//!     .bind(Address::loopback(443))
//!     .on_request(|req, res| match req.path() {
//!         Some("/hello") => res.ok(b"hi"),
//!         _ => res.not_found(),
//!     })
//!     .build()?;
//!
//! loop {
//!     server.tick(now_ms())?;
//!     // wait on server.fd() until server.next_timeout(now_ms()) here.
//!     # break;
//! }
//! # fn now_ms() -> i64 { 0 }
//! # Ok::<(), nwep::Error>(())
//! ```

use crate::address::Address;
use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::message::Headers;
use crate::raw::RawSocket;
use crate::wire::Status;
use core::ffi::{c_int, c_void, CStr};
use core::ptr;
use nwep_sys as sys;
use std::ffi::CString;

// request + responder NW060000

/// Request is the decoded request handed to a handler, borrowed for the call.
///
/// it exposes the request path, headers, body, and the id of the connection it
/// arrived on. the borrowed strings live only as long as the handler call, so
/// they cannot be stored past it.
pub struct Request {
    msg: *const sys::nwep_message,
    server: *mut sys::nwep_server,
    conn_id: u64,
    stream_id: u64,
}

impl Request {
    /// returns the id of the connection this request arrived on.
    ///
    /// used by sub-routers that rate-limit or dispatch per connection (the log
    /// server, NW000014).
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// returns the id of the quic stream this request arrived on.
    ///
    /// needed to begin a streamed response on the same stream NW060200.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// returns the authenticated peer node_id of this request's connection NW090000.
    ///
    /// returns the peer's [NodeId].
    /// errors [Error::IdentityNotFound] for an unknown connection.
    pub fn peer_node_id(&self) -> Result<NodeId> {
        let mut out = sys::nwep_node_id {
            bytes: [0; sys::NWEP_NODEID_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_server_get_peer_nodeid(self.server, self.conn_id, &mut out)
        })?;
        Ok(NodeId::from_bytes(out.bytes))
    }

    /// returns the codec this request's connection negotiated NW000017.
    pub fn compression(&self) -> Compression {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        match unsafe { sys::nwep_server_conn_compression(self.server, self.conn_id) } {
            0 => Compression::None,
            1 => Compression::Zstd,
            _ => Compression::Unknown,
        }
    }

    /// borrows the raw c message handle, for handing to a lower-layer router.
    pub(crate) fn raw_msg(&self) -> *const sys::nwep_message {
        self.msg
    }

    /// borrows the request path, the ":path" pseudo header NW060200.
    pub fn path(&self) -> Option<&str> {
        self.header(":path")
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

    /// borrows the request body, empty when there is none.
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

    /// iterates every request header in wire order NW060300.
    pub fn headers(&self) -> Headers<'_> {
        Headers::new(self.msg)
    }

    /// returns true when the request's if-none-match matches etag NW060700.
    ///
    /// a true result means a [Responder::not_modified] answer is correct.
    pub fn is_fresh(&self, etag: &str) -> bool {
        let Ok(c) = CString::new(etag) else {
            return false;
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_request_is_fresh(self.msg, c.as_ptr()) != 0 }
    }

    /// resolves the request's range header against a resource of total_len bytes NW060800.
    ///
    /// when etag is some and the request's if-range does not match it the range
    /// is ignored ([RangeOutcome::Full]), so a resumed transfer never mixes
    /// versions. feeds [Responder::partial] on the [RangeOutcome::Ranges] arm.
    ///
    /// returns the [RangeOutcome] to act on.
    /// errors [Error::Internal] only on a null argument, which cannot happen here.
    pub fn range(&self, total_len: u64, etag: Option<&str>) -> Result<RangeOutcome> {
        let etag_c = match etag {
            Some(e) => Some(CString::new(e).map_err(|_| Error::ProtoInvalidHeader)?),
            None => None,
        };
        let etag_ptr = etag_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let mut out = [sys::nwep_range { start: 0, end: 0 }; MAX_RANGES];
        let mut count = 0usize;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe {
            sys::nwep_request_range(
                self.msg,
                total_len,
                etag_ptr,
                out.as_mut_ptr(),
                MAX_RANGES,
                &mut count,
            )
        };
        match rc {
            sys::NWEP_RANGE_OK => Ok(RangeOutcome::Ranges(
                out[..count]
                    .iter()
                    .map(|r| ByteRange {
                        start: r.start,
                        end: r.end,
                    })
                    .collect(),
            )),
            sys::NWEP_RANGE_UNSATISFIABLE => Ok(RangeOutcome::Unsatisfiable),
            sys::NWEP_RANGE_NONE => Ok(RangeOutcome::Full),
            other => Err(Error::from_code(other)),
        }
    }
}

/// a buffer of at most this many satisfiable ranges per request NW060800.
const MAX_RANGES: usize = 16;

/// ByteRange is one inclusive byte range [start, end] of a resource NW060800.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    /// first byte offset, inclusive.
    pub start: u64,
    /// last byte offset, inclusive.
    pub end: u64,
}

/// RangeOutcome is how a request's range header resolves against a resource NW060800.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeOutcome {
    /// no range, or one ignored by if-range, serve the whole body with ok.
    Full,
    /// a valid range that selects no bytes, answer range-not-satisfiable.
    Unsatisfiable,
    /// satisfiable ranges, answer partial-content with [Responder::partial].
    Ranges(Vec<ByteRange>),
}

/// Reply is the token a [Responder] returns, proving the handler answered.
///
/// a handler must produce one by calling a Responder method, so the type system
/// enforces that every request is answered exactly once.
pub struct Reply(());

/// Responder is a handler's one shot reply, writing the response in place NW060000.
///
/// each terminal method (ok, status, ...) consumes the responder and returns a
/// [Reply], so a handler answers a request exactly once.
pub struct Responder {
    buf: *mut sys::nwep_buf,
    rc: *mut c_int,
    // server context, for beginning a streamed response on this request's stream.
    server: *mut sys::nwep_server,
    conn_id: u64,
    stream_id: u64,
}

impl Responder {
    /// answers with an ok status carrying body NW080000.
    pub fn ok(self, body: &[u8]) -> Reply {
        let (ptr, len) = slice_parts(body);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = sys::nwep_response_ok(self.buf, ptr, len) };
        Reply(())
    }

    /// answers with the given status token and body NW080000.
    pub fn status(self, status: Status, body: &[u8]) -> Reply {
        // nwep_status_str returns a static nul terminated token, exactly what
        // nwep_response_status wants, so no allocation is needed.
        // SAFETY: nwep_status_str returns a static nul-terminated string, never null.
        let token = unsafe { sys::nwep_status_str(status.code()) };
        let (ptr, len) = slice_parts(body);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = sys::nwep_response_status(self.buf, token, ptr, len) };
        Reply(())
    }

    /// answers with a not-found status and no body NW080000.
    pub fn not_found(self) -> Reply {
        self.status(Status::NotFound, b"")
    }

    /// answers with created and an optional body NW080000.
    pub fn created(self, body: &[u8]) -> Reply {
        self.status(Status::Created, body)
    }

    /// answers with accepted and an optional body NW080000.
    pub fn accepted(self, body: &[u8]) -> Reply {
        self.status(Status::Accepted, body)
    }

    /// answers with no-content and no body NW080000.
    pub fn no_content(self) -> Reply {
        self.status(Status::NoContent, b"")
    }

    /// answers with moved; sets the location header to the new web:// URI NW080000.
    pub fn moved(self, location: &str) -> Reply {
        self.header("location", location).status(Status::Moved, b"")
    }

    /// answers with bad-request and an optional body NW080000.
    pub fn bad_request(self, body: &[u8]) -> Reply {
        self.status(Status::BadRequest, body)
    }

    /// answers with unauthorized and an optional body NW080000.
    pub fn unauthorized(self, body: &[u8]) -> Reply {
        self.status(Status::Unauthorized, body)
    }

    /// answers with forbidden and an optional body NW080000.
    pub fn forbidden(self, body: &[u8]) -> Reply {
        self.status(Status::Forbidden, body)
    }

    /// answers with not-allowed  -  the method is not permitted on this resource NW080000.
    pub fn not_allowed(self) -> Reply {
        self.status(Status::NotAllowed, b"")
    }

    /// answers with conflict and an optional body NW080000.
    pub fn conflict(self, body: &[u8]) -> Reply {
        self.status(Status::Conflict, body)
    }

    /// answers with gone  -  the resource is permanently removed NW080000.
    pub fn gone(self) -> Reply {
        self.status(Status::Gone, b"")
    }

    /// answers with too-large  -  the request body exceeded the server limit NW080000.
    pub fn too_large(self) -> Reply {
        self.status(Status::TooLarge, b"")
    }

    /// answers with precondition-failed  -  a conditional header did not hold NW080000.
    pub fn precondition_failed(self) -> Reply {
        self.status(Status::PreconditionFailed, b"")
    }

    /// answers with rate-limited; retry_after is seconds until the client may retry NW080000.
    pub fn rate_limited(self, retry_after: &str) -> Reply {
        self.header("retry-after", retry_after)
            .status(Status::RateLimited, b"")
    }

    /// answers with error (internal server error) and an optional body NW080000.
    pub fn error(self, body: &[u8]) -> Reply {
        self.status(Status::Error, body)
    }

    /// answers with unavailable and no body NW080000.
    pub fn unavailable(self) -> Reply {
        self.status(Status::Unavailable, b"")
    }

    /// answers with timeout  -  the server took too long to process the request NW080000.
    pub fn timeout(self) -> Reply {
        self.status(Status::Timeout, b"")
    }

    /// answers with not-implemented  -  the method or feature is not supported NW080000.
    pub fn not_implemented(self) -> Reply {
        self.status(Status::NotImplemented, b"")
    }

    /// answers a fresh conditional read with not-modified and etag NW060700.
    pub fn not_modified(self, etag: &str) -> Reply {
        let token = CString::new(etag).unwrap_or_default();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = sys::nwep_response_not_modified(self.buf, token.as_ptr()) };
        Reply(())
    }

    /// answers with partial-content for the given byte ranges of body NW060800.
    ///
    /// body is the full resource, ranges come from [Request::range]. one range
    /// sends that sub range with a content-range header, several send a
    /// multipart body.
    pub fn partial(self, body: &[u8], ranges: &[ByteRange], content_type: &str) -> Reply {
        let raw: Vec<sys::nwep_range> = ranges
            .iter()
            .map(|r| sys::nwep_range {
                start: r.start,
                end: r.end,
            })
            .collect();
        let ctype = CString::new(content_type).unwrap_or_default();
        let (ptr, len) = slice_parts(body);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe {
            *self.rc = sys::nwep_response_partial(
                self.buf,
                ptr,
                len,
                raw.as_ptr(),
                raw.len(),
                ctype.as_ptr(),
            )
        };
        Reply(())
    }

    /// answers a well formed but out of bounds range with range-not-satisfiable NW060800.
    pub fn range_not_satisfiable(self, total_len: u64) -> Reply {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = sys::nwep_response_range_not_satisfiable(self.buf, total_len) };
        Reply(())
    }

    /// attaches a custom header to the response, before the terminal call NW060300.
    ///
    /// chain it ahead of ok, status, or partial. for example res.header("etag", tag).ok(body). the library copies name and value.
    pub fn header(self, name: &str, value: &str) -> Self {
        if let (Ok(n), Ok(v)) = (CString::new(name), CString::new(value)) {
            // best effort, a header that cannot be added (oom) surfaces when the
            // terminal call fails too.
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            unsafe { sys::nwep_response_header(self.buf, n.as_ptr(), v.as_ptr()) };
        }
        self
    }

    /// begins a streamed response, emitting the metadata frame NW060200.
    ///
    /// answers with status + headers now, then the body is sent across ticks with
    /// [Server::stream_send] and finished with [Server::stream_end], using the
    /// request's [Request::conn_id] and [Request::stream_id]. path is the request
    /// path, bound into the response signature. use it for a body larger than one
    /// message or of unknown length.
    pub fn stream(self, path: &str, status: Status, headers: &[(&str, &str)]) -> Reply {
        let cpath = CString::new(path).unwrap_or_default();
        // SAFETY: nwep_status_str returns a static nul-terminated string, never null.
        let token = unsafe { sys::nwep_status_str(status.code()) };
        let cstrings: Vec<(CString, CString)> = headers
            .iter()
            .filter_map(|(n, v)| Some((CString::new(*n).ok()?, CString::new(*v).ok()?)))
            .collect();
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
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe {
            *self.rc = sys::nwep_server_begin_stream(
                self.server,
                self.conn_id,
                self.stream_id,
                cpath.as_ptr(),
                token,
                array.as_ptr(),
            )
        };
        Reply(())
    }

    /// answers with a captured frame verbatim, no re-encode or re-sign NW000017.
    ///
    /// the frame must be one [CapturingResponder] produced for this connection's
    /// codec ([Request::compression]) and still within its signature freshness.
    /// the cache fast path, skip building an identical response twice.
    pub fn blit(self, frame: &[u8]) -> Reply {
        let (ptr, len) = slice_parts(frame);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = sys::nwep_response_blit(self.buf, ptr, len) };
        Reply(())
    }

    /// switches into capture mode, so each terminal also returns the built frame.
    ///
    /// build a response as usual on the returned [CapturingResponder]; its
    /// terminals answer the request and hand back the encoded frame bytes to
    /// cache and later [Responder::blit] NW000017.
    pub fn capturing(self) -> CapturingResponder {
        CapturingResponder(self)
    }

    /// answers by relaying an origin response verbatim, in-handler NW000017.
    ///
    /// emits origin's status, headers, and body unchanged, preserving its
    /// end-to-end signature NW060900 instead of re-signing  -  the synchronous
    /// counterpart of [DeferredResponder::relay]. for a proxy that fetched the
    /// origin response before the handler returned.
    pub fn relay(self, origin: &crate::Response) -> Reply {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = sys::nwep_response_relay(self.buf, origin.as_raw()) };
        Reply(())
    }

    /// defers the answer, to deliver it out of band later NW000017.
    ///
    /// the handler writes nothing now. the server keeps the stream open and the
    /// app answers later from its loop with [Server::respond] then a DeferredResponder terminal,
    /// using the request's [Request::conn_id] and [Request::stream_id]. use it for
    /// a response that depends on a backend fetch you do not want to block on (a
    /// proxy, a gateway). the parked stream is answered exactly once, or the
    /// client gets a generic error if the deadline elapses.
    pub fn defer(self) -> Reply {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = NWEP_DEFER };
        Reply(())
    }

    /// borrows the raw c response buffer, for a lower-layer router that writes
    /// the response itself (the log server, NW000014).
    pub(crate) fn raw_buf(&self) -> *mut sys::nwep_buf {
        self.buf
    }

    /// finalizes the response with an already-set status code, without writing
    /// the buffer (a lower-layer router wrote it). pairs with [Responder::raw_buf].
    pub(crate) fn finish(self, code: c_int) -> Reply {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *self.rc = code };
        Reply(())
    }
}

/// CapturingResponder answers a request and hands back the encoded frame NW000017.
///
/// each terminal builds the response (answering the request) and also captures
/// the encoded frame bytes, so a server can cache them and later [Responder::blit]
/// an identical response without re-encoding or re-signing it.
pub struct CapturingResponder(Responder);

impl CapturingResponder {
    /// answers ok with body and returns the captured frame NW080000 NW000017.
    pub fn ok(self, body: &[u8]) -> (Reply, Vec<u8>) {
        let (ptr, len) = slice_parts(body);
        let buf = self.0.buf;
        let rc = self.0.rc;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let build_rc = unsafe { sys::nwep_response_ok(buf, ptr, len) };
        Self::finish_capture(buf, rc, build_rc)
    }

    /// answers with status + body and returns the captured frame NW080000.
    pub fn status(self, status: Status, body: &[u8]) -> (Reply, Vec<u8>) {
        // SAFETY: nwep_status_str returns a static nul-terminated string, never null.
        let token = unsafe { sys::nwep_status_str(status.code()) };
        let (ptr, len) = slice_parts(body);
        let buf = self.0.buf;
        let rc = self.0.rc;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let build_rc = unsafe { sys::nwep_response_status(buf, token, ptr, len) };
        Self::finish_capture(buf, rc, build_rc)
    }

    /// records the build result, captures the frame, and finalizes the response.
    fn finish_capture(
        buf: *mut sys::nwep_buf,
        rc: *mut c_int,
        build_rc: c_int,
    ) -> (Reply, Vec<u8>) {
        if build_rc != 0 {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            unsafe { *rc = build_rc };
            return (Reply(()), Vec::new());
        }
        // two-call sizing, then capture the just-built frame for caching.
        let mut len = 0usize;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let frame = if unsafe { sys::nwep_response_capture(buf, ptr::null_mut(), 0, &mut len) } == 0
        {
            let mut f = vec![0u8; len];
            // SAFETY: buf is sized to len as returned by the probe call above.
            if unsafe { sys::nwep_response_capture(buf, f.as_mut_ptr(), f.len(), &mut len) } == 0 {
                f.truncate(len);
                f
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { *rc = 0 };
        (Reply(()), frame)
    }
}

/// splits a byte slice into a (ptr, len) pair, using null for an empty slice so
/// the c side never sees a dangling pointer.
fn slice_parts(b: &[u8]) -> (*const u8, usize) {
    if b.is_empty() {
        (ptr::null(), 0)
    } else {
        (b.as_ptr(), b.len())
    }
}

// handler trampoline NWG0900

// the closure is Send so the managed layer can move it to its owner thread
// NWG0600. it only ever runs on that one thread, so Send is the only bound
// the cross-thread move needs.
/// the c handler sentinel for answering a request out of band later NW000017.
const NWEP_DEFER: c_int = sys::NWEP_DEFER;

type Handler = dyn FnMut(&Request, Responder) -> Reply + Send;

/// HandlerBox owns the user closure behind a stable address, so its raw pointer
/// can ride as the c handler userdata for the life of the server.
struct HandlerBox {
    f: Box<Handler>,
}

/// the c callback. rebuilds the safe Request and Responder, runs the user
/// closure, and returns its status code. a panic is caught here and turned into
/// an error, because unwinding into c is undefined behavior NWG0900.
unsafe extern "C" fn trampoline(
    server: *mut sys::nwep_server,
    conn_id: u64,
    stream_id: u64,
    request: *const sys::nwep_message,
    resp_buf: *mut sys::nwep_buf,
    userdata: *mut c_void,
) -> c_int {
    // userdata is the HandlerBox, owned by the Server and alive for this call.
    // SAFETY: userdata is a valid HandlerBox pointer installed by set_handler, alive for this callback.
    let handler = unsafe { &mut *(userdata as *mut HandlerBox) };
    let mut rc: c_int = 0;
    let req = Request {
        msg: request,
        server,
        conn_id,
        stream_id,
    };
    let res = Responder {
        buf: resp_buf,
        rc: &mut rc,
        server,
        conn_id,
        stream_id,
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (handler.f)(&req, res);
    }));
    match outcome {
        Ok(()) => rc,
        Err(_) => Error::Internal.code(),
    }
}

// server builder NW070000 NWG0300

/// ServerBuilder configures and constructs a [Server] NWG0300.
///
/// set the identity and bind address, optionally an on_request handler, then
/// call build() for a driven server you tick yourself.
#[derive(Default)]
pub struct ServerBuilder {
    identity: Option<Identity>,
    bind: Option<Address>,
    handler: Option<Box<Handler>>,
    reuse_port: bool,
    max_parked: Option<usize>,
    // managed-dht options, consumed only by serve() (the runtime owns the loop,
    // so it can own an attached dht too). ignored by the driven build().
    pub(crate) dht_bootstraps: Vec<crate::Bootstrap>,
    pub(crate) dht_announce: Option<Address>,
    pub(crate) dht_initial_seq: u64,
}

impl ServerBuilder {
    /// sets the identity this server proves ownership of NW090000.
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// sets the address to bind, anything that converts into an [Address].
    pub fn bind(mut self, addr: impl Into<Address>) -> Self {
        self.bind = Some(addr.into());
        self
    }

    /// binds with so_reuseport so several reactors share one port NW000017.
    ///
    /// the kernel fans connections across them. only effective where
    /// [reuse_port_supported] is true; elsewhere build() errors.
    pub fn reuse_port(mut self, on: bool) -> Self {
        self.reuse_port = on;
        self
    }

    /// sets the deferred-response (parked) cap applied after binding NW000017.
    pub fn max_parked(mut self, max: usize) -> Self {
        self.max_parked = Some(max);
        self
    }

    /// attaches a managed dht with these bootstrap contacts NW110000, serve only.
    ///
    /// makes the managed runtime own a dht alongside the server, ticking it and
    /// answering the runtime's resolve(). applies only to serve()  -  for the
    /// driven path, attach a [crate::Dht] to the built [Server] yourself. at least
    /// one contact is required for the dht to join.
    pub fn dht(mut self, contacts: impl IntoIterator<Item = crate::Bootstrap>) -> Self {
        self.dht_bootstraps.extend(contacts);
        self
    }

    /// announces this address through the managed dht, re-published periodically.
    ///
    /// applies only to serve() with a [ServerBuilder::dht]. the address other
    /// nodes will dial after resolving this server's node_id NW110700.
    pub fn announce_as(mut self, addr: impl Into<Address>) -> Self {
        self.dht_announce = Some(addr.into());
        self
    }

    /// sets the managed dht's last announced sequence number to resume from NW110600.
    pub fn dht_initial_seq(mut self, seq: u64) -> Self {
        self.dht_initial_seq = seq;
        self
    }

    /// takes the managed-dht config out of the builder, leaving the build()-side
    /// fields intact. returns none when no dht was configured (the runtime calls
    /// this before consuming self into build()).
    #[cfg(feature = "runtime")]
    pub(crate) fn take_managed_dht(
        &mut self,
    ) -> Option<(Vec<crate::Bootstrap>, Option<Address>, u64)> {
        if self.dht_bootstraps.is_empty() {
            return None;
        }
        Some((
            core::mem::take(&mut self.dht_bootstraps),
            self.dht_announce.take(),
            self.dht_initial_seq,
        ))
    }

    /// sets the request handler, run synchronously inside tick NWG0900.
    ///
    /// the closure receives the request and a one shot responder and must return
    /// the responder's [Reply], so every request is answered exactly once. it
    /// must not block or call tick. a server with no handler still runs (for
    /// example a dht only node) but answers nothing.
    pub fn on_request(
        mut self,
        handler: impl FnMut(&Request, Responder) -> Reply + Send + 'static,
    ) -> Self {
        self.handler = Some(Box::new(handler));
        self
    }

    /// builds the server adopting a caller-owned udp socket NW000017.
    ///
    /// ownership of fd transfers to the server (closed on drop). the socket must
    /// be an af_inet6 udp socket, already bound. the portable multi-reactor
    /// primitive. shard_id, when some, tags every connection id this reactor
    /// issues so a steering program routes packets to it NW000017.
    ///
    /// returns the bound [Server].
    /// errors [Error::ConfigMissing] when the identity is unset, and a transport
    /// bind error.
    pub fn build_from_fd(mut self, fd: RawSocket, shard_id: Option<u16>) -> Result<Server> {
        let identity = self.identity.take().ok_or(Error::ConfigMissing)?;
        let fd = crate::raw::to_c(fd);
        let mut raw: *mut sys::nwep_server = ptr::null_mut();
        identity.with_keypair(|kp| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                match shard_id {
                    Some(s) => sys::nwep_server_listen_fd_sharded(&mut raw, kp, fd, s),
                    None => sys::nwep_server_listen_fd(&mut raw, kp, fd),
                }
            })
        })?;
        self.finish_build(raw)
    }

    /// binds the socket and returns a driven [Server] you advance with tick.
    ///
    /// the managed terminal that owns the loop is added in a later slice NWG0200.
    ///
    /// returns the bound [Server].
    /// errors [Error::ConfigMissing] when the identity or bind address is unset,
    /// and any bind error from the transport (for example a port in use).
    pub fn build(mut self) -> Result<Server> {
        let identity = self.identity.take().ok_or(Error::ConfigMissing)?;
        let bind = self.bind.take().ok_or(Error::ConfigMissing)?;

        let mut raw: *mut sys::nwep_server = ptr::null_mut();
        identity.with_keypair(|kp| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                if self.reuse_port {
                    sys::nwep_server_listen_reuseport(&mut raw, kp, bind.as_raw())
                } else {
                    sys::nwep_server_listen(&mut raw, kp, bind.as_raw())
                }
            })
        })?;
        self.finish_build(raw)
    }

    /// applies max_parked and the handler to a freshly bound server (shared by the
    /// bind and adopt-fd paths).
    fn finish_build(self, raw: *mut sys::nwep_server) -> Result<Server> {
        if let Some(max) = self.max_parked {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            unsafe { sys::nwep_server_set_max_parked(raw, max) };
        }

        let mut handler_ptr: *mut c_void = ptr::null_mut();
        if let Some(f) = self.handler {
            let boxed = Box::into_raw(Box::new(HandlerBox { f }));
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            let rc = unsafe {
                sys::nwep_server_set_handler(raw, Some(trampoline), boxed as *mut c_void)
            };
            if let Err(e) = Error::check(rc) {
                // unwind the half-built server, freeing the closure and socket.
                // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
                unsafe {
                    drop(Box::from_raw(boxed));
                    sys::nwep_server_close(raw);
                }
                return Err(e);
            }
            handler_ptr = boxed as *mut c_void;
        }

        Ok(Server {
            raw,
            handler: handler_ptr,
        })
    }
}

// server NW070000

/// Server is a bound, driven web/1 node NW070000. see the module docs.
pub struct Server {
    raw: *mut sys::nwep_server,
    // the HandlerBox raw pointer, or null. owned here, freed on drop after the
    // server is closed so no callback can still reach it.
    handler: *mut c_void,
}

impl Server {
    /// starts a [ServerBuilder].
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    /// advances every server state machine, reading datagrams, running
    /// handshakes, dispatching requests, and flushing output NW070000.
    ///
    /// call it on each wakeup of [Server::fd] and when [Server::next_timeout]
    /// expires. now_ms is a monotonic millisecond clock.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the tick fails.
    pub fn tick(&self, now_ms: i64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_server_tick(self.raw, now_ms) })
    }

    /// returns the udp socket handle, to register with a poller for readiness.
    pub fn fd(&self) -> RawSocket {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        crate::raw::from_c(unsafe { sys::nwep_server_fd(self.raw) })
    }

    /// returns milliseconds until the next required tick, or none to block on the
    /// socket alone (no timer pending). a returned zero means tick now.
    pub fn next_timeout(&self, now_ms: i64) -> Option<u32> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let ms = unsafe { sys::nwep_server_next_timeout_ms(self.raw, now_ms) };
        if ms < 0 {
            None
        } else {
            Some(ms as u32)
        }
    }

    /// returns the bound udp port, useful after binding port 0.
    pub fn local_port(&self) -> u16 {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_server_local_port(self.raw) }
    }

    /// returns this server's own node_id NW040200.
    ///
    /// returns the [NodeId].
    /// errors [Error::Internal] when the handle is unusable.
    pub fn node_id(&self) -> Result<NodeId> {
        let mut out = sys::nwep_node_id {
            bytes: [0; sys::NWEP_NODEID_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_server_local_nodeid(self.raw, &mut out) })?;
        Ok(NodeId::from_bytes(out.bytes))
    }

    /// queues body bytes on a streamed response, returning how many were accepted NW060200.
    ///
    /// pairs with [Responder::stream]. the accepted count may be fewer than the
    /// slice under back-pressure (including 0), retry the unaccepted tail after a
    /// [Server::tick]. conn_id and stream_id come from the request that began the
    /// stream.
    ///
    /// returns the number of bytes accepted.
    /// errors a transport [Error] when the send fails.
    pub fn stream_send(&self, conn_id: u64, stream_id: u64, body: &[u8]) -> Result<usize> {
        let (ptr, len) = if body.is_empty() {
            (ptr::null(), 0)
        } else {
            (body.as_ptr(), body.len())
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_server_stream_send(self.raw, conn_id, stream_id, ptr, len) };
        if rc < 0 {
            return Err(Error::from_code(rc));
        }
        Ok(rc as usize)
    }

    /// ends a streamed response, flushing the tail and writing quic fin NW060200.
    ///
    /// no further [Server::stream_send] is permitted on this stream.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the end fails.
    pub fn stream_end(&self, conn_id: u64, stream_id: u64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_server_stream_end(self.raw, conn_id, stream_id) })
    }

    /// returns the authenticated peer node_id of a connection NW090000.
    ///
    /// conn_id comes from a [Request::conn_id] on that connection.
    ///
    /// returns the peer's [NodeId].
    /// errors [Error::IdentityNotFound] for an unknown connection.
    pub fn peer_node_id(&self, conn_id: u64) -> Result<NodeId> {
        let mut out = sys::nwep_node_id {
            bytes: [0; sys::NWEP_NODEID_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_server_get_peer_nodeid(self.raw, conn_id, &mut out) })?;
        Ok(NodeId::from_bytes(out.bytes))
    }

    /// returns a snapshot of this reactor's observability counters NW000017.
    pub fn metrics(&self) -> Metrics {
        let mut m = sys::nwep_server_metrics {
            connections_active: 0,
            connections_accepted: 0,
            connections_refused: 0,
            connections_closed: 0,
            bytes_received: 0,
            bytes_sent: 0,
            datagrams_received: 0,
            datagrams_sent: 0,
            requests_dispatched: 0,
            requests_shed: 0,
            parked_active: 0,
            load: 0,
        };
        // a non null handle never errors, so the code is ignored.
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_server_metrics_get(self.raw, &mut m) };
        Metrics {
            connections_active: m.connections_active,
            connections_accepted: m.connections_accepted,
            connections_refused: m.connections_refused,
            connections_closed: m.connections_closed,
            bytes_received: m.bytes_received,
            bytes_sent: m.bytes_sent,
            datagrams_received: m.datagrams_received,
            datagrams_sent: m.datagrams_sent,
            requests_dispatched: m.requests_dispatched,
            requests_shed: m.requests_shed,
            parked_active: m.parked_active,
            load: m.load,
        }
    }

    /// returns a 0..100 load factor for an l4 router or health check NW000017.
    pub fn load(&self) -> i32 {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_server_load(self.raw) }
    }

    /// forces the reactor to shed load (or stops forcing it) NW000017.
    ///
    /// an overloaded reactor refuses new connections so a router steers elsewhere.
    pub fn set_overloaded(&self, on: bool) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_server_set_overloaded(self.raw, on as c_int) };
    }

    /// returns the codec a connection negotiated NW000017.
    ///
    /// returns the [Compression] in effect, or [Compression::Unknown] for an
    /// unknown connection.
    pub fn conn_compression(&self, conn_id: u64) -> Compression {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        match unsafe { sys::nwep_server_conn_compression(self.raw, conn_id) } {
            0 => Compression::None,
            1 => Compression::Zstd,
            _ => Compression::Unknown,
        }
    }

    /// returns why the most recent inbound handshake failed, if one did NW150200.
    ///
    /// a rejected handshake is closed silently to the peer, so this is the
    /// operator's only window into why inbound dials fail. for local diagnostics.
    ///
    /// returns some [Error] on the last fatal handshake, or none when none failed.
    pub fn last_handshake_error(&self) -> Option<Error> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_server_last_handshake_error(self.raw) };
        if rc < 0 {
            Some(Error::from_code(rc))
        } else {
            None
        }
    }

    /// begins a graceful drain, refusing new connections NW000017.
    ///
    /// existing connections finish their in-flight work; poll [Server::is_drained]
    /// for completion. keep ticking until then.
    ///
    /// returns unit on success.
    /// errors a transport [Error] when the drain cannot start.
    pub fn drain(&self) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_server_drain(self.raw) })
    }

    /// returns true once a drain has completed with no live connections left.
    pub fn is_drained(&self) -> bool {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_server_is_drained(self.raw) == 1 }
    }

    /// starts a deferred response on a parked stream NW000017.
    ///
    /// call it from your loop after a handler returned [Responder::defer], with
    /// the request's [Request::conn_id] and [Request::stream_id]. chain headers,
    /// then a terminal ([DeferredResponder::send] / [DeferredResponder::relay]).
    pub fn respond(&self, conn_id: u64, stream_id: u64) -> DeferredResponder<'_> {
        DeferredResponder {
            server: self,
            conn_id,
            stream_id,
            headers: Vec::new(),
        }
    }

    /// pushes a notify event to a connection on a fresh stream NW060200.
    ///
    /// the push flushes on the next [Server::tick]. body may be empty. the client
    /// reads it with [crate::Client::poll_notify].
    ///
    /// returns unit on success.
    /// errors [Error::IdentityNotFound] for an unknown connection.
    pub fn notify(&self, conn_id: u64, event: &str, body: &[u8]) -> Result<()> {
        let cevent = CString::new(event).map_err(|_| Error::ProtoInvalidHeader)?;
        let (ptr, len) = slice_parts(body);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_server_notify(
                self.raw,
                conn_id,
                cevent.as_ptr(),
                core::ptr::null(),
                ptr,
                len,
            )
        })
    }

    /// borrows the raw c server handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_server {
        self.raw
    }
}

// deferred responder NW000017 NWG0300

/// DeferredResponder delivers an out-of-band answer to a parked stream NW000017.
///
/// built by [Server::respond] after a handler deferred. add headers, then finish
/// with a terminal. every terminal returns [Error::AppNotFound] when the client
/// has gone (the stream is no longer parked)  -  treat that as discard, not retry.
pub struct DeferredResponder<'s> {
    server: &'s Server,
    conn_id: u64,
    stream_id: u64,
    headers: Vec<(String, String)>,
}

impl DeferredResponder<'_> {
    /// queues a header for the [DeferredResponder::send] terminal NW000017.
    ///
    /// ignored by [DeferredResponder::relay], which emits the origin's own headers.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// delivers the response, signed with the server identity NW000017 NW060900.
    ///
    /// returns unit on success.
    /// errors [Error::AppNotFound] when the stream is no longer parked.
    pub fn send(self, status: Status, body: &[u8]) -> Result<()> {
        for (name, value) in &self.headers {
            let n = CString::new(name.as_str()).map_err(|_| Error::ProtoInvalidHeader)?;
            let v = CString::new(value.as_str()).map_err(|_| Error::ProtoInvalidHeader)?;
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            Error::check(unsafe {
                sys::nwep_server_respond_header(
                    self.server.raw,
                    self.conn_id,
                    self.stream_id,
                    n.as_ptr(),
                    v.as_ptr(),
                )
            })?;
        }
        // SAFETY: nwep_status_str returns a static nul-terminated string, never null.
        let token = unsafe { sys::nwep_status_str(status.code()) };
        let (ptr, len) = slice_parts(body);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_server_respond(
                self.server.raw,
                self.conn_id,
                self.stream_id,
                token,
                ptr,
                len,
            )
        })
    }

    /// delivers an origin response verbatim, preserving its signature NW000017.
    ///
    /// emits origin's status, headers, and body unchanged, so a cache or proxy
    /// keeps the origin's end-to-end signature NW060900 instead of re-signing.
    /// queued headers are ignored.
    ///
    /// returns unit on success.
    /// errors [Error::AppNotFound] when the stream is no longer parked, and
    /// [Error::ProtoInvalidHeader] when origin carries no status.
    pub fn relay(self, origin: &crate::Response) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_server_relay(
                self.server.raw,
                self.conn_id,
                self.stream_id,
                origin.as_raw(),
            )
        })
    }

    /// delivers a captured frame verbatim onto the parked stream NW000017.
    ///
    /// the deferred counterpart of [Responder::blit]: a parked request answered
    /// from a frame cache. the frame must match the connection's codec. queued
    /// headers are ignored.
    ///
    /// returns unit on success.
    /// errors [Error::AppNotFound] when the stream is no longer parked.
    pub fn blit(self, frame: &[u8]) -> Result<()> {
        let (ptr, len) = slice_parts(frame);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_server_respond_blit(self.server.raw, self.conn_id, self.stream_id, ptr, len)
        })
    }
}

/// Metrics is a reactor's observability snapshot NW000017.
///
/// cumulative counters plus three gauges (connections_active, parked_active,
/// load). pull model, scrape it whenever.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    /// live connections right now (gauge).
    pub connections_active: u64,
    /// handshakes admitted (cumulative).
    pub connections_accepted: u64,
    /// connections dropped at the cap (cumulative).
    pub connections_refused: u64,
    /// connections torn down (cumulative).
    pub connections_closed: u64,
    /// udp payload bytes in (cumulative).
    pub bytes_received: u64,
    /// udp payload bytes out (cumulative).
    pub bytes_sent: u64,
    /// udp datagrams in (cumulative).
    pub datagrams_received: u64,
    /// udp datagrams out (cumulative).
    pub datagrams_sent: u64,
    /// requests that reached a handler (cumulative).
    pub requests_dispatched: u64,
    /// requests shed at the front door (cumulative).
    pub requests_shed: u64,
    /// deferred responses outstanding (gauge).
    pub parked_active: u64,
    /// 0..100 load factor (gauge).
    pub load: i32,
}

/// Compression is the body codec a connection negotiated NW000017.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// no compression.
    None,
    /// zstd.
    Zstd,
    /// unknown connection or codec.
    Unknown,
}

impl Drop for Server {
    fn drop(&mut self) {
        // close the server first so no callback can fire, then free the closure.
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_server_close(self.raw) };
        if !self.handler.is_null() {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            drop(unsafe { Box::from_raw(self.handler as *mut HandlerBox) });
        }
    }
}

/// returns true where this build supports so_reuseport load balancing NW000017.
///
/// query it before [ServerBuilder::reuse_port], which errors at build time on an
/// unsupported platform (linux and android only).
pub fn reuse_port_supported() -> bool {
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    unsafe { sys::nwep_reuse_port_supported() != 0 }
}

/// extracts the shard id a server stamped into a connection id, or none NW000017.
///
/// a steering program reads this to route a packet to the reactor that owns the
/// connection. none when the cid is not shard-encoded.
pub fn cid_shard_id(cid: &[u8]) -> Option<u16> {
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    let rc = unsafe { sys::nwep_cid_shard_id(cid.as_ptr(), cid.len()) };
    if rc < 0 {
        None
    } else {
        Some(rc as u16)
    }
}
