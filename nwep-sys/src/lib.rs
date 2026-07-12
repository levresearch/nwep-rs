//! nwep-sys is the raw, unsafe, layer 0 ffi to libnwep.
//!
//! every declaration here is a 1 to 1 mechanical mirror of include/nwep.h and
//! include/nwep_trust.h. it is ugly on purpose and exists only for completeness
//! and link soundness. the safe, idiomatic api lives one layer up in the nwep
//! crate, which is what you should use. tests/coverage.rs guards that the set of
//! symbols declared here never drifts from the library exports.
//!
//! the symbols are added slice by slice as the safe layer wraps them, each one
//! validated by a real round trip through the c abi (never declared blind).

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_void};

// sizes NW040200.

/// NWEP_NODEID_SIZE is the byte length of a node_id.
pub const NWEP_NODEID_SIZE: usize = 32;
/// NWEP_PUBKEY_SIZE is the byte length of an ed25519 public key.
pub const NWEP_PUBKEY_SIZE: usize = 32;
/// NWEP_PRIVKEY_SIZE is the byte length of an ed25519 private key.
pub const NWEP_PRIVKEY_SIZE: usize = 32;
/// NWEP_SIG_SIZE is the byte length of an ed25519 signature.
pub const NWEP_SIG_SIZE: usize = 64;

// plain types NW040200.

/// nwep_node_id is the 32 byte sha-256 identity of a node NW040200.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_node_id {
    pub bytes: [u8; NWEP_NODEID_SIZE],
}

/// nwep_keypair is an ed25519 public and private key pair. priv_ is secret.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_keypair {
    pub pub_: [u8; NWEP_PUBKEY_SIZE],
    pub priv_: [u8; NWEP_PRIVKEY_SIZE],
}

// identity, keys, nodeid NW040200 NW090500.

extern "C" {
    /// nwep_identity_generate fills out_id and out_kp with a fresh keypair NW040200.
    pub fn nwep_identity_generate(out_id: *mut nwep_node_id, out_kp: *mut nwep_keypair) -> c_int;

    /// nwep_nodeid_verify checks a node_id is sha-256(pubkey + "WEB/1") NW040200.
    pub fn nwep_nodeid_verify(id: *const nwep_node_id, pubkey: *const u8) -> c_int;

    /// nwep_nodeid_to_base58 encodes a node_id into out, writing the length to outlen.
    pub fn nwep_nodeid_to_base58(
        out: *mut c_char,
        outlen: *mut usize,
        id: *const nwep_node_id,
    ) -> c_int;

    /// nwep_nodeid_from_base58 decodes a base58 string of len bytes into a node_id.
    pub fn nwep_nodeid_from_base58(out: *mut nwep_node_id, s: *const c_char, len: usize) -> c_int;

    /// nwep_nodeid_from_pubkey derives a node_id from an ed25519 public key NW040200.
    pub fn nwep_nodeid_from_pubkey(out: *mut nwep_node_id, pubkey: *const u8) -> c_int;

    /// nwep_ed25519_sign writes the 64 byte signature of msg under privkey to out_sig.
    pub fn nwep_ed25519_sign(
        out_sig: *mut u8,
        msg: *const u8,
        msg_len: usize,
        privkey: *const u8,
    ) -> c_int;

    /// nwep_ed25519_verify checks a 64 byte signature over msg under pubkey.
    pub fn nwep_ed25519_verify(
        sig: *const u8,
        msg: *const u8,
        msg_len: usize,
        pubkey: *const u8,
    ) -> c_int;

    /// nwep_keypair_save_pem encodes a keypair to pkcs#8 pem in out (length in outlen).
    pub fn nwep_keypair_save_pem(
        out: *mut u8,
        outlen: *mut usize,
        kp: *const nwep_keypair,
    ) -> c_int;

    /// nwep_keypair_load_pem decodes pem bytes of len into a keypair.
    pub fn nwep_keypair_load_pem(out_kp: *mut nwep_keypair, pem: *const u8, len: usize) -> c_int;
}

// library utilities NW130000.

extern "C" {
    /// nwep_zeroize securely wipes len bytes at ptr. used on secret key material.
    pub fn nwep_zeroize(ptr: *mut c_void, len: usize);

    /// nwep_strerror returns the static, nul terminated name of an error code NW130000.
    pub fn nwep_strerror(err: c_int) -> *const c_char;

    /// nwep_version returns the static, nul terminated library version string.
    pub fn nwep_version() -> *const c_char;

    /// nwep_shamir_split splits secret into n shares (any t reconstruct), written
    /// contiguously to out as n blobs of 1+secret_len; two-call sizing NW150400.
    pub fn nwep_shamir_split(
        secret: *const u8,
        secret_len: usize,
        t: usize,
        n: usize,
        out: *mut u8,
        outlen: *mut usize,
    ) -> c_int;

    /// nwep_shamir_combine reconstructs a secret from n_shares contiguous shares
    /// of share_len bytes each, writing share_len-1 bytes to out_secret NW150400.
    pub fn nwep_shamir_combine(
        shares: *const u8,
        n_shares: usize,
        share_len: usize,
        out_secret: *mut u8,
        out_secret_len: *mut usize,
    ) -> c_int;
}

// address NW110300.

/// nwep_address is an opaque ipv6 socket address (a sockaddr_in6). never read its
/// bytes directly, web/1 is ipv6 only.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_address {
    pub opaque: [u8; 32],
}

extern "C" {
    /// nwep_address_loopback writes the ::1 loopback at port into out.
    pub fn nwep_address_loopback(out: *mut nwep_address, port: u16);

    /// nwep_address_wildcard writes the :: wildcard (all interfaces) at port into out.
    pub fn nwep_address_wildcard(out: *mut nwep_address, port: u16);

    /// nwep_address_ipv4_mapped writes the ::ffff:a.b.c.d mapped address at port into out.
    pub fn nwep_address_ipv4_mapped(out: *mut nwep_address, a: u8, b: u8, c: u8, d: u8, port: u16);

    /// nwep_address_from_bytes writes a 16 byte ipv6 address (network order) at port into out.
    pub fn nwep_address_from_bytes(out: *mut nwep_address, addr: *const u8, port: u16);

    /// nwep_address_get_port returns the host order port of an address.
    pub fn nwep_address_get_port(addr: *const nwep_address) -> u16;
}

// uri NW040400.

/// nwep_uri is a parsed web:// uri. path borrows the parse input, valid only
/// while that input is alive.
#[repr(C)]
pub struct nwep_uri {
    pub node_id: nwep_node_id,
    pub port: u16,
    pub path: *const c_char,
    pub path_len: usize,
}

extern "C" {
    /// nwep_uri_parse parses a the web://nodeid:port/path form (the port optional) uri of len bytes into out.
    pub fn nwep_uri_parse(out: *mut nwep_uri, input: *const c_char, len: usize) -> c_int;
}

// method / status tokens NW050000 NW080000.

extern "C" {
    /// nwep_method_str returns the static lowercase token of a method index, or null.
    pub fn nwep_method_str(method: c_int) -> *const c_char;

    /// nwep_status_str returns the static lowercase token of a status index, or null.
    pub fn nwep_status_str(status: c_int) -> *const c_char;
}

// opaque handles + handler types NW060000.

/// nwep_server is an opaque listening node handle.
pub enum nwep_server {}
/// nwep_client is an opaque outbound connection handle.
pub enum nwep_client {}
/// nwep_message is an opaque decoded request or response.
pub enum nwep_message {}

/// nwep_buf is a handler's response output buffer (an internal Buf pointer).
#[repr(C)]
pub struct nwep_buf {
    pub opaque: *mut c_void,
}

/// nwep_header is one request header, a name and value pair. a null name ends a
/// header array.
#[repr(C)]
pub struct nwep_header {
    pub name: *const c_char,
    pub value: *const c_char,
}

/// nwep_handler_fn is the request dispatch callback. it appends a response to
/// resp_buf and returns 0, a negative error, or NWEP_DEFER. called synchronously
/// inside nwep_server_tick on the ticking thread.
pub type nwep_handler_fn = unsafe extern "C" fn(
    server: *mut nwep_server,
    conn_id: u64,
    stream_id: u64,
    request: *const nwep_message,
    resp_buf: *mut nwep_buf,
    userdata: *mut c_void,
) -> c_int;

/// NWEP_DEFER is the handler return sentinel for answering a request out of band.
pub const NWEP_DEFER: c_int = 1;

// server NW070000.

extern "C" {
    /// nwep_server_listen binds a udp socket and allocates a server into out NW070000.
    pub fn nwep_server_listen(
        out: *mut *mut nwep_server,
        identity: *const nwep_keypair,
        bind_addr: *const nwep_address,
    ) -> c_int;

    /// nwep_server_set_handler registers the dispatch handler and its userdata.
    pub fn nwep_server_set_handler(
        server: *mut nwep_server,
        handler: Option<nwep_handler_fn>,
        userdata: *mut c_void,
    ) -> c_int;

    /// nwep_server_tick advances all server state machines at the monotonic now_ms.
    pub fn nwep_server_tick(server: *mut nwep_server, now_ms: i64) -> c_int;

    /// nwep_server_fd returns the udp socket descriptor to add to a poller.
    pub fn nwep_server_fd(server: *const nwep_server) -> isize;

    /// nwep_server_next_timeout_ms returns ms until the next required tick.
    pub fn nwep_server_next_timeout_ms(server: *mut nwep_server, now_ms: i64) -> c_int;

    /// nwep_server_local_port returns the bound udp port.
    pub fn nwep_server_local_port(server: *const nwep_server) -> u16;

    /// nwep_server_local_nodeid writes the server's own node_id into out.
    pub fn nwep_server_local_nodeid(server: *const nwep_server, out: *mut nwep_node_id) -> c_int;

    /// nwep_server_close frees the server and its socket.
    pub fn nwep_server_close(server: *mut nwep_server);

    /// nwep_server_listen_fd binds a server adopting a caller-owned udp socket NW000017.
    pub fn nwep_server_listen_fd(
        out: *mut *mut nwep_server,
        identity: *const nwep_keypair,
        fd: usize,
    ) -> c_int;

    /// nwep_server_listen_fd_sharded adopts a socket and tags the reactor with a
    /// shard id for cid steering NW000017.
    pub fn nwep_server_listen_fd_sharded(
        out: *mut *mut nwep_server,
        identity: *const nwep_keypair,
        fd: usize,
        shard_id: u16,
    ) -> c_int;

    /// nwep_server_begin_stream emits the metadata frame and enters stream mode NW060200.
    pub fn nwep_server_begin_stream(
        server: *mut nwep_server,
        conn_id: u64,
        stream_id: u64,
        path: *const c_char,
        status: *const c_char,
        headers: *const nwep_header,
    ) -> c_int;

    /// nwep_server_stream_send queues body bytes, returning how many were accepted
    /// (may be fewer under back-pressure) or a negative error NW060200.
    pub fn nwep_server_stream_send(
        server: *mut nwep_server,
        conn_id: u64,
        stream_id: u64,
        body: *const u8,
        body_len: usize,
    ) -> c_int;

    /// nwep_server_stream_end flushes remaining frames and writes quic fin NW060200.
    pub fn nwep_server_stream_end(server: *mut nwep_server, conn_id: u64, stream_id: u64) -> c_int;
}

/// nwep_server_metrics is one reactor's observability snapshot NW000017.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_server_metrics {
    pub connections_active: u64,
    pub connections_accepted: u64,
    pub connections_refused: u64,
    pub connections_closed: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub datagrams_received: u64,
    pub datagrams_sent: u64,
    pub requests_dispatched: u64,
    pub requests_shed: u64,
    pub parked_active: u64,
    pub load: i32,
}

/// NWEP_SERVER_CID_LEN is the byte length of a server connection id.
pub const NWEP_SERVER_CID_LEN: usize = 18;

extern "C" {
    /// nwep_server_listen_reuseport binds with so_reuseport for kernel load
    /// balancing, config-invalid where unsupported NW000017.
    pub fn nwep_server_listen_reuseport(
        out: *mut *mut nwep_server,
        identity: *const nwep_keypair,
        bind_addr: *const nwep_address,
    ) -> c_int;

    /// nwep_reuse_port_supported returns nonzero where so_reuseport works.
    pub fn nwep_reuse_port_supported() -> c_int;

    /// nwep_server_get_peer_nodeid writes a connection's authenticated peer
    /// node_id into out_node_id NW090000.
    pub fn nwep_server_get_peer_nodeid(
        server: *const nwep_server,
        conn_id: u64,
        out_node_id: *mut nwep_node_id,
    ) -> c_int;

    /// nwep_server_metrics_get fills out with the reactor's counter snapshot.
    pub fn nwep_server_metrics_get(
        server: *const nwep_server,
        out: *mut nwep_server_metrics,
    ) -> c_int;

    /// nwep_server_load returns a 0..100 reactor load factor NW000017.
    pub fn nwep_server_load(server: *const nwep_server) -> c_int;

    /// nwep_server_set_overloaded forces the reactor to shed load when on != 0.
    pub fn nwep_server_set_overloaded(server: *mut nwep_server, on: c_int);

    /// nwep_server_set_max_parked tunes the deferred-response cap NW000017.
    pub fn nwep_server_set_max_parked(server: *mut nwep_server, max_parked: usize);

    /// nwep_server_conn_compression returns a connection's codec, 0 none, 1 zstd,
    /// -1 unknown NW000017.
    pub fn nwep_server_conn_compression(server: *const nwep_server, conn_id: u64) -> c_int;

    /// nwep_server_last_handshake_error returns the last fatal handshake reason,
    /// or 0 if none NW150200.
    pub fn nwep_server_last_handshake_error(server: *const nwep_server) -> c_int;

    /// nwep_server_drain begins a graceful drain, refusing new connections NW000017.
    pub fn nwep_server_drain(server: *mut nwep_server) -> c_int;

    /// nwep_server_is_drained returns 1 once a drain completed with no live work.
    pub fn nwep_server_is_drained(server: *const nwep_server) -> c_int;

    /// nwep_cid_shard_id extracts the shard a server stamped into a cid, or -1 NW000017.
    pub fn nwep_cid_shard_id(cid: *const u8, cid_len: usize) -> c_int;

    /// nwep_server_notify pushes a notify event to a connection on a fresh
    /// server-initiated stream NW060200.
    pub fn nwep_server_notify(
        server: *mut nwep_server,
        conn_id: u64,
        event: *const c_char,
        headers: *const nwep_header,
        body: *const u8,
        body_len: usize,
    ) -> c_int;

    /// nwep_server_respond_header attaches a header to the next deferred respond
    /// on a parked stream NW000017.
    pub fn nwep_server_respond_header(
        server: *mut nwep_server,
        conn_id: u64,
        stream_id: u64,
        name: *const c_char,
        value: *const c_char,
    ) -> c_int;

    /// nwep_server_respond delivers a deferred response, signed with the server
    /// identity over the request path NW000017 NW060900.
    pub fn nwep_server_respond(
        server: *mut nwep_server,
        conn_id: u64,
        stream_id: u64,
        status: *const c_char,
        body: *const u8,
        body_len: usize,
    ) -> c_int;

    /// nwep_server_relay delivers an existing signed message verbatim onto a
    /// parked stream, preserving the origin's signature NW000017.
    pub fn nwep_server_relay(
        server: *mut nwep_server,
        conn_id: u64,
        stream_id: u64,
        origin_resp: *const nwep_message,
    ) -> c_int;

    /// nwep_server_respond_blit writes a captured frame onto a parked stream, the
    /// deferred counterpart of nwep_response_blit NW000017.
    pub fn nwep_server_respond_blit(
        server: *mut nwep_server,
        conn_id: u64,
        stream_id: u64,
        frame: *const u8,
        len: usize,
    ) -> c_int;
}

// response builders NW060000.

/// nwep_range is one inclusive byte range [start, end] NW060800.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_range {
    pub start: u64,
    pub end: u64,
}

/// NWEP_RANGE_OK means the request carried satisfiable ranges NW060800.
pub const NWEP_RANGE_OK: c_int = 0;
/// NWEP_RANGE_NONE means no or ignored range, serve the full body NW060800.
pub const NWEP_RANGE_NONE: c_int = 1;
/// NWEP_RANGE_UNSATISFIABLE means a valid but out of bounds range NW060800.
pub const NWEP_RANGE_UNSATISFIABLE: c_int = 2;

extern "C" {
    /// nwep_response_ok writes an ok response carrying body into resp NW080000.
    pub fn nwep_response_ok(resp: *mut nwep_buf, body: *const u8, body_len: usize) -> c_int;

    /// nwep_response_status writes a response with the given status token and body.
    pub fn nwep_response_status(
        resp: *mut nwep_buf,
        status: *const c_char,
        body: *const u8,
        body_len: usize,
    ) -> c_int;

    /// nwep_response_not_modified writes a not-modified response with etag NW060700.
    pub fn nwep_response_not_modified(resp: *mut nwep_buf, etag: *const c_char) -> c_int;

    /// nwep_response_partial writes a partial-content response for ranges of body NW060800.
    pub fn nwep_response_partial(
        resp: *mut nwep_buf,
        body: *const u8,
        body_len: usize,
        ranges: *const nwep_range,
        count: usize,
        content_type: *const c_char,
    ) -> c_int;

    /// nwep_response_range_not_satisfiable writes a range-not-satisfiable response NW060800.
    pub fn nwep_response_range_not_satisfiable(resp: *mut nwep_buf, total_len: u64) -> c_int;

    /// nwep_response_header attaches a custom header to the next response on resp.
    pub fn nwep_response_header(
        resp: *mut nwep_buf,
        name: *const c_char,
        value: *const c_char,
    ) -> c_int;

    /// nwep_response_verify checks a signed response against a pubkey for path NW060900.
    pub fn nwep_response_verify(
        resp: *const nwep_message,
        pubkey: *const u8,
        path: *const c_char,
        now_secs: u64,
    ) -> c_int;

    /// nwep_response_capture copies the just-built frame out of resp for caching,
    /// two-call sizing via out == null NW000017.
    pub fn nwep_response_capture(
        resp: *mut nwep_buf,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> c_int;

    /// nwep_response_blit writes a captured frame verbatim as the response, no
    /// re-encode or re-sign NW000017.
    pub fn nwep_response_blit(resp: *mut nwep_buf, frame: *const u8, len: usize) -> c_int;

    /// nwep_response_relay emits an origin message verbatim into resp in-handler,
    /// preserving its signature NW000017.
    pub fn nwep_response_relay(resp: *mut nwep_buf, origin: *const nwep_message) -> c_int;
}

// shared signed cache NW060700 NW060900.

/// nwep_cache is an opaque store of public, signed responses NW060700.
pub enum nwep_cache {}

extern "C" {
    /// nwep_cache_create makes a cache bounded by bytes and entries, null on oom.
    pub fn nwep_cache_create(max_bytes: usize, max_entries: usize) -> *mut nwep_cache;

    /// nwep_cache_free frees a cache (detach from any client first).
    pub fn nwep_cache_free(cache: *mut nwep_cache);

    /// nwep_cache_put_signed verifies a public signed response and stores it NW060900.
    pub fn nwep_cache_put_signed(
        cache: *mut nwep_cache,
        method: *const c_char,
        path: *const c_char,
        resp: *const nwep_message,
        origin_pubkey: *const u8,
        now_secs: u64,
    ) -> c_int;

    /// nwep_cache_get_signed serves a stored response into out, 0 hit NW060900.
    pub fn nwep_cache_get_signed(
        cache: *mut nwep_cache,
        method: *const c_char,
        path: *const c_char,
        origin_pubkey: *const u8,
        now_secs: u64,
        out: *mut *mut nwep_message,
    ) -> c_int;

    /// nwep_cache_clear drops all stored entries, the cache stays usable.
    pub fn nwep_cache_clear(cache: *mut nwep_cache);

    /// nwep_cache_stats copies the hit/miss/store/eviction counters out (any may be null).
    pub fn nwep_cache_stats(
        cache: *const nwep_cache,
        out_hits: *mut u64,
        out_misses: *mut u64,
        out_stores: *mut u64,
        out_evictions: *mut u64,
    );
}

// client NW070000.

/// nwep_client_metrics is one client's observability snapshot NW000017.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_client_metrics {
    pub requests_inflight: u64,
    pub requests_completed: u64,
    pub requests_failed: u64,
    pub smoothed_rtt_us: u64,
    pub alive: i32,
}

extern "C" {
    /// nwep_client_connect opens a blocking connection to target_addr into out NW070000.
    pub fn nwep_client_connect(
        out: *mut *mut nwep_client,
        identity: *const nwep_keypair,
        target_node_id: *const nwep_node_id,
        target_addr: *const nwep_address,
    ) -> c_int;

    /// nwep_client_send sends one request and blocks for the response into out_response.
    pub fn nwep_client_send(
        client: *mut nwep_client,
        method: c_int,
        path: *const c_char,
        headers: *const nwep_header,
        body: *const u8,
        body_len: usize,
        out_response: *mut *mut nwep_message,
    ) -> c_int;

    /// nwep_client_close frees the client and its connection.
    pub fn nwep_client_close(client: *mut nwep_client);

    /// nwep_client_connect_async starts a non-blocking connect, returning a
    /// handshaking client into out NW070000.
    pub fn nwep_client_connect_async(
        out: *mut *mut nwep_client,
        identity: *const nwep_keypair,
        target_node_id: *const nwep_node_id,
        target_addr: *const nwep_address,
    ) -> c_int;

    /// nwep_client_connect_fd opens a blocking connection adopting fd into out NW070000.
    pub fn nwep_client_connect_fd(
        out: *mut *mut nwep_client,
        identity: *const nwep_keypair,
        target_node_id: *const nwep_node_id,
        target_addr: *const nwep_address,
        fd: usize,
    ) -> c_int;

    /// nwep_client_connect_fd_async starts a non-blocking connect adopting fd NW070000.
    pub fn nwep_client_connect_fd_async(
        out: *mut *mut nwep_client,
        identity: *const nwep_keypair,
        target_node_id: *const nwep_node_id,
        target_addr: *const nwep_address,
        fd: usize,
    ) -> c_int;

    /// nwep_client_connect_poll polls an async connect, 1 complete, 0 handshaking,
    /// negative failed NW070000.
    pub fn nwep_client_connect_poll(client: *mut nwep_client) -> c_int;

    /// nwep_client_request_submit submits a request without blocking, writing the
    /// request id to out_id NW060000.
    pub fn nwep_client_request_submit(
        client: *mut nwep_client,
        method: c_int,
        path: *const c_char,
        headers: *const nwep_header,
        body: *const u8,
        body_len: usize,
        out_id: *mut u64,
    ) -> c_int;

    /// nwep_client_request_poll checks a submitted request, 0 done (out filled),
    /// would-block pending, negative failed NW060000.
    pub fn nwep_client_request_poll(
        client: *mut nwep_client,
        id: u64,
        out_response: *mut *mut nwep_message,
    ) -> c_int;

    /// nwep_client_request_cancel retires a submitted request.
    pub fn nwep_client_request_cancel(client: *mut nwep_client, id: u64);

    /// nwep_client_fd returns the udp socket descriptor for a poller.
    pub fn nwep_client_fd(client: *const nwep_client) -> isize;

    /// nwep_client_tick advances client state at the monotonic now_ms.
    pub fn nwep_client_tick(client: *mut nwep_client, now_ms: i64) -> c_int;

    /// nwep_client_next_timeout_ms returns ms until the next required tick, -1 none.
    pub fn nwep_client_next_timeout_ms(client: *mut nwep_client, now_ms: i64) -> c_int;

    /// nwep_client_is_alive returns 1 usable, 0 closed, -1 null handle.
    pub fn nwep_client_is_alive(client: *const nwep_client) -> c_int;

    /// nwep_client_compression returns the connection codec, 0 none, 1 zstd, -1 down.
    pub fn nwep_client_compression(client: *const nwep_client) -> c_int;

    /// nwep_client_peer_pubkey writes the connected server's ed25519 pubkey to out.
    pub fn nwep_client_peer_pubkey(client: *const nwep_client, out_pubkey: *mut u8) -> c_int;

    /// nwep_client_metrics_get fills out with the client's counter snapshot.
    pub fn nwep_client_metrics_get(
        client: *const nwep_client,
        out: *mut nwep_client_metrics,
    ) -> c_int;

    /// nwep_client_open_stream opens a stream and sends a body-less request,
    /// writing the stream id to out_stream_id NW060200.
    pub fn nwep_client_open_stream(
        client: *mut nwep_client,
        method: c_int,
        path: *const c_char,
        headers: *const nwep_header,
        out_stream_id: *mut u64,
    ) -> c_int;

    /// nwep_client_stream_response reads the leading metadata frame into out_response NW060200.
    pub fn nwep_client_stream_response(
        client: *mut nwep_client,
        stream_id: u64,
        out_response: *mut *mut nwep_message,
    ) -> c_int;

    /// nwep_client_stream_recv reads the next body chunk, writing the byte count to
    /// out_len and 1/0 to out_ended NW060200.
    pub fn nwep_client_stream_recv(
        client: *mut nwep_client,
        stream_id: u64,
        out_buf: *mut u8,
        cap: usize,
        out_len: *mut usize,
        out_ended: *mut c_int,
    ) -> c_int;

    /// nwep_client_stream_verify verifies a fully-received stream's signature NW060900.
    pub fn nwep_client_stream_verify(
        client: *mut nwep_client,
        stream_id: u64,
        pubkey: *const u8,
    ) -> c_int;

    /// nwep_client_stream_close releases a stream's bookkeeping.
    pub fn nwep_client_stream_close(client: *mut nwep_client, stream_id: u64);

    /// nwep_client_poll_notify pumps the connection and returns the next queued
    /// notify push, or null if none NW060200. caller frees the message.
    pub fn nwep_client_poll_notify(client: *mut nwep_client) -> *mut nwep_message;

    /// nwep_client_verify_response checks a response's signature against the
    /// connection's authenticated peer for path NW060900.
    pub fn nwep_client_verify_response(
        client: *const nwep_client,
        resp: *const nwep_message,
        path: *const c_char,
        now_secs: u64,
    ) -> c_int;

    /// nwep_client_set_cache attaches a borrowed cache (must outlive the client),
    /// or detaches with null NW060700.
    pub fn nwep_client_set_cache(client: *mut nwep_client, cache: *mut nwep_cache) -> c_int;

    /// nwep_client_set_request_done registers (or clears with null) the request
    /// completion callback, fired inside tick NW060000.
    pub fn nwep_client_set_request_done(
        client: *mut nwep_client,
        cb: Option<nwep_request_done_fn>,
        ud: *mut c_void,
    ) -> c_int;
}

/// nwep_request_done_fn is the async request completion callback. status is 0
/// (resp owns a message the callback must free) or a negative error (resp null).
pub type nwep_request_done_fn = unsafe extern "C" fn(
    client: *mut nwep_client,
    id: u64,
    status: c_int,
    resp: *mut nwep_message,
    ud: *mut c_void,
);

// message accessors NW060000.

extern "C" {
    /// nwep_message_get_status returns the response status token, or null on a request.
    pub fn nwep_message_get_status(msg: *const nwep_message) -> *const c_char;

    /// nwep_message_get_header returns the value of header name, or null if absent.
    pub fn nwep_message_get_header(msg: *const nwep_message, name: *const c_char) -> *const c_char;

    /// nwep_message_get_body returns the body pointer and writes its length to out_len.
    pub fn nwep_message_get_body(msg: *const nwep_message, out_len: *mut usize) -> *const u8;

    /// nwep_message_header_count returns how many headers the message carries.
    pub fn nwep_message_header_count(msg: *const nwep_message) -> usize;

    /// nwep_message_header_at borrows the i-th header's name and value, in wire order.
    pub fn nwep_message_header_at(
        msg: *const nwep_message,
        i: usize,
        name: *mut *const c_char,
        value: *mut *const c_char,
    ) -> c_int;

    /// nwep_message_free frees a decoded message and everything borrowed from it.
    pub fn nwep_message_free(msg: *mut nwep_message);

    /// nwep_request_is_fresh returns nonzero when the request's if-none-match
    /// matches etag, so a not-modified answer is correct NW060700.
    pub fn nwep_request_is_fresh(req: *const nwep_message, etag: *const c_char) -> c_int;

    /// nwep_request_range parses the request's range header against total_len,
    /// writing satisfiable ranges into out, returning a NWEP_RANGE_* code NW060800.
    pub fn nwep_request_range(
        req: *const nwep_message,
        total_len: u64,
        etag: *const c_char,
        out: *mut nwep_range,
        max_out: usize,
        out_count: *mut usize,
    ) -> c_int;
}

// dht NW110000.

/// nwep_dht is an opaque discovery node handle, attached to a server's socket.
pub enum nwep_dht {}

/// nwep_bootstrap_entry is a known peer to contact at startup, a node_id at an
/// address. all plain bytes, no pointers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_bootstrap_entry {
    pub node_id: nwep_node_id,
    pub addr: nwep_address,
}

/// nwep_dht_record is a resolved discovery record binding a node to an address
/// NW110300.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_dht_record {
    pub node_id: nwep_node_id,
    pub addr: nwep_address,
    pub pubkey: [u8; NWEP_PUBKEY_SIZE],
    pub seq: u64,
    pub timestamp: u64,
}

/// nwep_dht_metrics is a snapshot of dht traffic counters.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_dht_metrics {
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

extern "C" {
    /// nwep_dht_parse_bootstrap parses a the node_id@host:port text form (host bracketed for ipv6) entry NW110900.
    pub fn nwep_dht_parse_bootstrap(
        out: *mut nwep_bootstrap_entry,
        input: *const c_char,
        len: usize,
    ) -> c_int;

    /// nwep_dht_attach binds a dht to a server, reusing its socket, into out NW110900.
    pub fn nwep_dht_attach(
        out: *mut *mut nwep_dht,
        server: *mut nwep_server,
        bootstrap_nodes: *const nwep_bootstrap_entry,
        bootstrap_count: usize,
        initial_seq: u64,
    ) -> c_int;

    /// nwep_dht_bootstrap pings every bootstrap peer to join the network NW110900.
    pub fn nwep_dht_bootstrap(dht: *mut nwep_dht, now_secs: u64) -> c_int;

    /// nwep_dht_announce publishes a signed record binding this node to service_addr.
    pub fn nwep_dht_announce(
        dht: *mut nwep_dht,
        service_addr: *const nwep_address,
        now_secs: u64,
    ) -> c_int;

    /// nwep_dht_start_lookup begins an iterative find_value for target_node_id NW110800.
    pub fn nwep_dht_start_lookup(
        dht: *mut nwep_dht,
        target_node_id: *const nwep_node_id,
        now_secs: u64,
    ) -> c_int;

    /// nwep_dht_lookup_result reads a resolved record into out_record, 0 hit or -601 miss.
    pub fn nwep_dht_lookup_result(
        dht: *const nwep_dht,
        target_node_id: *const nwep_node_id,
        out_record: *mut nwep_dht_record,
    ) -> c_int;

    /// nwep_dht_tick advances dht timers at the unix-seconds clock now_secs.
    pub fn nwep_dht_tick(dht: *mut nwep_dht, now_secs: u64) -> c_int;

    /// nwep_dht_next_timeout_ms returns ms until the next dht timer, or -1 for none.
    pub fn nwep_dht_next_timeout_ms(dht: *const nwep_dht, now_secs: u64) -> c_int;

    /// nwep_dht_metrics_get reads the dht traffic snapshot into out.
    pub fn nwep_dht_metrics_get(dht: *const nwep_dht, out: *mut nwep_dht_metrics) -> c_int;

    /// nwep_dht_close detaches and frees the dht, leaving the server's socket open.
    pub fn nwep_dht_close(dht: *mut nwep_dht);
}

// client connect by node_id NW110800.

extern "C" {
    /// nwep_client_connect_by_nodeid resolves target_node_id through the dht and
    /// connects, blocking up to lookup_timeout_ms NW110800.
    pub fn nwep_client_connect_by_nodeid(
        out: *mut *mut nwep_client,
        identity: *const nwep_keypair,
        target_node_id: *const nwep_node_id,
        dht: *mut nwep_dht,
        lookup_timeout_ms: u32,
    ) -> c_int;
}

// trust-log entries + merkle log NW120200 NW120300, core, ed25519 only.

/// nwep_log is an opaque in-memory merkle log NW120200.
pub enum nwep_log {}

/// NWEP_ENTRY_KEY_BINDING is the key-binding entry type code NW120300.
pub const NWEP_ENTRY_KEY_BINDING: c_int = 1;
/// NWEP_ENTRY_KEY_ROTATION is the key-rotation entry type code NW120300.
pub const NWEP_ENTRY_KEY_ROTATION: c_int = 2;
/// NWEP_ENTRY_REVOCATION is the revocation entry type code NW120300.
pub const NWEP_ENTRY_REVOCATION: c_int = 3;
/// NWEP_ENTRY_ANCHOR_CHANGE is the anchor-change entry type code NW120300.
pub const NWEP_ENTRY_ANCHOR_CHANGE: c_int = 4;

/// nwep_keybinding is a decoded key-binding entry view NW120300.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_keybinding {
    pub node_id: [u8; NWEP_NODEID_SIZE],
    pub pubkey: [u8; NWEP_PUBKEY_SIZE],
    pub recovery_commitment: [u8; 32],
    pub timestamp: u64,
    pub signature: [u8; 64],
}

/// nwep_keyrotation is a decoded key-rotation entry view NW120300.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_keyrotation {
    pub node_id: [u8; NWEP_NODEID_SIZE],
    pub old_pubkey: [u8; NWEP_PUBKEY_SIZE],
    pub new_pubkey: [u8; NWEP_PUBKEY_SIZE],
    pub timestamp: u64,
    pub overlap_expiry: u64,
    pub sig_old: [u8; 64],
    pub sig_new: [u8; 64],
}

/// nwep_revocation is a decoded revocation entry view NW120300.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct nwep_revocation {
    pub node_id: [u8; NWEP_NODEID_SIZE],
    pub revoked_pubkey: [u8; NWEP_PUBKEY_SIZE],
    pub recovery_pubkey: [u8; NWEP_PUBKEY_SIZE],
    pub reason: u8,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

extern "C" {
    /// nwep_log_entry_type returns an entry's NWEP_ENTRY_* type code NW120300.
    pub fn nwep_log_entry_type(bytes: *const u8, len: usize) -> c_int;

    /// nwep_keybinding_create builds a signed key-binding entry, two-call sizing NW120300.
    pub fn nwep_keybinding_create(
        pubkey: *const u8,
        recovery_commitment: *const u8,
        timestamp: u64,
        privkey: *const u8,
        out: *mut u8,
        outlen: *mut usize,
    ) -> c_int;

    /// nwep_keybinding_decode parses a key-binding entry into out NW120300.
    pub fn nwep_keybinding_decode(bytes: *const u8, len: usize, out: *mut nwep_keybinding)
        -> c_int;

    /// nwep_keyrotation_create builds a signed key-rotation entry, two-call sizing NW120300.
    pub fn nwep_keyrotation_create(
        node_id: *const u8,
        old_pubkey: *const u8,
        new_pubkey: *const u8,
        timestamp: u64,
        overlap_expiry: u64,
        old_privkey: *const u8,
        new_privkey: *const u8,
        out: *mut u8,
        outlen: *mut usize,
    ) -> c_int;

    /// nwep_keyrotation_decode parses a key-rotation entry into out NW120300.
    pub fn nwep_keyrotation_decode(
        bytes: *const u8,
        len: usize,
        out: *mut nwep_keyrotation,
    ) -> c_int;

    /// nwep_revocation_create builds a signed revocation entry, two-call sizing NW120300.
    pub fn nwep_revocation_create(
        node_id: *const u8,
        revoked_pubkey: *const u8,
        recovery_pubkey: *const u8,
        reason: u8,
        timestamp: u64,
        recovery_privkey: *const u8,
        out: *mut u8,
        outlen: *mut usize,
    ) -> c_int;

    /// nwep_revocation_decode parses a revocation entry into out NW120300.
    pub fn nwep_revocation_decode(bytes: *const u8, len: usize, out: *mut nwep_revocation)
        -> c_int;

    /// nwep_log_create makes an empty in-memory merkle log, null on failure NW120200.
    pub fn nwep_log_create() -> *mut nwep_log;

    /// nwep_log_free frees a log.
    pub fn nwep_log_free(log: *mut nwep_log);

    /// nwep_log_append appends a raw entry as a leaf, returning its index NW120200.
    pub fn nwep_log_append(log: *mut nwep_log, bytes: *const u8, len: usize) -> i64;

    /// nwep_log_size returns how many entries the log holds.
    pub fn nwep_log_size(log: *const nwep_log) -> u64;

    /// nwep_log_root writes the log's 32-byte merkle root into out_root NW120200.
    pub fn nwep_log_root(log: *const nwep_log, out_root: *mut u8) -> c_int;
}

/// nwep_log_server is an opaque log server that routes /log/* endpoints NW120000 NW000014.
pub enum nwep_log_server {}

/// nwep_log_append_fn is the accepted-entry persistence hook, fired per entry the
/// server accepts via write /log/entry. entry is borrowed for the call only.
pub type nwep_log_append_fn =
    unsafe extern "C" fn(ctx: *mut c_void, entry: *const u8, len: usize, index: u64);

extern "C" {
    /// nwep_log_server_create makes a log server signing with identity over log,
    /// null on failure. log is borrowed and must outlive the server NW000014.
    pub fn nwep_log_server_create(
        identity: *const nwep_keypair,
        log: *mut nwep_log,
    ) -> *mut nwep_log_server;

    /// nwep_log_server_free frees a log server.
    pub fn nwep_log_server_free(ls: *mut nwep_log_server);

    /// nwep_log_server_set_on_append registers (or with cb null clears) the
    /// accepted-entry persistence hook.
    pub fn nwep_log_server_set_on_append(
        ls: *mut nwep_log_server,
        cb: Option<nwep_log_append_fn>,
        ctx: *mut c_void,
    );

    /// nwep_log_server_dispatch routes a request through the /log/* handlers,
    /// 0 handled, 1 not a log route, negative on error NW000014.
    pub fn nwep_log_server_dispatch(
        ls: *mut nwep_log_server,
        conn_id: u64,
        req: *const nwep_message,
        resp: *mut nwep_buf,
        now_secs: i64,
    ) -> c_int;
}

// trust layer NW120000, the `trust` feature, links libnwep with blst.
//
// these symbols live only in the full libnwep build, so they are gated behind
// the trust feature. with the feature off the crate links libnwep_core, which
// does not export them, and declaring them would be a link error.

/// NWEP_BLS_PUBKEY_SIZE is the byte length of a bls12-381 public key NW120500.
#[cfg(feature = "trust")]
pub const NWEP_BLS_PUBKEY_SIZE: usize = 48;
/// NWEP_BLS_SECKEY_SIZE is the byte length of a bls secret key NW120500.
#[cfg(feature = "trust")]
pub const NWEP_BLS_SECKEY_SIZE: usize = 32;
/// NWEP_BLS_SIGNATURE_SIZE is the byte length of a bls signature NW120500.
#[cfg(feature = "trust")]
pub const NWEP_BLS_SIGNATURE_SIZE: usize = 96;

/// nwep_checkpoint is an opaque decoded merkle checkpoint NW120700.
#[cfg(feature = "trust")]
pub enum nwep_checkpoint {}
/// nwep_trust_store is an opaque trust state, anchors plus the latest checkpoint.
#[cfg(feature = "trust")]
pub enum nwep_trust_store {}

/// NWEP_CHECKPOINT_FRESH means age under one epoch NW120700.
#[cfg(feature = "trust")]
pub const NWEP_CHECKPOINT_FRESH: c_int = 0;
/// NWEP_CHECKPOINT_WARNING means age in the warning band NW120700.
#[cfg(feature = "trust")]
pub const NWEP_CHECKPOINT_WARNING: c_int = 1;
/// NWEP_CHECKPOINT_STALE means age past the warning band NW120700.
#[cfg(feature = "trust")]
pub const NWEP_CHECKPOINT_STALE: c_int = 2;

#[cfg(feature = "trust")]
extern "C" {
    /// nwep_trust_version returns the static trust-layer version string.
    pub fn nwep_trust_version() -> *const c_char;

    /// nwep_bls_keygen writes a fresh bls secret and public key NW120500.
    pub fn nwep_bls_keygen(out_sk: *mut u8, out_pk: *mut u8) -> c_int;

    /// nwep_bls_sign signs msg under sk with the checkpoint domain tag NW120500.
    pub fn nwep_bls_sign(out_sig: *mut u8, sk: *const u8, msg: *const u8, msg_len: usize) -> c_int;

    /// nwep_bls_verify checks a single-signer bls signature NW120500.
    pub fn nwep_bls_verify(sig: *const u8, pk: *const u8, msg: *const u8, msg_len: usize) -> c_int;

    /// nwep_bls_aggregate combines n contiguous bls signatures into one NW120500.
    pub fn nwep_bls_aggregate(out_sig: *mut u8, sigs: *const u8, n: usize) -> c_int;

    /// nwep_bls_verify_aggregate checks an aggregate against n pubkeys over one msg NW120500.
    pub fn nwep_bls_verify_aggregate(
        agg_sig: *const u8,
        pks: *const u8,
        n: usize,
        msg: *const u8,
        msg_len: usize,
    ) -> c_int;

    /// nwep_checkpoint_decode decodes wire bytes into a checkpoint handle NW120700.
    pub fn nwep_checkpoint_decode(
        bytes: *const u8,
        len: usize,
        out_cp: *mut *mut nwep_checkpoint,
    ) -> c_int;

    /// nwep_checkpoint_free frees a decoded checkpoint.
    pub fn nwep_checkpoint_free(cp: *mut nwep_checkpoint);

    /// nwep_checkpoint_staleness returns the checkpoint's staleness band NW120700.
    pub fn nwep_checkpoint_staleness(cp: *const nwep_checkpoint, now_secs: i64) -> c_int;

    /// nwep_genesis_checkpoint_create runs the genesis ceremony and encodes the
    /// epoch-0 checkpoint NW121100. two-call sizing via out == null.
    pub fn nwep_genesis_checkpoint_create(
        bls_secrets: *const u8,
        bls_pubkeys: *const u8,
        indices: *const u8,
        n_founders: usize,
        threshold: usize,
        out: *mut u8,
        outlen: *mut usize,
    ) -> c_int;

    /// nwep_trust_store_create allocates an empty trust store, null on failure.
    pub fn nwep_trust_store_create() -> *mut nwep_trust_store;

    /// nwep_trust_store_free frees a trust store.
    pub fn nwep_trust_store_free(ts: *mut nwep_trust_store);

    /// nwep_trust_store_load_genesis_anchors seeds n genesis anchor pubkeys NW121100.
    pub fn nwep_trust_store_load_genesis_anchors(
        ts: *mut nwep_trust_store,
        pubkeys: *const u8,
        n: usize,
    ) -> c_int;

    /// nwep_trust_store_update_checkpoint installs a checkpoint, returning its
    /// staleness band or a negative error NW120700.
    pub fn nwep_trust_store_update_checkpoint(
        ts: *mut nwep_trust_store,
        cp_bytes: *const u8,
        cp_len: usize,
        now_secs: i64,
    ) -> c_int;

    /// nwep_checkpoint_verify verifies a checkpoint against the store without
    /// installing it NW120800.
    pub fn nwep_checkpoint_verify(
        ts: *const nwep_trust_store,
        cp_bytes: *const u8,
        cp_len: usize,
        now_secs: i64,
    ) -> c_int;

    /// nwep_trust_store_observe_log_size bumps the rollback counter, never backwards.
    pub fn nwep_trust_store_observe_log_size(ts: *mut nwep_trust_store, observed: u64) -> c_int;

    /// nwep_trust_store_max_log_size returns the current rollback counter.
    pub fn nwep_trust_store_max_log_size(ts: *const nwep_trust_store) -> u64;

    /// nwep_trust_store_save serializes the rollback-critical state NW121000.
    /// two-call sizing via out == null.
    pub fn nwep_trust_store_save(
        ts: *const nwep_trust_store,
        out: *mut u8,
        outlen: *mut usize,
    ) -> c_int;

    /// nwep_trust_store_load restores state written by save into an existing store.
    pub fn nwep_trust_store_load(ts: *mut nwep_trust_store, bytes: *const u8, len: usize) -> c_int;

    /// nwep_trust_store_evaluate_key_rotation decides whether presented_pubkey is
    /// currently acceptable given a key-rotation entry, 0 acceptable NW120800.
    pub fn nwep_trust_store_evaluate_key_rotation(
        rotation_bytes: *const u8,
        rotation_len: usize,
        presented_pubkey: *const u8,
        now_secs: i64,
    ) -> c_int;

    /// nwep_trust_store_verify_key checks a node's revocation status over a
    /// connected log-server client, 0 not revoked, 1 revoked NW120800 NW121000.
    pub fn nwep_trust_store_verify_key(
        ts: *mut nwep_trust_store,
        client: *mut nwep_client,
        node_id: *const u8,
        recovery_commitment: *const u8,
        now_secs: i64,
    ) -> c_int;

    /// nwep_trust_store_verify_key_binding verifies a key-binding bundle against
    /// the installed checkpoint, 0 valid NW120800.
    pub fn nwep_trust_store_verify_key_binding(
        ts: *mut nwep_trust_store,
        node_id: *const u8,
        expected_pubkey: *const u8,
        bundle: *const u8,
        bundle_len: usize,
        now_secs: i64,
    ) -> c_int;

    /// nwep_trust_store_apply_anchor_change applies a quorum-signed anchor-change
    /// entry to the anchor set NW120300.
    pub fn nwep_trust_store_apply_anchor_change(
        ts: *mut nwep_trust_store,
        entry_bytes: *const u8,
        entry_len: usize,
        current_epoch: u64,
    ) -> c_int;
}

/// nwep_anchor_node is an opaque anchor that signs checkpoints NW120900.
#[cfg(feature = "trust")]
pub enum nwep_anchor_node {}

#[cfg(feature = "trust")]
extern "C" {
    /// nwep_anchor_node_create makes an anchor from its web/1 keypair and bls
    /// share, null on failure NW120900.
    pub fn nwep_anchor_node_create(
        pubkey: *const u8,
        privkey: *const u8,
        bls_secret: *const u8,
        bls_pubkey: *const u8,
        share_index: u64,
        collection_window_ms: u64,
    ) -> *mut nwep_anchor_node;

    /// nwep_anchor_node_free frees an anchor node.
    pub fn nwep_anchor_node_free(node: *mut nwep_anchor_node);

    /// nwep_anchor_node_collect_log_root records a verified epoch root the anchor
    /// will sign over NW120900.
    pub fn nwep_anchor_node_collect_log_root(
        node: *mut nwep_anchor_node,
        epoch: u64,
        server_root: *const u8,
        server_log_size: u64,
        local_root: *const u8,
    ) -> c_int;

    /// nwep_anchor_node_dispatch answers a peer's partial-sig request NW120900.
    pub fn nwep_anchor_node_dispatch(
        node: *mut nwep_anchor_node,
        requester_node_id: *const u8,
        anchor_ids: *const u8,
        n_anchors: usize,
        req: *const nwep_message,
        resp: *mut nwep_buf,
        now_secs: i64,
    ) -> c_int;

    /// nwep_anchor_node_produce_partial_sig produces this anchor's own partial
    /// signature for an epoch NW120600.
    pub fn nwep_anchor_node_produce_partial_sig(
        node: *mut nwep_anchor_node,
        epoch: u64,
        merkle_root: *const u8,
        log_size: u64,
        out_index: *mut u8,
        out_sig: *mut u8,
    ) -> c_int;

    /// nwep_anchor_request_partial_sig asks one peer anchor for its partial over
    /// a client and verifies it NW120900.
    pub fn nwep_anchor_request_partial_sig(
        client: *mut nwep_client,
        epoch: u64,
        merkle_root: *const u8,
        log_size: u64,
        peer_bls_pubkey: *const u8,
        out_index: *mut u8,
        out_sig: *mut u8,
    ) -> c_int;

    /// nwep_anchor_finish_checkpoint aggregates gathered partials into a
    /// checkpoint, two-call sizing via out == null NW120900.
    pub fn nwep_anchor_finish_checkpoint(
        epoch: u64,
        merkle_root: *const u8,
        log_size: u64,
        indices: *const u8,
        sigs: *const u8,
        n_partials: usize,
        anchor_bls_pks: *const u8,
        n_anchors: usize,
        out: *mut u8,
        outlen: *mut usize,
    ) -> c_int;
}
