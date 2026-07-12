//! nwep log server, the trust-log endpoints behind a web/1 server NW120000 NW000014.
//!
//! LogServer routes the /log/* endpoints (entry submission, inclusion proofs,
//! the root, revocation queries) over a [crate::Server]. drop it into a server
//! handler with [LogServer::dispatch], which either handles a log request or
//! hands the responder back so the app can answer its own routes. it owns its
//! [Log] and signs assertions with the server's identity, which a client checks
//! against the connection's authenticated peer.

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::log::Log;
use crate::server::{Reply, Request, Responder};
use core::ffi::c_void;
use nwep_sys as sys;

/// the boxed accepted-entry hook, owned by the LogServer at a stable address.
type AppendHook = Box<dyn FnMut(&[u8], u64) + Send>;

/// DispatchOutcome is whether [LogServer::dispatch] answered a request NW000014.
pub enum DispatchOutcome {
    /// the log server handled the request and produced the [Reply].
    Handled(Reply),
    /// the request was not a /log/* route, here is the responder back so the
    /// app can answer it.
    NotMine(Responder),
}

/// LogServer serves the trust-log endpoints over a server's connections NW000014.
///
/// it owns its [Log] and a borrowed-once identity copy. it is pinned to the one
/// thread that runs its server's handler (the actor-bridge owner thread). see the
/// Send note below.
pub struct LogServer {
    raw: *mut sys::nwep_log_server,
    hook: Option<*mut AppendHook>,
    // the log outlives the server (the c api borrows it), so we own it and drop
    // it after the server in this struct's drop order.
    _log: Log,
}

// the log server is single threaded like every other handle, but it must be
// movable into a server handler that the managed runtime relocates to its owner
// thread once NWG0600. Send (not Sync) models exactly that move-once, never
// aliased ownership. it is never accessed from two threads at once.
unsafe impl Send for LogServer {}

impl LogServer {
    /// creates a log server signing with identity over log NW000014.
    ///
    /// the identity should match the web/1 server's, so a client checks the
    /// server-id of a signed assertion against the connection's peer. the log is
    /// taken by value and owned for the server's life.
    ///
    /// returns the new [LogServer].
    /// errors [Error::InternalAlloc] when allocation fails.
    pub fn new(identity: &Identity, log: Log) -> Result<LogServer> {
        let raw =
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            identity.with_keypair(|kp| unsafe { sys::nwep_log_server_create(kp, log.as_ptr()) });
        if raw.is_null() {
            return Err(Error::InternalAlloc);
        }
        Ok(LogServer {
            raw,
            hook: None,
            _log: log,
        })
    }

    /// registers a hook fired with the bytes and index of each accepted entry NW000014.
    ///
    /// the hook runs on the server's handler thread, synchronously inside the
    /// write that accepted the entry, so it must not block. lets an embedder
    /// durably persist accepted entries without inferring acceptance.
    pub fn on_append(&mut self, hook: impl FnMut(&[u8], u64) + Send + 'static) {
        // drop any previous hook before installing the new one.
        self.clear_hook();
        let boxed: *mut AppendHook = Box::into_raw(Box::new(Box::new(hook)));
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe {
            sys::nwep_log_server_set_on_append(
                self.raw,
                Some(append_trampoline),
                boxed as *mut c_void,
            )
        };
        self.hook = Some(boxed);
    }

    /// routes a request through the /log/* handlers NW000014.
    ///
    /// call it first in a server handler. on a log route it writes the response
    /// and returns [DispatchOutcome::Handled], otherwise it returns the responder
    /// unchanged as [DispatchOutcome::NotMine] so the app can answer. now_secs is
    /// unix seconds.
    pub fn dispatch(&self, req: &Request, res: Responder, now_secs: i64) -> DispatchOutcome {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe {
            sys::nwep_log_server_dispatch(
                self.raw,
                req.conn_id(),
                req.raw_msg(),
                res.raw_buf(),
                now_secs,
            )
        };
        if rc == 1 {
            // not a log route, hand the responder back untouched.
            DispatchOutcome::NotMine(res)
        } else {
            // handled (0) or error (<0); the buffer is written, finalize with rc.
            DispatchOutcome::Handled(res.finish(rc))
        }
    }

    /// borrows the raw c log-server handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_log_server {
        self.raw
    }

    fn clear_hook(&mut self) {
        if let Some(ptr) = self.hook.take() {
            // SAFETY: all pointers are valid; ptr is Box::into_raw-ed in on_append and uniquely owned after take.
            unsafe {
                sys::nwep_log_server_set_on_append(self.raw, None, core::ptr::null_mut());
                drop(Box::from_raw(ptr));
            }
        }
    }
}

impl Drop for LogServer {
    fn drop(&mut self) {
        // free the server first so no hook can fire, then the hook box, then the
        // owned log (field order drops _log last).
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_log_server_free(self.raw) };
        self.clear_hook();
    }
}

/// the c append callback. rebuilds the borrowed entry slice and runs the hook.
/// it cannot unwind into c, so a panic is swallowed NWG0900.
unsafe extern "C" fn append_trampoline(ctx: *mut c_void, entry: *const u8, len: usize, index: u64) {
    // SAFETY: ctx is a Box<AppendHook> cast to raw pointer in on_append; the server ensures it is valid and exclusively accessed here.
    let hook = unsafe { &mut *(ctx as *mut AppendHook) };
    let bytes = if entry.is_null() || len == 0 {
        &[][..]
    } else {
        // SAFETY: entry is non-null and len > 0 (checked above); the C library guarantees the bytes are valid for the duration of this callback.
        unsafe { core::slice::from_raw_parts(entry, len) }
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(bytes, index)));
}
