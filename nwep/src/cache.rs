//! nwep shared signed cache, store-and-serve for public responses NW060700 NW060900.
//!
//! Cache stores "public", signed responses from origin servers and serves them to
//! other clients, who trust them through the response signature (verified against
//! the origin node) rather than the connection. it is the proxy/cdn surface, a
//! proxy verifies an origin response, [Cache::put_signed]s it, and later
//! [Cache::get_signed]s it for a different client. it owns c state, so it is
//! !Send and !Sync NWG0900.

use crate::client::Response;
use crate::error::{Error, Result};
use crate::wire::Method;
use core::ptr;
use nwep_sys as sys;

/// CacheStats is a cache's hit/miss/store/eviction counters NW060700.
#[derive(Clone, Copy, Debug, Default)]
pub struct CacheStats {
    /// served-from-cache lookups.
    pub hits: u64,
    /// lookups that found nothing fresh.
    pub misses: u64,
    /// responses stored.
    pub stores: u64,
    /// entries evicted to stay within bounds.
    pub evictions: u64,
}

/// Cache is a bounded store of public, signed responses NW060700.
pub struct Cache {
    raw: *mut sys::nwep_cache,
}

impl Cache {
    /// creates a cache bounded by total stored bytes and entry count NW060700.
    ///
    /// returns the new [Cache].
    /// errors [Error::InternalAlloc] when allocation fails.
    pub fn new(max_bytes: usize, max_entries: usize) -> Result<Cache> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let raw = unsafe { sys::nwep_cache_create(max_bytes, max_entries) };
        if raw.is_null() {
            return Err(Error::InternalAlloc);
        }
        Ok(Cache { raw })
    }

    /// verifies a public signed response and stores it under (method, path) NW060900.
    ///
    /// the response must be "public" and carry a valid signature for origin_pubkey,
    /// so a shared cache never serves unverified bytes. now_secs is unix seconds.
    ///
    /// returns unit when stored.
    /// errors [Error::ProtoInvalidHeader] when the response is not cacheable
    /// (not public or unsigned), and [Error::CryptoVerify] on a bad signature.
    pub fn put_signed(
        &mut self,
        method: Method,
        path: &str,
        response: &Response,
        origin_pubkey: &[u8; 32],
        now_secs: u64,
    ) -> Result<()> {
        let cpath = std::ffi::CString::new(path).map_err(|_| Error::ProtoInvalidHeader)?;
        let cmethod = method_cstr(method);
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_cache_put_signed(
                self.raw,
                cmethod.as_ptr(),
                cpath.as_ptr(),
                response.as_raw(),
                origin_pubkey.as_ptr(),
                now_secs,
            )
        })
    }

    /// serves a stored response for (method, path) if one is fresh NW060900.
    ///
    /// now_secs is unix seconds, used to enforce the stored response's freshness.
    ///
    /// returns some [Response] on a fresh hit, or none on a miss or expiry.
    pub fn get_signed(
        &mut self,
        method: Method,
        path: &str,
        origin_pubkey: &[u8; 32],
        now_secs: u64,
    ) -> Option<Response> {
        let cpath = std::ffi::CString::new(path).ok()?;
        let cmethod = method_cstr(method);
        let mut out: *mut sys::nwep_message = ptr::null_mut();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe {
            sys::nwep_cache_get_signed(
                self.raw,
                cmethod.as_ptr(),
                cpath.as_ptr(),
                origin_pubkey.as_ptr(),
                now_secs,
                &mut out,
            )
        };
        if rc == 0 && !out.is_null() {
            Some(Response::from_raw(out))
        } else {
            None
        }
    }

    /// drops all stored entries; the cache stays usable.
    pub fn clear(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_cache_clear(self.raw) };
    }

    /// returns the cache's hit/miss/store/eviction counters.
    pub fn stats(&self) -> CacheStats {
        let mut s = CacheStats::default();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe {
            sys::nwep_cache_stats(
                self.raw,
                &mut s.hits,
                &mut s.misses,
                &mut s.stores,
                &mut s.evictions,
            )
        };
        s
    }

    /// borrows the raw c cache handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_cache {
        self.raw
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_cache_free(self.raw) };
    }
}

/// returns a method's lowercase wire token as a nul-terminated c string for the
/// cache key, for example "read".
fn method_cstr(method: Method) -> std::ffi::CString {
    // the token is fixed ascii with no interior nul, so this never fails.
    std::ffi::CString::new(method.as_str()).unwrap_or_default()
}
