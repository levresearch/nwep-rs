//! nwep message headers, the shared view over a decoded message's header block NW060300.
//!
//! Headers walks every header of a request or response in wire order, for a
//! consumer that must forward or print headers it does not know in advance (a
//! proxy, a generic client). both [crate::Request] and [crate::Response] hand
//! one out. the borrowed strings live as long as the message they came from.

use core::ffi::{c_char, CStr};
use core::marker::PhantomData;
use core::ptr;
use nwep_sys as sys;

/// Headers iterates a message's headers in wire order as (name, value) pairs NW060300.
pub struct Headers<'a> {
    msg: *const sys::nwep_message,
    next: usize,
    count: usize,
    _life: PhantomData<&'a ()>,
}

impl<'a> Headers<'a> {
    /// builds a header iterator over msg, valid while the borrow 'a lasts.
    pub(crate) fn new(msg: *const sys::nwep_message) -> Headers<'a> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let count = unsafe { sys::nwep_message_header_count(msg) };
        Headers {
            msg,
            next: 0,
            count,
            _life: PhantomData,
        }
    }
}

impl<'a> Iterator for Headers<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<(&'a str, &'a str)> {
        if self.next >= self.count {
            return None;
        }
        let i = self.next;
        self.next += 1;
        let mut name: *const c_char = ptr::null();
        let mut value: *const c_char = ptr::null();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_message_header_at(self.msg, i, &mut name, &mut value) };
        if rc != 0 || name.is_null() || value.is_null() {
            // a header that does not read back is reported as empty rather than
            // dropped, so the count and the iteration stay in step.
            return Some(("", ""));
        }
        // wire headers are ascii tokens, so a decode failure falls back to empty.
        // SAFETY: the library writes nul-terminated strings into its own memory; rc == 0 guarantees non-null.
        let k = unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("");
        // SAFETY: the library writes nul-terminated strings into its own memory; rc == 0 guarantees non-null.
        let v = unsafe { CStr::from_ptr(value) }.to_str().unwrap_or("");
        Some((k, v))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Headers<'_> {}
