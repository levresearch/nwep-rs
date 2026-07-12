//! nwep wire tokens, the request methods and response statuses NW050000 NW080000.
//!
//! Method is the verb a client sends NW050000. Status is the result token a
//! server returns NW080000. both render to and parse from their lowercase wire
//! tokens. the numeric discriminants are the protocol method and status indices.

use core::ffi::{c_char, c_int, CStr};
use core::fmt;
use nwep_sys as sys;

/// Method is a web/1 request verb NW050000.
///
/// the discriminant is the method code carried on the wire and accepted by the
/// client send call. the handshake only verbs connect and authenticate are not
/// in this set, an application never sends them.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Method {
    /// read a resource NW050000.
    Read = 0,
    /// write a resource NW050000.
    Write = 1,
    /// update a resource NW050000.
    Update = 2,
    /// delete a resource NW050000.
    Delete = 3,
    /// liveness check NW050000.
    Heartbeat = 6,
    /// read a resource's metadata only, no body NW060600.
    Head = 7,
}

impl Method {
    /// returns the method code carried on the wire NW050000.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// returns the lowercase wire token of this method, for example "read".
    pub fn as_str(self) -> &'static str {
        // every variant is a known index, so the library never returns null.
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        static_token(unsafe { sys::nwep_method_str(self as c_int) })
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Status is a web/1 response result token NW080000.
///
/// the discriminant is the status index. an unknown token a peer sends maps to
/// [Status::Error], the spec 8 rule for degraded forward compatibility.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Status {
    /// ok NW080000.
    Ok = 0,
    /// created NW080000.
    Created = 1,
    /// accepted NW080000.
    Accepted = 2,
    /// no-content NW080000.
    NoContent = 3,
    /// partial-content NW060800.
    PartialContent = 4,
    /// moved  -  resource permanently at a new web:// URI; location header required NW080000.
    Moved = 5,
    /// not-modified NW060700.
    NotModified = 6,
    /// bad-request NW080000.
    BadRequest = 7,
    /// unauthorized NW080000.
    Unauthorized = 8,
    /// forbidden NW080000.
    Forbidden = 9,
    /// not-found NW080000.
    NotFound = 10,
    /// not-allowed  -  method not permitted on this resource NW080000.
    NotAllowed = 11,
    /// conflict NW080000.
    Conflict = 12,
    /// gone  -  resource permanently removed, no replacement NW080000.
    Gone = 13,
    /// too-large  -  request body exceeded the server's limit NW080000.
    TooLarge = 14,
    /// precondition-failed  -  a conditional header did not hold NW080000.
    PreconditionFailed = 15,
    /// range-not-satisfiable NW060800.
    RangeNotSatisfiable = 16,
    /// rate-limited NW080000. pairs with a retry-after header NW080000.
    RateLimited = 17,
    /// error, also the catch-all for an unknown token NW080000.
    Error = 18,
    /// unavailable NW080000.
    Unavailable = 19,
    /// timeout  -  server took too long to process the request NW080000.
    Timeout = 20,
    /// not-implemented  -  method or feature not supported by this server NW080000.
    NotImplemented = 21,
}

impl Status {
    /// returns the status index this token sits at NW080000.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// returns the lowercase wire token of this status, for example "not-found".
    pub fn as_str(self) -> &'static str {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        static_token(unsafe { sys::nwep_status_str(self as c_int) })
    }

    /// maps a wire status token to a Status.
    ///
    /// an unrecognized token becomes [Status::Error], the spec 8 rule so a newer
    /// status from a peer degrades to a plain failure instead of breaking.
    pub fn from_token(token: &str) -> Status {
        use Status::*;
        match token {
            "ok" => Ok,
            "created" => Created,
            "accepted" => Accepted,
            "no-content" => NoContent,
            "partial-content" => PartialContent,
            "moved" => Moved,
            "not-modified" => NotModified,
            "bad-request" => BadRequest,
            "unauthorized" => Unauthorized,
            "forbidden" => Forbidden,
            "not-found" => NotFound,
            "not-allowed" => NotAllowed,
            "conflict" => Conflict,
            "gone" => Gone,
            "too-large" => TooLarge,
            "precondition-failed" => PreconditionFailed,
            "range-not-satisfiable" => RangeNotSatisfiable,
            "rate-limited" => RateLimited,
            "unavailable" => Unavailable,
            "timeout" => Timeout,
            "not-implemented" => NotImplemented,
            _ => Error,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// reads a static, nul terminated token the library returned. the pointer is to
/// a static literal for a known index, so this never frees and never sees null.
fn static_token(ptr: *const c_char) -> &'static str {
    debug_assert!(!ptr.is_null(), "a known method or status index has a token");
    // SAFETY: nwep_method_str and nwep_status_str return static nul-terminated strings, never null.
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_tokens_and_codes() {
        assert_eq!(Method::Read.as_str(), "read");
        assert_eq!(Method::Head.as_str(), "head");
        assert_eq!(Method::Heartbeat.code(), 6);
        assert_eq!(Method::Head.code(), 7);
        assert_eq!(Method::Delete.to_string(), "delete");
    }

    #[test]
    fn status_tokens_round_trip() {
        assert_eq!(Status::NotFound.as_str(), "not-found");
        assert_eq!(Status::NotAllowed.as_str(), "not-allowed");
        assert_eq!(Status::Gone.as_str(), "gone");
        assert_eq!(Status::TooLarge.as_str(), "too-large");
        assert_eq!(Status::PreconditionFailed.as_str(), "precondition-failed");
        assert_eq!(Status::Timeout.as_str(), "timeout");
        assert_eq!(Status::NotImplemented.as_str(), "not-implemented");
        assert_eq!(Status::Moved.as_str(), "moved");
        assert_eq!(
            Status::RangeNotSatisfiable.as_str(),
            "range-not-satisfiable"
        );
        assert_eq!(Status::from_token("not-found"), Status::NotFound);
        assert_eq!(Status::from_token("moved"), Status::Moved);
        assert_eq!(Status::from_token("gone"), Status::Gone);
        assert_eq!(Status::from_token("timeout"), Status::Timeout);
        assert_eq!(
            Status::from_token("not-implemented"),
            Status::NotImplemented
        );
        assert_eq!(
            Status::from_token("partial-content"),
            Status::PartialContent
        );
    }

    #[test]
    fn unknown_status_token_degrades_to_error() {
        assert_eq!(Status::from_token("teapot"), Status::Error);
    }
}
