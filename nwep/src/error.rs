//! nwep error taxonomy, the rust face of the spec 13 error table.
//!
//! Error mirrors every error code the c abi can return, grouped into the spec
//! families, with the numeric code preserved and the same human message the c
//! library would give (via nwep_strerror). it is the single error type the whole
//! crate returns.

use core::ffi::{c_int, CStr};
use core::fmt;

/// Result is the crate wide result type, short for the std result over [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// Error is one variant per spec 13 error code, plus [Error::Other] for a code
/// a newer library version may add.
///
/// the numeric code is recoverable with [Error::code], and [Error::is_fatal]
/// tells a connection level death (a spec *-fatal-* code) apart from a
/// retryable failure.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// config-invalid (-101). a configuration value was unusable.
    ConfigInvalid,
    /// config-missing (-102). a required configuration value was absent.
    ConfigMissing,
    /// network-connect (-201).
    NetworkConnect,
    /// network-timeout (-202).
    NetworkTimeout,
    /// network-closed (-203).
    NetworkClosed,
    /// network-quic (-204).
    NetworkQuic,
    /// network-tls (-205).
    NetworkTls,
    /// crypto-keygen (-301). the csprng or key generation failed.
    CryptoKeygen,
    /// crypto-rand (-302). the csprng failed.
    CryptoRand,
    /// crypto-sign (-303).
    CryptoSign,
    /// crypto-verify (-304). a signature did not verify.
    CryptoVerify,
    /// crypto-fatal-cert (-381). fatal, the connection must close NW090000.
    CryptoFatalCert,
    /// crypto-fatal-nodeid-mismatch (-382). fatal NW090600.
    CryptoFatalNodeIdMismatch,
    /// crypto-fatal-challenge (-383). fatal NW090600.
    CryptoFatalChallenge,
    /// crypto-fatal-server-sig (-384). fatal NW090600.
    CryptoFatalServerSig,
    /// crypto-fatal-client-sig (-385). fatal NW090600.
    CryptoFatalClientSig,
    /// proto-invalid-message (-401).
    ProtoInvalidMessage,
    /// proto-invalid-method (-402).
    ProtoInvalidMethod,
    /// proto-invalid-header (-403).
    ProtoInvalidHeader,
    /// proto-connect-required (-404). connect must be the first message NW070300.
    ProtoConnectRequired,
    /// proto-stream-reuse (-405).
    ProtoStreamReuse,
    /// proto-max-streams (-406).
    ProtoMaxStreams,
    /// proto-flow-control (-407).
    ProtoFlowControl,
    /// proto-message-too-large (-408).
    ProtoMessageTooLarge,
    /// proto-fatal-version (-481). fatal, version negotiation failed NW070000.
    ProtoFatalVersion,
    /// identity-generate (-501).
    IdentityGenerate,
    /// identity-mismatch (-502).
    IdentityMismatch,
    /// identity-not-found (-503). a dht lookup resolved nothing NW110800.
    IdentityNotFound,
    /// identity-revoked (-504).
    IdentityRevoked,
    /// app-not-found (-601).
    AppNotFound,
    /// app-conflict (-602).
    AppConflict,
    /// app-rate-limited (-603).
    AppRateLimited,
    /// app-forbidden (-604).
    AppForbidden,
    /// trust-invalid-entry (-701) NW120300.
    TrustInvalidEntry,
    /// trust-invalid-anchor (-702) NW120500.
    TrustInvalidAnchor,
    /// trust-stale-checkpoint (-703) NW120700.
    TrustStaleCheckpoint,
    /// trust-threshold (-704). too few anchor signatures NW120500.
    TrustThreshold,
    /// trust-revoked (-705).
    TrustRevoked,
    /// trust-no-checkpoint (-706).
    TrustNoCheckpoint,
    /// trust-fatal-equivocation (-781). fatal, the log forked NW120700.
    TrustFatalEquivocation,
    /// trust-fatal-log-corrupt (-782). fatal NW120000.
    TrustFatalLogCorrupt,
    /// internal (-801).
    Internal,
    /// internal-alloc (-802). an allocation failed.
    InternalAlloc,
    /// would-block (-803). an async operation is not ready yet (not an error).
    WouldBlock,
    /// other holds a negative code this build of the crate does not name.
    Other(i32),
}

impl Error {
    /// returns the spec 13 numeric code (always negative) behind this error.
    pub fn code(self) -> i32 {
        use Error::*;
        match self {
            ConfigInvalid => -101,
            ConfigMissing => -102,
            NetworkConnect => -201,
            NetworkTimeout => -202,
            NetworkClosed => -203,
            NetworkQuic => -204,
            NetworkTls => -205,
            CryptoKeygen => -301,
            CryptoRand => -302,
            CryptoSign => -303,
            CryptoVerify => -304,
            CryptoFatalCert => -381,
            CryptoFatalNodeIdMismatch => -382,
            CryptoFatalChallenge => -383,
            CryptoFatalServerSig => -384,
            CryptoFatalClientSig => -385,
            ProtoInvalidMessage => -401,
            ProtoInvalidMethod => -402,
            ProtoInvalidHeader => -403,
            ProtoConnectRequired => -404,
            ProtoStreamReuse => -405,
            ProtoMaxStreams => -406,
            ProtoFlowControl => -407,
            ProtoMessageTooLarge => -408,
            ProtoFatalVersion => -481,
            IdentityGenerate => -501,
            IdentityMismatch => -502,
            IdentityNotFound => -503,
            IdentityRevoked => -504,
            AppNotFound => -601,
            AppConflict => -602,
            AppRateLimited => -603,
            AppForbidden => -604,
            TrustInvalidEntry => -701,
            TrustInvalidAnchor => -702,
            TrustStaleCheckpoint => -703,
            TrustThreshold => -704,
            TrustRevoked => -705,
            TrustNoCheckpoint => -706,
            TrustFatalEquivocation => -781,
            TrustFatalLogCorrupt => -782,
            Internal => -801,
            InternalAlloc => -802,
            WouldBlock => -803,
            Other(c) => c,
        }
    }

    /// returns true for a spec *-fatal-* code, where the connection or the trust
    /// state is dead and must not be retried NW090000 NW120700.
    pub fn is_fatal(self) -> bool {
        use Error::*;
        matches!(
            self,
            CryptoFatalCert
                | CryptoFatalNodeIdMismatch
                | CryptoFatalChallenge
                | CryptoFatalServerSig
                | CryptoFatalClientSig
                | ProtoFatalVersion
                | TrustFatalEquivocation
                | TrustFatalLogCorrupt
        )
    }

    /// maps a raw c return code to an Error. a non negative code is success and
    /// must be handled by the caller, not passed here, so it folds to internal.
    pub(crate) fn from_code(code: c_int) -> Error {
        use Error::*;
        match code {
            -101 => ConfigInvalid,
            -102 => ConfigMissing,
            -201 => NetworkConnect,
            -202 => NetworkTimeout,
            -203 => NetworkClosed,
            -204 => NetworkQuic,
            -205 => NetworkTls,
            -301 => CryptoKeygen,
            -302 => CryptoRand,
            -303 => CryptoSign,
            -304 => CryptoVerify,
            -381 => CryptoFatalCert,
            -382 => CryptoFatalNodeIdMismatch,
            -383 => CryptoFatalChallenge,
            -384 => CryptoFatalServerSig,
            -385 => CryptoFatalClientSig,
            -401 => ProtoInvalidMessage,
            -402 => ProtoInvalidMethod,
            -403 => ProtoInvalidHeader,
            -404 => ProtoConnectRequired,
            -405 => ProtoStreamReuse,
            -406 => ProtoMaxStreams,
            -407 => ProtoFlowControl,
            -408 => ProtoMessageTooLarge,
            -481 => ProtoFatalVersion,
            -501 => IdentityGenerate,
            -502 => IdentityMismatch,
            -503 => IdentityNotFound,
            -504 => IdentityRevoked,
            -601 => AppNotFound,
            -602 => AppConflict,
            -603 => AppRateLimited,
            -604 => AppForbidden,
            -701 => TrustInvalidEntry,
            -702 => TrustInvalidAnchor,
            -703 => TrustStaleCheckpoint,
            -704 => TrustThreshold,
            -705 => TrustRevoked,
            -706 => TrustNoCheckpoint,
            -781 => TrustFatalEquivocation,
            -782 => TrustFatalLogCorrupt,
            -801 => Internal,
            -802 => InternalAlloc,
            -803 => WouldBlock,
            other => Other(other),
        }
    }

    /// turns a c status code into a result, where 0 and any positive value are
    /// success and a negative value is the matching [Error].
    ///
    /// returns ok for a non negative code.
    /// errors the [Error] named by a negative spec 13 code.
    pub(crate) fn check(code: c_int) -> Result<()> {
        if code >= 0 {
            Ok(())
        } else {
            Err(Error::from_code(code))
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // the message text comes straight from the library so it reads the same
        // across every binding NWG0800.
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let ptr = unsafe { nwep_sys::nwep_strerror(self.code()) };
        let name = if ptr.is_null() {
            "unknown"
        } else {
            // SAFETY: nwep_strerror returns a static nul-terminated string; non-null confirmed by the check above.
            unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("unknown")
        };
        write!(f, "{name} ({})", self.code())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error({self})")
    }
}

impl std::error::Error for Error {}
