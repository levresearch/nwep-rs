//! nwep trust layer, the bls anchor and merkle log surface NW120000.
//!
//! this is the verifiable trust half of the protocol, gated behind the "trust"
//! cargo feature so consumers that do not verify anchors do not link blst. it is
//! built against the full libnwep, not libnwep_core NWG1200.
//!
//! today it covers the bls threshold primitives ([bls]), the [checkpoint] and
//! genesis ceremony, and the [TrustStore]. the anchor production ceremony is
//! added in a later slice.

pub mod anchor;
pub mod bls;
pub mod checkpoint;
mod key;
mod store;

pub use anchor::{finish_checkpoint, request_partial_sig, AnchorNode, PartialSig};
pub use checkpoint::{genesis_checkpoint, Checkpoint, CheckpointStatus};
pub use key::evaluate_key_rotation;
pub use store::{KeyStatus, TrustStore};

/// returns the static version string of the linked trust layer.
pub fn version() -> &'static str {
    // SAFETY: nwep_trust_version takes no arguments.
    let ptr = unsafe { nwep_sys::nwep_trust_version() };
    // SAFETY: nwep_trust_version returns a static nul-terminated string, never null.
    unsafe { core::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or("unknown")
}
