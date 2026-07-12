//! nwep key-rotation acceptance, the trust check for a rotated key NW120800.
//!
//! when a node presents a key for which it has published a [crate::log::KeyRotation],
//! [evaluate_key_rotation] decides whether that key is currently acceptable, the
//! new key always, the old key only within its overlap window. it requires the "trust" feature.

use crate::error::{Error, Result};
use nwep_sys as sys;

/// decides whether presented_pubkey is acceptable given a key-rotation entry NW120800.
///
/// the caller has already verified the rotation's proof and signatures. the new
/// key is accepted, the old key only until its overlap expiry. now_secs is unix
/// seconds.
///
/// returns unit when the key is acceptable.
/// errors [Error::IdentityRevoked] when the old key is presented past its
/// overlap window, [Error::IdentityMismatch] when the key is neither the old nor
/// the new one, and [Error::ProtoInvalidMessage] when the entry is malformed.
pub fn evaluate_key_rotation(
    rotation_bytes: &[u8],
    presented_pubkey: &[u8; 32],
    now_secs: i64,
) -> Result<()> {
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    Error::check(unsafe {
        sys::nwep_trust_store_evaluate_key_rotation(
            rotation_bytes.as_ptr(),
            rotation_bytes.len(),
            presented_pubkey.as_ptr(),
            now_secs,
        )
    })
}
