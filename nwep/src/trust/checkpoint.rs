//! nwep checkpoint, the bls-signed merkle root that anchors trust to an epoch NW120700.
//!
//! Checkpoint is a decoded checkpoint a node can inspect for staleness. the
//! genesis checkpoint, minted once by the founding anchors with
//! [genesis_checkpoint], is the hardcoded root of trust that bootstraps a
//! [crate::trust::TrustStore].

use crate::error::{Error, Result};
use crate::trust::bls::BlsKeypair;
use core::ptr;
use nwep_sys as sys;

/// CheckpointStatus is a checkpoint's staleness band, by age NW120700.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointStatus {
    /// age under one epoch, fully trusted.
    Fresh,
    /// age in the warning band, usable but due for refresh.
    Warning,
    /// age past the warning band, not installed by the store.
    Stale,
}

impl CheckpointStatus {
    /// maps a c staleness band code to a status, defaulting to stale on anything
    /// unexpected so an unknown band never reads as fresh.
    pub(crate) fn from_code(code: core::ffi::c_int) -> CheckpointStatus {
        match code {
            sys::NWEP_CHECKPOINT_FRESH => CheckpointStatus::Fresh,
            sys::NWEP_CHECKPOINT_WARNING => CheckpointStatus::Warning,
            _ => CheckpointStatus::Stale,
        }
    }
}

/// Checkpoint is a decoded merkle checkpoint NW120700.
pub struct Checkpoint {
    raw: *mut sys::nwep_checkpoint,
}

impl Checkpoint {
    /// decodes a checkpoint from its wire bytes NW120700.
    ///
    /// returns the decoded [Checkpoint].
    /// errors [Error::ProtoInvalidMessage] when the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Result<Checkpoint> {
        let mut raw: *mut sys::nwep_checkpoint = ptr::null_mut();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_checkpoint_decode(bytes.as_ptr(), bytes.len(), &mut raw)
        })?;
        Ok(Checkpoint { raw })
    }

    /// returns the checkpoint's staleness band at now_secs NW120700.
    ///
    /// returns the [CheckpointStatus].
    /// errors [Error::Internal] when the handle is unusable.
    pub fn staleness(&self, now_secs: i64) -> Result<CheckpointStatus> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_checkpoint_staleness(self.raw, now_secs) };
        if rc < 0 {
            return Err(Error::from_code(rc));
        }
        Ok(CheckpointStatus::from_code(rc))
    }

    /// borrows the raw c checkpoint handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_checkpoint {
        self.raw
    }
}

impl Drop for Checkpoint {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_checkpoint_free(self.raw) };
    }
}

/// runs the genesis ceremony and encodes the network's epoch-0 checkpoint NW121100.
///
/// every founding anchor signs, and the aggregate is bls-verified before the
/// bytes are produced. these bytes are the hardcoded genesis a deployment commits
/// to bootstrap trust. each founder is its [BlsKeypair] and its 1-based share
/// index. the founding secret keys are the root of all trust, this copies them
/// into a temporary buffer and zeroizes it before returning NWG0700 NW121100.
///
/// returns the encoded genesis checkpoint bytes.
/// errors [Error::ConfigInvalid] when there are no founders or the threshold is
/// out of range, and [Error::TrustInvalidEntry] when the ceremony fails.
pub fn genesis_checkpoint(founders: &[(&BlsKeypair, u8)], threshold: usize) -> Result<Vec<u8>> {
    if founders.is_empty() || threshold == 0 || threshold > founders.len() {
        return Err(Error::ConfigInvalid);
    }
    let n = founders.len();
    let mut secrets = vec![0u8; n * sys::NWEP_BLS_SECKEY_SIZE];
    let mut pubkeys = vec![0u8; n * sys::NWEP_BLS_PUBKEY_SIZE];
    let mut indices = vec![0u8; n];
    for (i, (kp, index)) in founders.iter().enumerate() {
        let sk = i * sys::NWEP_BLS_SECKEY_SIZE;
        let pk = i * sys::NWEP_BLS_PUBKEY_SIZE;
        secrets[sk..sk + sys::NWEP_BLS_SECKEY_SIZE].copy_from_slice(kp.secret());
        pubkeys[pk..pk + sys::NWEP_BLS_PUBKEY_SIZE].copy_from_slice(kp.public_key());
        indices[i] = *index;
    }

    // two-call sizing, then the real encode.
    let mut len = 0usize;
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    let size_rc = unsafe {
        sys::nwep_genesis_checkpoint_create(
            secrets.as_ptr(),
            pubkeys.as_ptr(),
            indices.as_ptr(),
            n,
            threshold,
            ptr::null_mut(),
            &mut len,
        )
    };
    if let Err(e) = Error::check(size_rc) {
        // SAFETY: the slice pointer and length are consistent.
        unsafe { sys::nwep_zeroize(secrets.as_mut_ptr().cast(), secrets.len()) };
        return Err(e);
    }
    let mut out = vec![0u8; len];
    // SAFETY: buf is sized to len as returned by the probe call above.
    let rc = unsafe {
        sys::nwep_genesis_checkpoint_create(
            secrets.as_ptr(),
            pubkeys.as_ptr(),
            indices.as_ptr(),
            n,
            threshold,
            out.as_mut_ptr(),
            &mut len,
        )
    };
    // the founding secrets must not linger in our buffer NW121100.
    // SAFETY: the slice pointer and length are consistent.
    unsafe { sys::nwep_zeroize(secrets.as_mut_ptr().cast(), secrets.len()) };
    Error::check(rc)?;
    out.truncate(len);
    Ok(out)
}
