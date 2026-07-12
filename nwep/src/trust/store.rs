//! nwep trust store, a node's verifiable trust state NW120700.
//!
//! TrustStore holds the anchor set and the latest installed checkpoint, and is
//! what a node consults to decide whether a key is trustworthy. seed it with the
//! genesis anchors, install checkpoints as they arrive, and persist its
//! rollback-critical state across restarts. it owns c state, so it is !Send and
//! !Sync NWG0900.

use crate::client::Client;
use crate::error::{Error, Result};
use crate::identity::NodeId;
use crate::trust::checkpoint::CheckpointStatus;
use core::ptr;
use nwep_sys as sys;

/// KeyStatus is a node key's revocation state from [TrustStore::verify_key] NW120800.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    /// no revocation found, the key is current.
    NotRevoked,
    /// a verified revocation was found, the key is retired.
    Revoked,
}

/// TrustStore is the anchor set plus the latest checkpoint a node trusts NW120700.
pub struct TrustStore {
    raw: *mut sys::nwep_trust_store,
}

impl TrustStore {
    /// creates an empty trust store NW120700.
    ///
    /// seed the anchor set with [TrustStore::load_genesis_anchors] before any
    /// non-genesis checkpoint will verify.
    ///
    /// returns the new [TrustStore].
    /// errors [Error::InternalAlloc] when allocation fails.
    pub fn new() -> Result<TrustStore> {
        // SAFETY: nwep_trust_store_create takes no arguments; the returned pointer is null-checked below.
        let raw = unsafe { sys::nwep_trust_store_create() };
        if raw.is_null() {
            return Err(Error::InternalAlloc);
        }
        Ok(TrustStore { raw })
    }

    /// seeds the anchor set with the genesis anchor bls pubkeys NW121100.
    ///
    /// returns unit on success.
    /// errors [Error::TrustInvalidAnchor] when a pubkey is malformed.
    pub fn load_genesis_anchors(&mut self, pubkeys: &[[u8; 48]]) -> Result<()> {
        let n = pubkeys.len();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_trust_store_load_genesis_anchors(self.raw, pubkeys.as_ptr().cast::<u8>(), n)
        })
    }

    /// installs a checkpoint, returning its staleness band NW120700.
    ///
    /// runs the structural, threshold, bls-aggregate, and equivocation checks,
    /// then installs the checkpoint unless it is stale. now_secs is unix seconds.
    ///
    /// returns the installed checkpoint's [CheckpointStatus] (fresh or warning).
    /// errors [Error::TrustStaleCheckpoint] when the checkpoint is too old to
    /// install, and other trust errors when a check fails.
    pub fn update_checkpoint(
        &mut self,
        cp_bytes: &[u8],
        now_secs: i64,
    ) -> Result<CheckpointStatus> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe {
            sys::nwep_trust_store_update_checkpoint(
                self.raw,
                cp_bytes.as_ptr(),
                cp_bytes.len(),
                now_secs,
            )
        };
        if rc < 0 {
            return Err(Error::from_code(rc));
        }
        Ok(CheckpointStatus::from_code(rc))
    }

    /// verifies a checkpoint against the anchor set without installing it NW120800.
    ///
    /// runs the same structural, threshold, and bls checks as
    /// [TrustStore::update_checkpoint] but does not mutate the store or run the
    /// equivocation guard. now_secs is unix seconds.
    ///
    /// returns unit when the checkpoint is valid.
    /// errors [Error::TrustStaleCheckpoint], [Error::TrustThreshold], or
    /// [Error::CryptoVerify] when a check fails.
    pub fn verify_checkpoint(&self, cp_bytes: &[u8], now_secs: i64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_checkpoint_verify(self.raw, cp_bytes.as_ptr(), cp_bytes.len(), now_secs)
        })
    }

    /// advances the rollback counter from a non-checkpoint observation NW120700.
    ///
    /// refuses to go backwards, the rollback protection.
    ///
    /// returns unit on success.
    /// errors a trust error when the observation would roll back.
    pub fn observe_log_size(&mut self, observed: u64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_trust_store_observe_log_size(self.raw, observed) })
    }

    /// returns the current rollback-protection counter, 0 for a fresh store.
    pub fn max_log_size(&self) -> u64 {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_trust_store_max_log_size(self.raw) }
    }

    /// serializes the rollback-critical state for persistence NW121000.
    ///
    /// covers the max log size, the equivocation history, and the installed
    /// checkpoint, but not the anchor set, reload genesis anchors after a
    /// [TrustStore::load].
    ///
    /// returns the serialized state bytes.
    /// errors [Error::Internal] when serialization fails.
    pub fn save(&self) -> Result<Vec<u8>> {
        let mut len = 0usize;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_trust_store_save(self.raw, ptr::null_mut(), &mut len) })?;
        let mut out = vec![0u8; len];
        // SAFETY: buf is sized to len as returned by the probe call above.
        Error::check(unsafe { sys::nwep_trust_store_save(self.raw, out.as_mut_ptr(), &mut len) })?;
        out.truncate(len);
        Ok(out)
    }

    /// restores state written by [TrustStore::save] NW121000.
    ///
    /// replaces the max log size, equivocation history, and checkpoint. on
    /// malformed input the store is left unchanged.
    ///
    /// returns unit on success.
    /// errors [Error::ProtoInvalidMessage] when the bytes are malformed.
    pub fn load(&mut self, bytes: &[u8]) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_trust_store_load(self.raw, bytes.as_ptr(), bytes.len()) })
    }

    /// checks a node's revocation status over a connected log-server client NW120800.
    ///
    /// issues a read of the node's revocation record on client and validates the
    /// server's signed answer, whose server-id must match the connection's
    /// authenticated peer. advances the rollback counter on a clean assertion.
    /// recovery_commitment is the node's key-binding commitment, needed to verify
    /// a revocation proof, pass none to treat any revocation as an error.
    /// now_secs is unix seconds.
    ///
    /// returns [KeyStatus::NotRevoked] or [KeyStatus::Revoked].
    /// errors a network error, [Error::CryptoVerify] on a bad signature, or a
    /// rollback error when the log appears to have shrunk.
    pub fn verify_key(
        &mut self,
        client: &Client,
        node_id: &NodeId,
        recovery_commitment: Option<&[u8; 32]>,
        now_secs: i64,
    ) -> Result<KeyStatus> {
        let commit_ptr = recovery_commitment.map_or(ptr::null(), |c| c.as_ptr());
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe {
            sys::nwep_trust_store_verify_key(
                self.raw,
                client.as_ptr(),
                node_id.raw().bytes.as_ptr(),
                commit_ptr,
                now_secs,
            )
        };
        match rc {
            0 => Ok(KeyStatus::NotRevoked),
            1 => Ok(KeyStatus::Revoked),
            other => Err(Error::from_code(other)),
        }
    }

    /// verifies a node's key-binding bundle against the installed checkpoint NW120800.
    ///
    /// the foundational check, this node_id's key is in the trust log under a
    /// checkpoint i trust. bundle is the key-binding entry followed by its merkle
    /// inclusion proof (the entry from read /log/entry/{idx} and the proof from
    /// read /log/proof/{idx}). now_secs is unix seconds.
    ///
    /// returns unit when the binding is valid.
    /// errors [Error::TrustNoCheckpoint] with no installed checkpoint,
    /// [Error::IdentityMismatch] when the key does not match, and
    /// [Error::CryptoVerify] when the proof or signature is bad.
    pub fn verify_key_binding(
        &self,
        node_id: &NodeId,
        expected_pubkey: &[u8; 32],
        bundle: &[u8],
        now_secs: i64,
    ) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_trust_store_verify_key_binding(
                self.raw,
                node_id.raw().bytes.as_ptr(),
                expected_pubkey.as_ptr(),
                bundle.as_ptr(),
                bundle.len(),
                now_secs,
            )
        })
    }

    /// applies a quorum-signed anchor-change entry to the anchor set NW120300.
    ///
    /// decodes the entry, verifies a quorum of current members signed it, then
    /// adds or removes the anchor. the caller must already have checked the
    /// entry's node_id against a current key-binding. current_epoch stamps an
    /// added anchor.
    ///
    /// returns unit when applied.
    /// errors [Error::TrustThreshold] without a signing quorum, and
    /// [Error::TrustInvalidEntry] when the entry is malformed.
    pub fn apply_anchor_change(&mut self, entry: &[u8], current_epoch: u64) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_trust_store_apply_anchor_change(
                self.raw,
                entry.as_ptr(),
                entry.len(),
                current_epoch,
            )
        })
    }

    /// borrows the raw c trust store handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_trust_store {
        self.raw
    }
}

impl Drop for TrustStore {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_trust_store_free(self.raw) };
    }
}
