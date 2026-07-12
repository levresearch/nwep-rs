//! nwep trust-log entries and the merkle log NW120200 NW120300.
//!
//! the producer and decoder side of the identity lifecycle, ed25519 only so it
//! lives in core (no bls, no trust feature). a node builds its own signed
//! [key_binding], [key_rotation], and [revocation] entries to submit to a log,
//! decodes entries it reads back, and a [Log] hashes appended entries into a
//! merkle root. verifying others' entries against a checkpoint is the trust
//! layer's job ([crate::trust]).

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use core::ptr;
use nwep_sys as sys;

// entry types NW120300

/// EntryType is which kind of trust-log entry a byte blob is NW120300.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryType {
    /// a key binding, registering a node's key NW120300.
    KeyBinding,
    /// a key rotation, replacing a node's key NW120300.
    KeyRotation,
    /// a revocation, retiring a compromised key NW120300.
    Revocation,
    /// an anchor change, adding or removing a quorum member NW120300.
    AnchorChange,
}

impl EntryType {
    /// reads the type of an encoded log entry from its leading byte NW120300.
    ///
    /// returns the [EntryType].
    /// errors [Error::ProtoInvalidMessage] on an unknown type byte, and
    /// [Error::Internal] on an empty buffer.
    pub fn of(bytes: &[u8]) -> Result<EntryType> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_log_entry_type(bytes.as_ptr(), bytes.len()) };
        match rc {
            sys::NWEP_ENTRY_KEY_BINDING => Ok(EntryType::KeyBinding),
            sys::NWEP_ENTRY_KEY_ROTATION => Ok(EntryType::KeyRotation),
            sys::NWEP_ENTRY_REVOCATION => Ok(EntryType::Revocation),
            sys::NWEP_ENTRY_ANCHOR_CHANGE => Ok(EntryType::AnchorChange),
            other => Err(Error::from_code(other)),
        }
    }
}

/// RevocationReason is why a key was revoked NW120300.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    /// the key was compromised.
    Compromised,
    /// the key was rotated out.
    Rotation,
    /// the node was decommissioned.
    Decommission,
}

impl RevocationReason {
    fn code(self) -> u8 {
        match self {
            RevocationReason::Compromised => 1,
            RevocationReason::Rotation => 2,
            RevocationReason::Decommission => 3,
        }
    }

    fn from_code(code: u8) -> Option<RevocationReason> {
        match code {
            1 => Some(RevocationReason::Compromised),
            2 => Some(RevocationReason::Rotation),
            3 => Some(RevocationReason::Decommission),
            _ => None,
        }
    }
}

// decoded entry views NW120300

/// KeyBinding is a decoded key-binding entry, parse only, no signature check NW120300.
#[derive(Clone, Copy, Debug)]
pub struct KeyBinding {
    /// the node this entry binds a key to.
    pub node_id: NodeId,
    /// the ed25519 public key being registered.
    pub pubkey: [u8; 32],
    /// sha-256 of the offline recovery key.
    pub recovery_commitment: [u8; 32],
    /// unix-seconds timestamp.
    pub timestamp: u64,
}

impl KeyBinding {
    /// decodes a key-binding entry NW120300.
    ///
    /// returns the decoded [KeyBinding].
    /// errors [Error::ProtoInvalidMessage] on the wrong type or a short buffer.
    pub fn decode(bytes: &[u8]) -> Result<KeyBinding> {
        let mut out = core::mem::MaybeUninit::<sys::nwep_keybinding>::zeroed();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_keybinding_decode(bytes.as_ptr(), bytes.len(), out.as_mut_ptr())
        })?;
        // SAFETY: nwep_keybinding_decode returned 0, guaranteeing the struct is fully written.
        let kb = unsafe { out.assume_init() };
        Ok(KeyBinding {
            node_id: NodeId::from_bytes(kb.node_id),
            pubkey: kb.pubkey,
            recovery_commitment: kb.recovery_commitment,
            timestamp: kb.timestamp,
        })
    }
}

/// KeyRotation is a decoded key-rotation entry, parse only NW120300.
#[derive(Clone, Copy, Debug)]
pub struct KeyRotation {
    /// the node rotating its key.
    pub node_id: NodeId,
    /// the key being retired.
    pub old_pubkey: [u8; 32],
    /// the key taking over.
    pub new_pubkey: [u8; 32],
    /// unix-seconds timestamp.
    pub timestamp: u64,
    /// unix-seconds cutoff after which the old key is rejected.
    pub overlap_expiry: u64,
}

impl KeyRotation {
    /// decodes a key-rotation entry NW120300.
    ///
    /// returns the decoded [KeyRotation].
    /// errors [Error::ProtoInvalidMessage] on the wrong type or a short buffer.
    pub fn decode(bytes: &[u8]) -> Result<KeyRotation> {
        let mut out = core::mem::MaybeUninit::<sys::nwep_keyrotation>::zeroed();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_keyrotation_decode(bytes.as_ptr(), bytes.len(), out.as_mut_ptr())
        })?;
        // SAFETY: nwep_keyrotation_decode returned 0, guaranteeing the struct is fully written.
        let kr = unsafe { out.assume_init() };
        Ok(KeyRotation {
            node_id: NodeId::from_bytes(kr.node_id),
            old_pubkey: kr.old_pubkey,
            new_pubkey: kr.new_pubkey,
            timestamp: kr.timestamp,
            overlap_expiry: kr.overlap_expiry,
        })
    }
}

/// Revocation is a decoded revocation entry, parse only NW120300.
#[derive(Clone, Copy, Debug)]
pub struct Revocation {
    /// the node retiring a key.
    pub node_id: NodeId,
    /// the key being revoked.
    pub revoked_pubkey: [u8; 32],
    /// the offline recovery key that signed this revocation.
    pub recovery_pubkey: [u8; 32],
    /// why the key was revoked, or none for an unknown code.
    pub reason: Option<RevocationReason>,
    /// unix-seconds timestamp.
    pub timestamp: u64,
}

impl Revocation {
    /// decodes a revocation entry NW120300.
    ///
    /// returns the decoded [Revocation].
    /// errors [Error::ProtoInvalidMessage] on the wrong type or a short buffer.
    pub fn decode(bytes: &[u8]) -> Result<Revocation> {
        let mut out = core::mem::MaybeUninit::<sys::nwep_revocation>::zeroed();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_revocation_decode(bytes.as_ptr(), bytes.len(), out.as_mut_ptr())
        })?;
        // SAFETY: nwep_revocation_decode returned 0, guaranteeing the struct is fully written.
        let r = unsafe { out.assume_init() };
        Ok(Revocation {
            node_id: NodeId::from_bytes(r.node_id),
            revoked_pubkey: r.revoked_pubkey,
            recovery_pubkey: r.recovery_pubkey,
            reason: RevocationReason::from_code(r.reason),
            timestamp: r.timestamp,
        })
    }
}

// entry creation NW120300

/// runs a two-call-sizing producer, returning the encoded entry bytes.
fn produce(mut call: impl FnMut(*mut u8, *mut usize) -> i32) -> Result<Vec<u8>> {
    let mut len = 0usize;
    Error::check(call(ptr::null_mut(), &mut len))?;
    let mut out = vec![0u8; len];
    Error::check(call(out.as_mut_ptr(), &mut len))?;
    out.truncate(len);
    Ok(out)
}

/// builds a node's signed key-binding entry, ready to submit to a log NW120300.
///
/// registers identity's key under the node_id derived from it.
/// recovery_commitment is sha-256 of the offline recovery key.
///
/// returns the 169-byte encoded entry.
/// errors [Error::CryptoSign] when signing fails.
pub fn key_binding(
    identity: &Identity,
    recovery_commitment: &[u8; 32],
    timestamp: u64,
) -> Result<Vec<u8>> {
    identity.with_raw_keys(|pk, sk| {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        produce(|out, len| unsafe {
            sys::nwep_keybinding_create(pk, recovery_commitment.as_ptr(), timestamp, sk, out, len)
        })
    })
}

/// builds a node's signed key-rotation entry from old to new NW120300.
///
/// signed by both keys. overlap_expiry is the unix-seconds cutoff after which the
/// old key is rejected.
///
/// returns the 241-byte encoded entry.
/// errors [Error::CryptoSign] when signing fails.
pub fn key_rotation(
    node_id: &NodeId,
    old: &Identity,
    new: &Identity,
    timestamp: u64,
    overlap_expiry: u64,
) -> Result<Vec<u8>> {
    let nid = node_id.raw();
    old.with_raw_keys(|old_pk, old_sk| {
        new.with_raw_keys(|new_pk, new_sk| {
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            produce(|out, len| unsafe {
                sys::nwep_keyrotation_create(
                    nid.bytes.as_ptr(),
                    old_pk,
                    new_pk,
                    timestamp,
                    overlap_expiry,
                    old_sk,
                    new_sk,
                    out,
                    len,
                )
            })
        })
    })
}

/// builds a signed revocation entry for a node's key NW120300.
///
/// signed by the offline recovery identity, whose public key is carried in the
/// entry.
///
/// returns the 170-byte encoded entry.
/// errors [Error::CryptoSign] when signing fails.
pub fn revocation(
    node_id: &NodeId,
    revoked_pubkey: &[u8; 32],
    recovery: &Identity,
    reason: RevocationReason,
    timestamp: u64,
) -> Result<Vec<u8>> {
    let nid = node_id.raw();
    recovery.with_raw_keys(|rec_pk, rec_sk| {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        produce(|out, len| unsafe {
            sys::nwep_revocation_create(
                nid.bytes.as_ptr(),
                revoked_pubkey.as_ptr(),
                rec_pk,
                reason.code(),
                timestamp,
                rec_sk,
                out,
                len,
            )
        })
    })
}

// merkle log NW120200

/// Log is an in-memory append-only merkle log of trust entries NW120200.
///
/// it hashes each appended entry as a leaf and exposes the rolling merkle root,
/// so an operator can checkpoint its own log without reading it back over the
/// wire. it owns c state, so it is !Send and !Sync NWG0900.
pub struct Log {
    raw: *mut sys::nwep_log,
}

impl Log {
    /// creates an empty merkle log NW120200.
    ///
    /// returns the new [Log].
    /// errors [Error::InternalAlloc] when allocation fails.
    pub fn new() -> Result<Log> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let raw = unsafe { sys::nwep_log_create() };
        if raw.is_null() {
            return Err(Error::InternalAlloc);
        }
        Ok(Log { raw })
    }

    /// appends a raw entry as a merkle leaf, returning its index NW120200.
    ///
    /// the entry is hashed as-is with no structural validation at this layer.
    ///
    /// returns the new entry's index.
    /// errors a protocol [Error] when the append fails.
    pub fn append(&mut self, entry: &[u8]) -> Result<u64> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_log_append(self.raw, entry.as_ptr(), entry.len()) };
        if rc < 0 {
            return Err(Error::from_code(rc as core::ffi::c_int));
        }
        Ok(rc as u64)
    }

    /// returns the number of entries in the log.
    pub fn len(&self) -> u64 {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_log_size(self.raw) }
    }

    /// returns true when the log has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// returns the log's current 32-byte merkle root NW120200.
    ///
    /// returns the root.
    /// errors [Error::Internal] when the handle is unusable.
    pub fn root(&self) -> Result<[u8; 32]> {
        let mut root = [0u8; 32];
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_log_root(self.raw, root.as_mut_ptr()) })?;
        Ok(root)
    }

    /// borrows the raw c log handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_log {
        self.raw
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_log_free(self.raw) };
    }
}
