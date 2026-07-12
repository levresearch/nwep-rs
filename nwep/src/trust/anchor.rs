//! nwep anchor node, the checkpoint signer of the trust layer NW120900.
//!
//! AnchorNode is a member of the anchor quorum. each epoch it signs the verified
//! merkle log root as a partial signature, and a coordinator aggregates a quorum
//! of partials into a checkpoint with [finish_checkpoint]. this slice covers the
//! local production ceremony, the networked respond and request sides are added
//! later.

use crate::error::{Error, Result};
use crate::identity::{Identity, NodeId};
use crate::trust::bls::{BlsKeypair, SIGNATURE_SIZE};
use core::ptr;
use core::time::Duration;
use nwep_sys as sys;

/// PartialSig is one anchor's contribution to a checkpoint, its share index and
/// 96 byte bls signature NW120600.
#[derive(Clone, Copy)]
pub struct PartialSig {
    index: u8,
    sig: [u8; SIGNATURE_SIZE],
}

impl PartialSig {
    /// returns the 1-based anchor share index this partial came from.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// borrows the 96 byte partial signature.
    pub fn signature(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.sig
    }
}

/// AnchorNode is a quorum member that signs checkpoints NW120900.
///
/// it owns c state and is single threaded. like the log server it may be moved
/// once into a server handler the managed runtime relocates to its owner thread,
/// so it is Send (not Sync), the move-once, never-aliased contract NWG0600.
pub struct AnchorNode {
    raw: *mut sys::nwep_anchor_node,
}

// move-once into a handler, never accessed from two threads at once NWG0600.
unsafe impl Send for AnchorNode {}

impl AnchorNode {
    /// creates an anchor from its web/1 identity and bls share NW120900.
    ///
    /// share_index is the anchor's 1-based position in the ordered anchor set.
    /// collection_window is how long a coordinator gathers partials (NW120900, default 55 minutes).
    ///
    /// returns the new [AnchorNode].
    /// errors [Error::ConfigInvalid] when the keys or share index are unusable.
    pub fn new(
        identity: &Identity,
        bls: &BlsKeypair,
        share_index: u8,
        collection_window: Duration,
    ) -> Result<AnchorNode> {
        let window_ms = collection_window.as_millis().min(u64::MAX as u128) as u64;
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let raw = identity.with_raw_keys(|pk, sk| unsafe {
            sys::nwep_anchor_node_create(
                pk,
                sk,
                bls.secret().as_ptr(),
                bls.public_key().as_ptr(),
                share_index as u64,
                window_ms,
            )
        });
        if raw.is_null() {
            return Err(Error::ConfigInvalid);
        }
        Ok(AnchorNode { raw })
    }

    /// records a verified log root the anchor will sign over for an epoch NW120900.
    ///
    /// the anchor refuses to sign an epoch whose root it has not collected.
    /// server_root and server_log_size are the fetched snapshot, local_root is
    /// the anchor's own replica, they must match.
    ///
    /// returns unit on success.
    /// errors [Error::TrustFatalLogCorrupt] when the server and local roots disagree.
    pub fn collect_log_root(
        &mut self,
        epoch: u64,
        server_root: &[u8; 32],
        server_log_size: u64,
        local_root: &[u8; 32],
    ) -> Result<()> {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_anchor_node_collect_log_root(
                self.raw,
                epoch,
                server_root.as_ptr(),
                server_log_size,
                local_root.as_ptr(),
            )
        })
    }

    /// produces this anchor's own partial signature for an epoch NW120600.
    ///
    /// the epoch's root must have been recorded with [AnchorNode::collect_log_root]
    /// first.
    ///
    /// returns this anchor's [PartialSig].
    /// errors [Error::TrustInvalidEntry] when the epoch's root was not collected.
    pub fn produce_partial_sig(
        &mut self,
        epoch: u64,
        merkle_root: &[u8; 32],
        log_size: u64,
    ) -> Result<PartialSig> {
        let mut index = 0u8;
        let mut sig = [0u8; SIGNATURE_SIZE];
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_anchor_node_produce_partial_sig(
                self.raw,
                epoch,
                merkle_root.as_ptr(),
                log_size,
                &mut index,
                sig.as_mut_ptr(),
            )
        })?;
        Ok(PartialSig { index, sig })
    }

    /// answers a peer's read /anchor/partial-sig request from a handler NW120900.
    ///
    /// call it first in a server handler with the request's authenticated peer
    /// node_id ([crate::Request::peer_node_id]) and the anchor set's node_ids. on
    /// an anchor route it writes the partial-signature response and returns
    /// [crate::DispatchOutcome::Handled]; otherwise it hands the responder back so
    /// the app can answer its own routes.
    pub fn dispatch(
        &mut self,
        requester: &NodeId,
        anchor_ids: &[NodeId],
        req: &crate::Request,
        res: crate::Responder,
        now_secs: i64,
    ) -> crate::DispatchOutcome {
        // pack the anchor set's node_ids contiguously for the c call.
        let mut ids = Vec::with_capacity(anchor_ids.len() * 32);
        for id in anchor_ids {
            ids.extend_from_slice(id.as_bytes());
        }
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe {
            sys::nwep_anchor_node_dispatch(
                self.raw,
                requester.raw().bytes.as_ptr(),
                ids.as_ptr(),
                anchor_ids.len(),
                req.raw_msg(),
                res.raw_buf(),
                now_secs,
            )
        };
        if rc == 1 {
            crate::DispatchOutcome::NotMine(res)
        } else {
            crate::DispatchOutcome::Handled(res.finish(rc))
        }
    }

    /// borrows the raw c anchor handle, the escape hatch to the sys layer NWG0200.
    pub fn as_ptr(&self) -> *mut sys::nwep_anchor_node {
        self.raw
    }
}

/// requests one peer anchor's partial signature over a client and verifies it NW120900.
///
/// the coordinator side, dial a peer anchor and ask for its partial over the
/// epoch root, checking it against peer_bls_pubkey before returning. pair the
/// results with [finish_checkpoint].
///
/// returns the peer's [PartialSig].
/// errors [Error::AppForbidden] when the peer declines, and [Error::CryptoVerify]
/// on a bad signature.
pub fn request_partial_sig(
    client: &crate::Client,
    epoch: u64,
    merkle_root: &[u8; 32],
    log_size: u64,
    peer_bls_pubkey: &[u8; 48],
) -> Result<PartialSig> {
    let mut index = 0u8;
    let mut sig = [0u8; SIGNATURE_SIZE];
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    Error::check(unsafe {
        sys::nwep_anchor_request_partial_sig(
            client.as_ptr(),
            epoch,
            merkle_root.as_ptr(),
            log_size,
            peer_bls_pubkey.as_ptr(),
            &mut index,
            sig.as_mut_ptr(),
        )
    })?;
    Ok(PartialSig { index, sig })
}

impl Drop for AnchorNode {
    fn drop(&mut self) {
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_anchor_node_free(self.raw) };
    }
}

/// aggregates gathered partials into a checkpoint for publication NW120900.
///
/// the coordinator step, a quorum of partials over the same epoch root becomes
/// the single checkpoint a node installs. each partial's [PartialSig::index] is
/// 1-based into the ordered anchor_bls_pubkeys. two-call sizing is hidden.
///
/// returns the encoded checkpoint bytes.
/// errors [Error::ConfigInvalid] on empty input, and [Error::TrustThreshold]
/// when too few partials are supplied for the quorum.
pub fn finish_checkpoint(
    epoch: u64,
    merkle_root: &[u8; 32],
    log_size: u64,
    partials: &[PartialSig],
    anchor_bls_pubkeys: &[[u8; 48]],
) -> Result<Vec<u8>> {
    if partials.is_empty() || anchor_bls_pubkeys.is_empty() {
        return Err(Error::ConfigInvalid);
    }
    let mut indices = Vec::with_capacity(partials.len());
    let mut sigs = Vec::with_capacity(partials.len() * SIGNATURE_SIZE);
    for p in partials {
        indices.push(p.index);
        sigs.extend_from_slice(&p.sig);
    }

    let mut len = 0usize;
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    let call = |out: *mut u8, len: *mut usize| unsafe {
        sys::nwep_anchor_finish_checkpoint(
            epoch,
            merkle_root.as_ptr(),
            log_size,
            indices.as_ptr(),
            sigs.as_ptr(),
            partials.len(),
            anchor_bls_pubkeys.as_ptr().cast::<u8>(),
            anchor_bls_pubkeys.len(),
            out,
            len,
        )
    };
    Error::check(call(ptr::null_mut(), &mut len))?;
    let mut out = vec![0u8; len];
    Error::check(call(out.as_mut_ptr(), &mut len))?;
    out.truncate(len);
    Ok(out)
}
