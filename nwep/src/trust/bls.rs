//! nwep bls threshold signatures, the anchor signing primitive NW120500.
//!
//! anchors co-sign each merkle checkpoint with bls12-381, so a quorum's separate
//! signatures aggregate into one that verifies against their public keys. this
//! module is the building block, a [BlsKeypair] to sign, free [verify],
//! [aggregate], and [verify_aggregate] over a shared message. it requires the "trust" feature and links blst.

use crate::error::{Error, Result};
use core::fmt;
use nwep_sys as sys;

/// the byte length of a bls public key NW120500.
pub const PUBKEY_SIZE: usize = sys::NWEP_BLS_PUBKEY_SIZE;
/// the byte length of a bls signature NW120500.
pub const SIGNATURE_SIZE: usize = sys::NWEP_BLS_SIGNATURE_SIZE;

/// BlsSignature is a 96 byte bls12-381 signature, single or aggregate NW120500.
///
/// it is transparent over its bytes, so a slice of signatures is already the
/// contiguous form [aggregate] wants.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BlsSignature(pub [u8; SIGNATURE_SIZE]);

impl BlsSignature {
    /// borrows the raw 96 signature bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// wraps 96 raw bytes as a signature.
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> BlsSignature {
        BlsSignature(bytes)
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSignature(96 bytes)")
    }
}

/// BlsKeypair is a bls12-381 secret and public key for anchor signing NW120500.
///
/// the secret key is wiped on drop NWG0700. an anchor holds one and contributes
/// a partial signature to each checkpoint quorum.
pub struct BlsKeypair {
    secret: [u8; sys::NWEP_BLS_SECKEY_SIZE],
    public: [u8; PUBKEY_SIZE],
}

impl BlsKeypair {
    /// generates a fresh bls keypair from the system csprng NW120500.
    ///
    /// returns the new [BlsKeypair].
    /// errors [Error::CryptoKeygen] when key generation fails.
    pub fn generate() -> Result<BlsKeypair> {
        let mut secret = [0u8; sys::NWEP_BLS_SECKEY_SIZE];
        let mut public = [0u8; PUBKEY_SIZE];
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_bls_keygen(secret.as_mut_ptr(), public.as_mut_ptr()) })?;
        Ok(BlsKeypair { secret, public })
    }

    /// signs msg under this key with the checkpoint domain tag NW120500.
    ///
    /// returns the [BlsSignature].
    /// errors [Error::CryptoSign] when signing fails.
    pub fn sign(&self, msg: &[u8]) -> Result<BlsSignature> {
        let mut sig = [0u8; SIGNATURE_SIZE];
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_bls_sign(
                sig.as_mut_ptr(),
                self.secret.as_ptr(),
                msg.as_ptr(),
                msg.len(),
            )
        })?;
        Ok(BlsSignature(sig))
    }

    /// borrows this keypair's 48 byte public key.
    pub fn public_key(&self) -> &[u8; PUBKEY_SIZE] {
        &self.public
    }

    /// borrows the 32 byte secret key, for the genesis ceremony NW121100.
    ///
    /// crate internal, the genesis checkpoint is the only consumer that needs the
    /// founding secret keys, and it zeroizes its own copy after use.
    pub(crate) fn secret(&self) -> &[u8; sys::NWEP_BLS_SECKEY_SIZE] {
        &self.secret
    }
}

impl Drop for BlsKeypair {
    fn drop(&mut self) {
        // the secret key is key material, wipe it through the library so the
        // write is not elided NWG0700.
        // SAFETY: the slice pointer and length are consistent.
        unsafe { sys::nwep_zeroize(self.secret.as_mut_ptr().cast(), self.secret.len()) };
    }
}

impl fmt::Debug for BlsKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never print the secret key.
        f.debug_struct("BlsKeypair").finish_non_exhaustive()
    }
}

/// verifies a single-signer bls signature over msg under public NW120500.
///
/// returns true when the signature is valid.
pub fn verify(sig: &BlsSignature, public: &[u8; PUBKEY_SIZE], msg: &[u8]) -> bool {
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    unsafe { sys::nwep_bls_verify(sig.0.as_ptr(), public.as_ptr(), msg.as_ptr(), msg.len()) == 0 }
}

/// aggregates several bls signatures over the same message into one NW120500.
///
/// the quorum step, each anchor's partial signature combines into the single
/// signature a checkpoint carries.
///
/// returns the aggregate [BlsSignature].
/// errors [Error::CryptoSign] when aggregation fails, and [Error::ConfigInvalid]
/// for an empty input.
pub fn aggregate(sigs: &[BlsSignature]) -> Result<BlsSignature> {
    if sigs.is_empty() {
        return Err(Error::ConfigInvalid);
    }
    let mut out = [0u8; SIGNATURE_SIZE];
    // BlsSignature is transparent over [u8; 96], so the slice is already the
    // contiguous buffer the c side expects.
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    Error::check(unsafe {
        sys::nwep_bls_aggregate(out.as_mut_ptr(), sigs.as_ptr().cast::<u8>(), sigs.len())
    })?;
    Ok(BlsSignature(out))
}

/// verifies an aggregate signature against many pubkeys over one message NW120500.
///
/// every public key must have signed the same msg, the checkpoint case.
///
/// returns true when the aggregate is valid for all the pubkeys.
pub fn verify_aggregate(agg: &BlsSignature, publics: &[[u8; PUBKEY_SIZE]], msg: &[u8]) -> bool {
    if publics.is_empty() {
        return false;
    }
    // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
    unsafe {
        sys::nwep_bls_verify_aggregate(
            agg.0.as_ptr(),
            publics.as_ptr().cast::<u8>(),
            publics.len(),
            msg.as_ptr(),
            msg.len(),
        ) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let kp = BlsKeypair::generate().unwrap();
        let msg = b"epoch 7 merkle root";
        let sig = kp.sign(msg).unwrap();
        assert!(verify(&sig, kp.public_key(), msg));
        // a tampered message does not verify.
        assert!(!verify(&sig, kp.public_key(), b"epoch 8 merkle root"));
    }

    #[test]
    fn threshold_aggregate_verifies() {
        let signers: Vec<BlsKeypair> = (0..3).map(|_| BlsKeypair::generate().unwrap()).collect();
        let msg = b"checkpoint quorum";
        let sigs: Vec<BlsSignature> = signers.iter().map(|s| s.sign(msg).unwrap()).collect();
        let agg = aggregate(&sigs).unwrap();
        let pks: Vec<[u8; PUBKEY_SIZE]> = signers.iter().map(|s| *s.public_key()).collect();
        assert!(verify_aggregate(&agg, &pks, msg));
        // a different message fails against the same aggregate.
        assert!(!verify_aggregate(&agg, &pks, b"other root"));
    }

    #[test]
    fn empty_inputs_are_rejected() {
        assert!(aggregate(&[]).is_err());
        let kp = BlsKeypair::generate().unwrap();
        let sig = kp.sign(b"x").unwrap();
        assert!(!verify_aggregate(&sig, &[], b"x"));
    }
}
