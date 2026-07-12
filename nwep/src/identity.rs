//! nwep identity and nodeid, the cryptographic identity layer NW040200 NW090500.
//!
//! Identity is an ed25519 keypair plus the NodeId derived from it, and is what a
//! server or client proves ownership of during the handshake. NodeId is the 32
//! byte sha-256(pubkey + "WEB/1") that names a node on the network and in the
//! dht. NodeId is a plain value, cheap to copy and safe to share across threads.
//! Identity holds a private key, so it zeroizes it on drop NWG0700.

use crate::error::{Error, Result};
use core::ffi::c_char;
use core::fmt;
use core::str::FromStr;
use nwep_sys as sys;

// nodeid NW040200

/// NodeId is the 32 byte sha-256 identity that names a node NW040200.
///
/// it is the public half of an [Identity] and the key the dht resolves to an
/// address. it is just bytes, so it is Copy and Send.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; sys::NWEP_NODEID_SIZE]);

impl NodeId {
    /// derives the node_id of an ed25519 public key, sha-256(pubkey + "WEB/1").
    ///
    /// recovers the name of a key whose raw bytes do not carry it, for example
    /// one loaded with [Identity::from_pem] NW040200.
    ///
    /// returns the derived [NodeId].
    /// errors [Error::CryptoSign] when the underlying sha-256 hash fails (very rare).
    pub fn from_pubkey(pubkey: &[u8; sys::NWEP_PUBKEY_SIZE]) -> Result<NodeId> {
        let mut out = sys::nwep_node_id {
            bytes: [0; sys::NWEP_NODEID_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_nodeid_from_pubkey(&mut out, pubkey.as_ptr()) })?;
        Ok(NodeId(out.bytes))
    }

    /// parses a base58 node_id string.
    ///
    /// the inverse of [NodeId::to_base58]. also available through [FromStr].
    ///
    /// returns the decoded [NodeId].
    /// errors [Error::ProtoInvalidHeader] when s is not valid base58 of a 32 byte id.
    pub fn from_base58(s: &str) -> Result<NodeId> {
        let mut out = sys::nwep_node_id {
            bytes: [0; sys::NWEP_NODEID_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_nodeid_from_base58(&mut out, s.as_ptr().cast::<c_char>(), s.len())
        })?;
        Ok(NodeId(out.bytes))
    }

    /// encodes this node_id as a base58 string.
    ///
    /// a 32 byte id is at most 44 base58 characters, so this never fails. also
    /// available through [fmt::Display].
    pub fn to_base58(&self) -> String {
        let id = sys::nwep_node_id { bytes: self.0 };
        let mut buf = [0u8; 64];
        let mut len = buf.len();
        // out is non null and the buffer always fits, so this cannot error.
        let rc =
            // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
            unsafe { sys::nwep_nodeid_to_base58(buf.as_mut_ptr().cast::<c_char>(), &mut len, &id) };
        debug_assert_eq!(
            rc, 0,
            "nodeid base58 encode should not fail into a 64 byte buffer"
        );
        String::from_utf8_lossy(&buf[..len]).into_owned()
    }

    /// checks that pubkey is the key this node_id was derived from NW040200.
    ///
    /// constant time, so it leaks nothing about the comparison.
    ///
    /// returns true when node_id equals sha-256(pubkey + "WEB/1").
    pub fn verify(&self, pubkey: &[u8; sys::NWEP_PUBKEY_SIZE]) -> bool {
        let id = sys::nwep_node_id { bytes: self.0 };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        unsafe { sys::nwep_nodeid_verify(&id, pubkey.as_ptr()) == 0 }
    }

    /// borrows the raw 32 identity bytes.
    pub fn as_bytes(&self) -> &[u8; sys::NWEP_NODEID_SIZE] {
        &self.0
    }

    /// wraps 32 raw bytes as a node_id without checking they name a real key.
    pub fn from_bytes(bytes: [u8; sys::NWEP_NODEID_SIZE]) -> NodeId {
        NodeId(bytes)
    }

    /// builds the raw c node_id, for handing to a lower layer.
    pub(crate) fn raw(&self) -> sys::nwep_node_id {
        sys::nwep_node_id { bytes: self.0 }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.to_base58())
    }
}

impl FromStr for NodeId {
    type Err = Error;
    fn from_str(s: &str) -> Result<NodeId> {
        NodeId::from_base58(s)
    }
}

// identity NW040200 NW090500

/// Identity is an ed25519 keypair and the [NodeId] it derives to NW040200.
///
/// it is what a server or client uses to prove ownership of its node_id in the
/// handshake NW090000. it owns a private key, which it wipes on drop NWG0700.
pub struct Identity {
    node_id: NodeId,
    pubkey: [u8; sys::NWEP_PUBKEY_SIZE],
    privkey: [u8; sys::NWEP_PRIVKEY_SIZE],
}

impl Identity {
    /// generates a fresh ed25519 identity from the system csprng.
    ///
    /// derives the node_id from the new public key NW040200, so the result is
    /// ready to bind a server or open a client.
    ///
    /// returns a new [Identity].
    /// errors [Error::CryptoKeygen] when the csprng or key generation fails.
    pub fn generate() -> Result<Identity> {
        let mut id = sys::nwep_node_id {
            bytes: [0; sys::NWEP_NODEID_SIZE],
        };
        let mut kp = sys::nwep_keypair {
            pub_: [0; sys::NWEP_PUBKEY_SIZE],
            priv_: [0; sys::NWEP_PRIVKEY_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_identity_generate(&mut id, &mut kp) })?;
        let identity = Identity {
            node_id: NodeId(id.bytes),
            pubkey: kp.pub_,
            privkey: kp.priv_,
        };
        zeroize(&mut kp.priv_);
        Ok(identity)
    }

    /// loads an identity from pkcs#8 pem bytes.
    ///
    /// decodes the keypair and re derives the node_id from its public key, since
    /// the pem carries the keys but not the name NW040200. pairs with [Identity::to_pem].
    ///
    /// returns the loaded [Identity].
    /// errors [Error::CryptoFatalCert] when the pem is malformed or not an ed25519 key.
    pub fn from_pem(pem: &str) -> Result<Identity> {
        let mut kp = sys::nwep_keypair {
            pub_: [0; sys::NWEP_PUBKEY_SIZE],
            priv_: [0; sys::NWEP_PRIVKEY_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe { sys::nwep_keypair_load_pem(&mut kp, pem.as_ptr(), pem.len()) })?;
        let mut nid = sys::nwep_node_id {
            bytes: [0; sys::NWEP_NODEID_SIZE],
        };
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let derived = unsafe { sys::nwep_nodeid_from_pubkey(&mut nid, kp.pub_.as_ptr()) };
        if let Err(e) = Error::check(derived) {
            zeroize(&mut kp.priv_);
            return Err(e);
        }
        let identity = Identity {
            node_id: NodeId(nid.bytes),
            pubkey: kp.pub_,
            privkey: kp.priv_,
        };
        zeroize(&mut kp.priv_);
        Ok(identity)
    }

    /// encodes this identity to pkcs#8 pem.
    ///
    /// the returned string contains the private key, so it is secret material and
    /// the caller is responsible for protecting and wiping it NWG0700.
    ///
    /// returns the pem text.
    /// errors [Error::Internal] when encoding fails.
    pub fn to_pem(&self) -> Result<String> {
        let mut kp = sys::nwep_keypair {
            pub_: self.pubkey,
            priv_: self.privkey,
        };
        let mut buf = vec![0u8; 4096];
        let mut len = buf.len();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let rc = unsafe { sys::nwep_keypair_save_pem(buf.as_mut_ptr(), &mut len, &kp) };
        zeroize(&mut kp.priv_);
        Error::check(rc)?;
        buf.truncate(len);
        String::from_utf8(buf).map_err(|_| Error::Internal)
    }

    /// signs msg with this identity's private key NW090500.
    ///
    /// returns the 64 byte ed25519 signature.
    /// errors [Error::CryptoSign] when signing fails.
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; sys::NWEP_SIG_SIZE]> {
        let mut sig = [0u8; sys::NWEP_SIG_SIZE];
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        Error::check(unsafe {
            sys::nwep_ed25519_sign(
                sig.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                self.privkey.as_ptr(),
            )
        })?;
        Ok(sig)
    }

    /// borrows the node_id this identity proves ownership of.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// borrows the ed25519 public key.
    pub fn public_key(&self) -> &[u8; sys::NWEP_PUBKEY_SIZE] {
        &self.pubkey
    }

    /// runs f with a temporary raw keypair, zeroizing the private copy after.
    ///
    /// the library copies the keypair internally during the call (listen,
    /// connect), so this lends a pointer for the call duration only NWG0700.
    pub(crate) fn with_keypair<R>(&self, f: impl FnOnce(*const sys::nwep_keypair) -> R) -> R {
        let mut kp = sys::nwep_keypair {
            pub_: self.pubkey,
            priv_: self.privkey,
        };
        let out = f(&kp);
        zeroize(&mut kp.priv_);
        out
    }

    /// runs f with the raw public and private key pointers, zeroizing the private
    /// copy after. for c apis that take the two keys separately (the anchor node).
    pub(crate) fn with_raw_keys<R>(&self, f: impl FnOnce(*const u8, *const u8) -> R) -> R {
        let mut secret = self.privkey;
        let out = f(self.pubkey.as_ptr(), secret.as_ptr());
        zeroize(&mut secret);
        out
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // the private key is secret material, wipe it before the memory can be
        // reused (NWG0700, via nwep_zeroize so the compiler cannot elide it).
        zeroize(&mut self.privkey);
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never print the private key.
        f.debug_struct("Identity")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

/// wipes a byte buffer of secret material through the library, which guarantees
/// the write is not optimized away NW130000 NWG0700.
fn zeroize(bytes: &mut [u8]) {
    // SAFETY: the slice pointer and length are consistent.
    unsafe { sys::nwep_zeroize(bytes.as_mut_ptr().cast(), bytes.len()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_verify_and_round_trip_base58() {
        let id = Identity::generate().unwrap();
        // the node_id is the binding of the public key.
        assert!(id.node_id().verify(id.public_key()));
        // base58 round trips exactly.
        let s = id.node_id().to_base58();
        let back = NodeId::from_base58(&s).unwrap();
        assert_eq!(&back, id.node_id());
        // and through FromStr / Display too.
        assert_eq!(s.parse::<NodeId>().unwrap(), back);
        assert_eq!(back.to_string(), s);
    }

    #[test]
    fn from_pubkey_matches_generated_node_id() {
        let id = Identity::generate().unwrap();
        let derived = NodeId::from_pubkey(id.public_key()).unwrap();
        assert_eq!(&derived, id.node_id());
    }

    #[test]
    fn verify_rejects_a_different_key() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert!(!a.node_id().verify(b.public_key()));
    }

    #[test]
    fn sign_produces_a_verifiable_signature() {
        let id = Identity::generate().unwrap();
        let msg = b"web/1 binding test";
        let sig = id.sign(msg).unwrap();
        // SAFETY: all pointers are valid references for the duration of the call; sizes match the nwep.h contract.
        let ok = unsafe {
            sys::nwep_ed25519_verify(
                sig.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                id.public_key().as_ptr(),
            )
        };
        assert_eq!(ok, 0);
    }

    #[test]
    fn pem_round_trips_to_the_same_node_id() {
        let id = Identity::generate().unwrap();
        let pem = id.to_pem().unwrap();
        let loaded = Identity::from_pem(&pem).unwrap();
        assert_eq!(loaded.node_id(), id.node_id());
        assert_eq!(loaded.public_key(), id.public_key());
    }

    #[test]
    fn bad_base58_is_an_error_not_a_crash() {
        assert!(NodeId::from_base58("not valid base58 !!!").is_err());
    }
}
