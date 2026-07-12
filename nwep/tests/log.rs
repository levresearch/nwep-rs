// trust-log entry production and the merkle log, networking free and core (no
// trust feature). mirrors the sandbox nwlog producer side: a node builds its own
// signed key-binding / rotation / revocation entries, they decode back to the
// same fields, and a merkle log hashes them into a moving root.

use nwep::log::{self, EntryType, KeyBinding, KeyRotation, Revocation, RevocationReason};
use nwep::{Identity, Log};

const COMMITMENT: [u8; 32] = [0x11; 32];
const TS: u64 = 1_700_000_000;

#[test]
fn key_binding_creates_decodes_and_logs() {
    let id = Identity::generate().unwrap();
    let entry = log::key_binding(&id, &COMMITMENT, TS).unwrap();

    // the type byte reads back as a key binding.
    assert_eq!(EntryType::of(&entry).unwrap(), EntryType::KeyBinding);

    // the decoded fields match what went in, the node_id derived from the key.
    let kb = KeyBinding::decode(&entry).unwrap();
    assert_eq!(&kb.node_id, id.node_id());
    assert_eq!(&kb.pubkey, id.public_key());
    assert_eq!(kb.recovery_commitment, COMMITMENT);
    assert_eq!(kb.timestamp, TS);

    // appending to a merkle log advances the size and moves the root.
    let mut merkle = Log::new().unwrap();
    assert!(merkle.is_empty());
    let idx = merkle.append(&entry).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(merkle.len(), 1);
    let root1 = merkle.root().unwrap();

    let second = log::key_binding(&Identity::generate().unwrap(), &COMMITMENT, TS).unwrap();
    assert_eq!(merkle.append(&second).unwrap(), 1);
    assert_eq!(merkle.len(), 2);
    assert_ne!(merkle.root().unwrap(), root1);
}

#[test]
fn key_rotation_creates_and_decodes() {
    let node = Identity::generate().unwrap();
    let new_key = Identity::generate().unwrap();
    let entry = log::key_rotation(node.node_id(), &node, &new_key, TS, TS + 1000).unwrap();

    assert_eq!(EntryType::of(&entry).unwrap(), EntryType::KeyRotation);
    let kr = KeyRotation::decode(&entry).unwrap();
    assert_eq!(&kr.node_id, node.node_id());
    assert_eq!(&kr.old_pubkey, node.public_key());
    assert_eq!(&kr.new_pubkey, new_key.public_key());
    assert_eq!(kr.overlap_expiry, TS + 1000);
}

#[test]
fn revocation_creates_and_decodes() {
    let node = Identity::generate().unwrap();
    let recovery = Identity::generate().unwrap();
    let entry = log::revocation(
        node.node_id(),
        node.public_key(),
        &recovery,
        RevocationReason::Compromised,
        TS,
    )
    .unwrap();

    assert_eq!(EntryType::of(&entry).unwrap(), EntryType::Revocation);
    let rev = Revocation::decode(&entry).unwrap();
    assert_eq!(&rev.node_id, node.node_id());
    assert_eq!(&rev.revoked_pubkey, node.public_key());
    assert_eq!(&rev.recovery_pubkey, recovery.public_key());
    assert_eq!(rev.reason, Some(RevocationReason::Compromised));
}

#[test]
fn entry_type_rejects_garbage() {
    assert!(EntryType::of(&[0xFF, 0x00, 0x00]).is_err());
}
