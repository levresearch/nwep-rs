// key-rotation acceptance, the trust check that decides whether a presented key
// is currently valid for a rotated node NW120800. only built with the trust
// feature. the new key is always acceptable, the old key only within its overlap
// window.
#![cfg(feature = "trust")]

use nwep::log;
use nwep::trust::evaluate_key_rotation;
use nwep::Identity;

const TS: u64 = 1_700_000_000;
const OVERLAP: u64 = 1000;

#[test]
fn old_key_is_accepted_within_overlap_then_revoked() {
    let node = Identity::generate().unwrap();
    let new_key = Identity::generate().unwrap();
    let rotation = log::key_rotation(node.node_id(), &node, &new_key, TS, TS + OVERLAP).unwrap();

    let now = (TS + 1) as i64;
    let after = (TS + OVERLAP + 1) as i64;

    // the new key is acceptable.
    assert!(evaluate_key_rotation(&rotation, new_key.public_key(), now).is_ok());
    // the old key is acceptable inside the overlap window,
    assert!(evaluate_key_rotation(&rotation, node.public_key(), now).is_ok());
    // but rejected once the overlap has expired.
    assert!(evaluate_key_rotation(&rotation, node.public_key(), after).is_err());
    // a key that is neither the old nor the new one is rejected.
    let stranger = Identity::generate().unwrap();
    assert!(evaluate_key_rotation(&rotation, stranger.public_key(), now).is_err());
}
