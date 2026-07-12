// bls threshold signatures end to end, the proof the trust feature links blst
// and the full libnwep. mirrors the sandbox nwlog anchor-signing path: three
// anchors co-sign one checkpoint root, their signatures aggregate into one, and
// it verifies against their public keys. only built with the trust feature.
#![cfg(feature = "trust")]

use nwep::trust::bls::{self, BlsKeypair};

#[test]
fn anchor_quorum_signs_and_verifies_a_checkpoint() {
    // a checkpoint root the anchors co-sign.
    let root = b"epoch 12 merkle root bytes";

    // three anchors each sign the same root.
    let anchors: Vec<BlsKeypair> = (0..3).map(|_| BlsKeypair::generate().unwrap()).collect();
    let partials: Vec<_> = anchors.iter().map(|a| a.sign(root).unwrap()).collect();

    // every partial verifies on its own.
    for (anchor, sig) in anchors.iter().zip(&partials) {
        assert!(bls::verify(sig, anchor.public_key(), root));
    }

    // the quorum aggregates into one signature that verifies against all keys.
    let aggregate = bls::aggregate(&partials).unwrap();
    let pubkeys: Vec<_> = anchors.iter().map(|a| *a.public_key()).collect();
    assert!(bls::verify_aggregate(&aggregate, &pubkeys, root));

    // a forged root does not verify against the quorum.
    assert!(!bls::verify_aggregate(&aggregate, &pubkeys, b"forged root"));
}
