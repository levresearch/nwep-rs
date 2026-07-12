// the anchor checkpoint-production ceremony, networking free. three anchors each
// sign one epoch's merkle root as a partial, a coordinator aggregates them into
// a checkpoint, and a node verifies and installs it against the anchor set. this
// is the produce -> aggregate -> verify loop the trust layer rests on. mirrors
// the sandbox nwlog checkpoint path. only built with the trust feature.
#![cfg(feature = "trust")]

use nwep::trust::{self, bls::BlsKeypair, AnchorNode, CheckpointStatus, TrustStore};
use nwep::Identity;
use std::time::Duration;

const EPOCH: u64 = 1;
const EPOCH_SECS: i64 = 3600;
const LOG_SIZE: u64 = 128;

#[test]
fn anchors_produce_aggregate_and_verify_a_checkpoint() {
    let root = [0xABu8; 32];

    // three anchors, each a web/1 identity plus a bls share at a 1-based index.
    let bls_keys: Vec<BlsKeypair> = (0..3).map(|_| BlsKeypair::generate().unwrap()).collect();
    let mut anchors: Vec<AnchorNode> = bls_keys
        .iter()
        .enumerate()
        .map(|(i, bls)| {
            let id = Identity::generate().unwrap();
            AnchorNode::new(&id, bls, (i + 1) as u8, Duration::from_secs(3300)).unwrap()
        })
        .collect();

    // each anchor records the epoch root (server replica matches its own), then
    // produces its partial signature over it.
    let partials: Vec<_> = anchors
        .iter_mut()
        .map(|a| {
            a.collect_log_root(EPOCH, &root, LOG_SIZE, &root).unwrap();
            a.produce_partial_sig(EPOCH, &root, LOG_SIZE).unwrap()
        })
        .collect();
    // the partials carry the anchors' 1-based indices.
    assert_eq!(
        partials.iter().map(|p| p.index()).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );

    // the coordinator aggregates the quorum into a checkpoint.
    let anchor_pubkeys: Vec<[u8; 48]> = bls_keys.iter().map(|k| *k.public_key()).collect();
    let checkpoint =
        trust::finish_checkpoint(EPOCH, &root, LOG_SIZE, &partials, &anchor_pubkeys).unwrap();
    assert!(!checkpoint.is_empty());

    // a node with the anchor set installed verifies the checkpoint (no install),
    let mut store = TrustStore::new().unwrap();
    store.load_genesis_anchors(&anchor_pubkeys).unwrap();
    let now = EPOCH as i64 * EPOCH_SECS; // timestamp == epoch * EPOCH_SECS -> fresh
    assert!(store.verify_checkpoint(&checkpoint, now).is_ok());

    // and installs it as the latest fresh checkpoint.
    assert_eq!(
        store.update_checkpoint(&checkpoint, now).unwrap(),
        CheckpointStatus::Fresh
    );

    // a forged root at the same epoch does not verify against the anchor set.
    let forged =
        trust::finish_checkpoint(EPOCH, &[0x11u8; 32], LOG_SIZE, &partials, &anchor_pubkeys);
    // either aggregation rejects the mismatch, or verification does.
    let rejected = match forged {
        Err(_) => true,
        Ok(bytes) => store.verify_checkpoint(&bytes, now).is_err(),
    };
    assert!(rejected, "a checkpoint over a forged root must not verify");
}
