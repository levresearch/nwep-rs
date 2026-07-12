// the trust-store verification and persistence path, networking free. mirrors
// the sandbox nwlog bootstrap: founding anchors mint a genesis checkpoint, a
// node seeds its store with their pubkeys, verifies and installs the genesis,
// then saves and restores its rollback-critical state. only built with trust.
#![cfg(feature = "trust")]

use nwep::trust::{self, bls::BlsKeypair, Checkpoint, CheckpointStatus, TrustStore};

#[test]
fn genesis_to_store_verify_install_and_persist() {
    // three founding anchors, 1-based share indices, all must sign genesis.
    let founders: Vec<BlsKeypair> = (0..3).map(|_| BlsKeypair::generate().unwrap()).collect();
    let with_index: Vec<(&BlsKeypair, u8)> = founders
        .iter()
        .enumerate()
        .map(|(i, kp)| (kp, (i + 1) as u8))
        .collect();

    let genesis = trust::genesis_checkpoint(&with_index, founders.len()).unwrap();
    assert!(!genesis.is_empty());

    // genesis is epoch 0, timestamp 0, so the decoded checkpoint is fresh at
    // now_secs = 0 and stale far in the future.
    let cp = Checkpoint::decode(&genesis).unwrap();
    assert_eq!(cp.staleness(0).unwrap(), CheckpointStatus::Fresh);
    assert_eq!(cp.staleness(100 * 86400).unwrap(), CheckpointStatus::Stale);

    // a node seeds its store with the founders' bls pubkeys, then installs the
    // genesis (the store applies the epoch-0 bypass per spec 12.11).
    let mut store = TrustStore::new().unwrap();
    let pubkeys: Vec<[u8; 48]> = founders.iter().map(|kp| *kp.public_key()).collect();
    store.load_genesis_anchors(&pubkeys).unwrap();
    assert_eq!(
        store.update_checkpoint(&genesis, 0).unwrap(),
        CheckpointStatus::Fresh
    );
    assert_eq!(store.max_log_size(), 0);

    // a later log-size observation advances the rollback counter.
    store.observe_log_size(42).unwrap();
    assert_eq!(store.max_log_size(), 42);

    // save and restore the rollback-critical state into a fresh store.
    let blob = store.save().unwrap();
    let mut restored = TrustStore::new().unwrap();
    restored.load_genesis_anchors(&pubkeys).unwrap();
    restored.load(&blob).unwrap();
    assert_eq!(restored.max_log_size(), 42);
}

#[test]
fn genesis_rejects_a_bad_threshold() {
    let founders: Vec<BlsKeypair> = (0..2).map(|_| BlsKeypair::generate().unwrap()).collect();
    let with_index: Vec<(&BlsKeypair, u8)> = founders
        .iter()
        .enumerate()
        .map(|(i, kp)| (kp, (i + 1) as u8))
        .collect();
    // a threshold larger than the founder count is invalid.
    assert!(trust::genesis_checkpoint(&with_index, 3).is_err());
}

#[test]
fn trust_version_is_reported() {
    assert!(!trust::version().is_empty());
}
