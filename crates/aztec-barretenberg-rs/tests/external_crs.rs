#![cfg(feature = "external-crs")]

use aztec_barretenberg_rs::{
    batch_merge_leaf_vk, configure_external_prover_crs, mega_honk_vk_hash, prepare_prover_crs,
    prover_crs_initialized, verify_mega_honk_leaf, ProverCrs,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Barrier,
};

#[test]
fn verification_needs_no_loader_and_failed_loading_is_retryable() {
    let vk = batch_merge_leaf_vk().expect("embedded VK needs no proving data");
    let hash = mega_honk_vk_hash(&vk.0).expect("VK hashing needs no proving data");
    assert_ne!(hash, [0; 32]);
    assert!(!prover_crs_initialized());
    let proof = include_bytes!("fixtures/addition.proof");
    let proof_vk = include_bytes!("fixtures/addition.vk");
    assert!(
        verify_mega_honk_leaf(proof, proof_vk).expect("valid proof checks with verifier-only CRS")
    );
    let mut tampered = proof.to_vec();
    tampered[35] ^= 1;
    assert!(!verify_mega_honk_leaf(&tampered, proof_vk).expect("tampered proof is well formed"));
    assert!(verify_mega_honk_leaf(&[], &vk.0).is_err());
    assert!(prepare_prover_crs().is_err());

    static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let loader_started = Arc::clone(&started);
    let loader_release = Arc::clone(&release);
    configure_external_prover_crs(move || {
        if ATTEMPTS.fetch_add(1, Ordering::SeqCst) == 0 {
            loader_started.wait();
            loader_release.wait();
            Err("interrupted download".into())
        } else {
            Ok(ProverCrs {
                bn254_g1: vec![0; 64],
                grumpkin_g1: Vec::new(),
            })
        }
    })
    .unwrap();
    let loading = std::thread::spawn(prepare_prover_crs);
    started.wait();
    // Verifier calls must remain available while a worker fetches proving data.
    assert!(verify_mega_honk_leaf(proof, proof_vk).unwrap());
    release.wait();
    assert!(loading
        .join()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("interrupted download"));
    assert!(prepare_prover_crs()
        .unwrap_err()
        .to_string()
        .contains("length"));
    assert_eq!(ATTEMPTS.load(Ordering::SeqCst), 2);
    assert!(!prover_crs_initialized());
    assert_eq!(mega_honk_vk_hash(&vk.0).unwrap(), hash);
}
