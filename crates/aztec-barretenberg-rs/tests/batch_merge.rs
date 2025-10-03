#[test]
fn batch_merge_two_app_proofs() {
    use aztec_barretenberg_rs as bb;

    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    const ACIR: &[u8] = include_bytes!("fixtures/utxo_merge.acir");
    const WIT_A: &[u8] = include_bytes!("fixtures/utxo_merge_wit_a.bin");
    const WIT_B: &[u8] = include_bytes!("fixtures/utxo_merge_wit_b.bin");

    let root = repo_root();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));

    // Compile once and obtain the deterministic key ID for this ACIR.
    let key_id = bb::compile_mega(ACIR).expect("compile_mega");

    // Write VK bytes once; both witnesses share the same circuit VK.
    let vk_bytes = bb::write_vk_mega_honk(ACIR).expect("write_vk");

    // Create two application proofs (A, B) through the ID-based API using distinct witnesses.
    let proof_a = bb::prove_with_id(&key_id, WIT_A).expect("prove_with_id A");
    assert!(bb::verify_with_id(&key_id, &proof_a.0).expect("verify_with_id A"));

    let proof_b = bb::prove_with_id(&key_id, WIT_B).expect("prove_with_id B");
    assert!(bb::verify_with_id(&key_id, &proof_b.0).expect("verify_with_id B"));

    // Batch-merge using the new proofs and the cached VK bytes.
    let (merged_proof, merged_vk) = bb::batch_merge_h2(
        &proof_a.0,
        &vk_bytes.0,
        &proof_b.0,
        &vk_bytes.0,
    )
    .expect("batch merge");

    // Verify merged Mega proof via legacy verifier to ensure compatibility.
    let ok = bb::verify_mega_honk(&merged_proof.0, &merged_vk.0).expect("verify merged");
    assert!(ok);
}
