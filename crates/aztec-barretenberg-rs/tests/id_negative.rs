use aztec_barretenberg_rs as bb;
use serial_test::serial;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

// Use embedded ACIR/witness fixtures (no external deps)

#[test]
#[serial]
fn invalid_id_errors_for_prove_and_verify() {
    let root = repo_root();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));
    let acir: &[u8] = include_bytes!("fixtures/utxo_merge.acir");
    let witness: &[u8] = include_bytes!("fixtures/utxo_merge_wit_a.bin");

    // Compile and get a valid ID
    let id = bb::compile_mega(acir).expect("compile");
    // Create a bogus ID not present in the cache
    let mut bad_id = id;
    bad_id[0] ^= 0xFF;
    if bad_id == id { bad_id[1] ^= 0xAA; }

    // Prove with invalid ID should error
    let proved = bb::prove_with_id(&bad_id, witness);
    assert!(proved.is_err(), "prove_with_id must error for unknown ID");

    // Produce a valid proof to test verify path
    let proof = bb::prove_with_id(&id, witness).expect("prove_with_id ok");
    let ver = bb::verify_with_id(&bad_id, &proof.0);
    assert!(ver.is_err(), "verify_with_id must error for unknown ID");
}

#[test]
#[serial]
fn verify_with_wrong_id_is_false() {
    let root = repo_root();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));
    let acir_a: &[u8] = include_bytes!("fixtures/utxo_merge.acir");
    let acir_b: &[u8] = include_bytes!("fixtures/utxo_spend.acir");
    let id_a = bb::compile_mega(acir_a).expect("compile A");
    let id_b = bb::compile_mega(acir_b).expect("compile B");
    assert_ne!(id_a, id_b, "different circuits should produce different IDs");

    let wit_a: &[u8] = include_bytes!("fixtures/utxo_merge_wit_a.bin");
    let proof_a = bb::prove_with_id(&id_a, wit_a).expect("prove A");
    let ok_a = bb::verify_with_id(&id_a, &proof_a.0).expect("verify A");
    assert!(ok_a, "proof A should verify under ID A");

    // Verifying proof A under ID B should return false (VK mismatch)
    let ok_wrong = bb::verify_with_id(&id_b, &proof_a.0).expect("verify with wrong ID");
    assert!(!ok_wrong, "proof should not verify under mismatched ID");
}
