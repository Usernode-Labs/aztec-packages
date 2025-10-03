use aztec_barretenberg_rs as bb;
use serial_test::serial;

#[test]
#[serial]
fn multi_witness_same_id_and_valid_proofs() {
    // Initialize CRS
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));
    // Use embedded fixtures: utxo_merge ACIR and two valid witnesses
    let acir: &[u8] = include_bytes!("fixtures/utxo_merge.acir");
    let wit_a: &[u8] = include_bytes!("fixtures/utxo_merge_wit_a.bin");
    let wit_b: &[u8] = include_bytes!("fixtures/utxo_merge_wit_b.bin");

    // Compile and get ID (deterministic across identical ACIR)
    let id = bb::compile_mega(acir).expect("compile");
    let id2 = bb::compile_mega(acir).expect("compile again");
    assert_eq!(id2, id, "compile_mega must return the same ID for identical ACIR");

    // Prove/verify with witness A
    let proof_a = bb::prove_with_id(&id, wit_a).expect("prove a");
    let ok_a = bb::verify_with_id(&id, &proof_a.0).expect("verify a");
    assert!(ok_a);

    // Prove/verify with witness B
    let proof_b = bb::prove_with_id(&id, wit_b).expect("prove b");
    let ok_b = bb::verify_with_id(&id, &proof_b.0).expect("verify b");
    assert!(ok_b);

    // The key ID is by definition the VK hash; it is constant across witnesses.
}
