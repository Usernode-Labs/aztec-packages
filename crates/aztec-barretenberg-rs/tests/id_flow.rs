use aztec_barretenberg_rs as bb;
use serial_test::serial;
use std::path::PathBuf;
fn repo_root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf() }

#[test]
#[serial]
fn compile_and_prove_with_id_flow() {
    let root = repo_root();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));

    // Use embedded utxo_merge fixtures (no external deps)
    let acir: &[u8] = include_bytes!("fixtures/utxo_merge.acir");
    let witness: &[u8] = include_bytes!("fixtures/utxo_merge_wit_a.bin");

    // Compile twice; ID must be deterministic for same ACIR
    let key_id = bb::compile_mega(acir).expect("compile");
    let key_id2 = bb::compile_mega(acir).expect("compile again");
    assert_eq!(key_id2, key_id, "compile_mega must return the same ID for identical ACIR");
    // Prove using the ID and verify with the ID
    let proof = bb::prove_with_id(&key_id, witness).expect("prove_with_id");
    let ok = bb::verify_with_id(&key_id, &proof.0).expect("verify_with_id");
    assert!(ok, "verify_with_id returned false");
}
