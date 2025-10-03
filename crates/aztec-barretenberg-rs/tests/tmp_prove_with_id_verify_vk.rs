use aztec_barretenberg_rs as bb;
use serial_test::serial;

#[test]
#[serial]
fn prove_with_id_verify_with_vk_bytes() {
    // CRS init
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));

    // Fixtures
    let acir: &[u8] = include_bytes!("fixtures/utxo_merge.acir");
    let wit: &[u8] = include_bytes!("fixtures/utxo_merge_wit_a.bin");

    // Compile + prove
    let id = bb::compile_mega(acir).expect("compile");
    let proof = bb::prove_with_id(&id, wit).expect("prove_with_id");

    // Verify using freshly written VK bytes
    let vk = bb::write_vk_mega_honk(acir).expect("write_vk");
    let ok = bb::verify_mega_honk(&proof.0, &vk.0).expect("verify");
    assert!(ok, "verify_mega_honk should succeed");
}

