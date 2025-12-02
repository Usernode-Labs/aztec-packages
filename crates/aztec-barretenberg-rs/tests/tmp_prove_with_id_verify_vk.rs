use aztec_barretenberg_rs as bb;
use serial_test::serial;

#[test]
#[serial]
fn prove_with_id_verify_with_vk_bytes() {
    // CRS init
    bb::init_embedded_crs().expect("init CRS");

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
