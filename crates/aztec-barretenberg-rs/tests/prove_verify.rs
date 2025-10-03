use aztec_barretenberg_rs as bb;
use std::path::PathBuf;
fn repo_root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf() }

#[test]
fn prove_and_verify_hash_ecdsa_native() {
    let root = repo_root();
    // Set CRS path to the repo TS crs dir (will fetch if missing)
    let crs = root.join("barretenberg/ts/crs");
    let _ = bb::set_crs_path(&crs);

    // Use embedded utxo_merge fixtures
    let acir: &[u8] = include_bytes!("fixtures/utxo_merge.acir");
    let witness: &[u8] = include_bytes!("fixtures/utxo_merge_wit_a.bin");

    // Sanity: sizes
    let (_total, _subgroup) = bb::acir_sizes(acir).expect("acir_sizes");

    // VK
    let _vk = bb::write_vk_mega_honk(acir).expect("write_vk");

    // Prove + verify
    let (proof, vk) = bb::prove_mega_honk(acir, witness).expect("prove");
    let ok = bb::verify_mega_honk(&proof.0, &vk.0).expect("verify");
    assert!(ok);
}
