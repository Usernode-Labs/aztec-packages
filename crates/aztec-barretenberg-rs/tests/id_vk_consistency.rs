use aztec_barretenberg_rs as bb;
use std::path::PathBuf;
fn repo_root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf() }

#[test]
fn key_id_matches_vk_hash_and_is_stable() {
    let root = repo_root();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));
    let acir: &[u8] = include_bytes!("fixtures/utxo_merge.acir");

    let id1 = bb::compile_mega(acir).expect("compile_mega");
    let id2 = bb::compile_mega(acir).expect("compile_mega again");
    assert_eq!(id1, id2, "key id should be deterministic for same ACIR");

    // Also ensure it matches the vk hash from legacy write_vk + hash
    let vk = bb::write_vk_mega_honk(acir).expect("write_vk");
    let vk_hash = bb::mega_vk_hash(&vk.0).expect("vk hash");
    assert_eq!(id1, vk_hash, "key id must equal vk hash");
}
