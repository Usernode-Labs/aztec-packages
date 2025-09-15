use aztec_barretenberg_rs as bb;
use base64::Engine as _;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn load_acir_from_program_json(p: &std::path::Path) -> Vec<u8> {
    let s = fs::read_to_string(p).expect("read program.json");
    let v: serde_json::Value = serde_json::from_str(&s).expect("json");
    let b64 = v.get("bytecode").and_then(|x| x.as_str()).expect("bytecode str");
    let gz = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("base64 decode");
    let mut dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut out = Vec::new();
    use std::io::Read;
    dec.read_to_end(&mut out).expect("gunzip");
    out
}

fn load_gunzipped(p: &std::path::Path) -> Vec<u8> {
    let gz = fs::read(p).expect("read gz");
    let mut dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut out = Vec::new();
    use std::io::Read;
    dec.read_to_end(&mut out).expect("gunzip");
    out
}

#[test]
#[ignore]
fn batch_merge_two_app_proofs() {
    let root = repo_root();
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));

    let proj = root.join("barretenberg/noir/hash_ecdsa/target");
    let acir = load_acir_from_program_json(&proj.join("program.json"));
    let witness = load_gunzipped(&proj.join("witness.gz"));

    // Create two identical app proofs (A, B)
    let (proof_a, vk_a) = bb::prove_mega_honk(&acir, &witness).expect("prove A");
    let (proof_b, vk_b) = bb::prove_mega_honk(&acir, &witness).expect("prove B");

    // Batch-merge (currently delegates to merge_mega in the shim)
    let (merged_proof, merged_vk) = bb::batch_merge_h2(&proof_a.0, &vk_a.0, &proof_b.0, &vk_b.0).expect("batch merge");

    // Verify merged Mega proof
    let ok = bb::verify_mega_honk(&merged_proof.0, &merged_vk.0).expect("verify merged");
    assert!(ok);
}
