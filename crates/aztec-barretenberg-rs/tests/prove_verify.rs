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
fn prove_and_verify_hash_ecdsa_native() {
    let root = repo_root();
    // Set CRS path to the repo TS crs dir (will fetch if missing)
    let crs = root.join("barretenberg/ts/crs");
    let _ = bb::set_crs_path(&crs);

    let proj = root.join("barretenberg/noir/hash_ecdsa/target");
    let acir = load_acir_from_program_json(&proj.join("program.json"));
    let witness = load_gunzipped(&proj.join("witness.gz"));

    // Sanity: sizes
    let (_total, _subgroup) = bb::acir_sizes(&acir).expect("acir_sizes");

    // VK
    let _vk = bb::write_vk_mega_honk(&acir).expect("write_vk");

    // Prove + verify
    let (proof, vk) = bb::prove_mega_honk(&acir, &witness).expect("prove");
    let ok = bb::verify_mega_honk(&proof.0, &vk.0).expect("verify");
    assert!(ok);
}

