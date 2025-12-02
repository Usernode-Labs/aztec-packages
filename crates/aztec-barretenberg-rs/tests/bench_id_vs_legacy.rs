use aztec_barretenberg_rs as bb;
use base64::Engine as _;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_acir_from_program_json(p: &std::path::Path) -> Vec<u8> {
    let s = fs::read_to_string(p).expect("read program.json");
    let v: serde_json::Value = serde_json::from_str(&s).expect("json");
    let b64 = v
        .get("bytecode")
        .and_then(|x| x.as_str())
        .expect("bytecode str");
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
fn bench_new_api_vs_legacy() {
    match std::env::var("BB_BENCH_DEEP_COPY").as_deref() {
        Ok("0") => std::env::set_var("BB_REFRESH_DEEP_COPY", "0"),
        _ => std::env::remove_var("BB_REFRESH_DEEP_COPY"),
    }
    let root = repo_root();
    bb::init_embedded_crs().expect("init CRS");
    let proj = root.join("barretenberg/noir/hash_ecdsa/target");
    let acir = load_acir_from_program_json(&proj.join("program.json"));
    let witness = load_gunzipped(&proj.join("witness.gz"));

    // Determine which sections to run
    let bench_mode = std::env::var("BB_BENCH_ONLY").unwrap_or_else(|_| "both".to_string());
    let run_new = bench_mode != "legacy";
    let run_old = bench_mode != "new";

    // New API (deterministic ID)
    let mut dur_new = Duration::default();
    let mut dur_old = Duration::default();
    let id = bb::compile_mega(&acir).expect("compile");
    let id2 = bb::compile_mega(&acir).expect("compile again");
    assert_eq!(
        id2, id,
        "compile_mega must return the same ID for identical ACIR"
    );
    let n = std::env::var("BB_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(30);

    if run_new {
        let start_new = Instant::now();
        for _ in 0..n {
            let proof = bb::prove_with_id(&id, &witness).expect("prove_with_id");
            let ok = bb::verify_with_id(&id, &proof.0).expect("verify_with_id");
            assert!(ok);
        }
        dur_new = start_new.elapsed();
    }

    // Legacy one-shot
    if run_old {
        let start_old = Instant::now();
        for _ in 0..n {
            let (proof, vk) = bb::prove_mega_honk(&acir, &witness).expect("prove_legacy");
            let ok = bb::verify_mega_honk(&proof.0, &vk.0).expect("verify_legacy");
            assert!(ok);
        }
        dur_old = start_old.elapsed();
    }

    match (run_new, run_old) {
        (true, true) => {
            eprintln!(
                "new_api total {:?} ({} iters) vs legacy total {:?}",
                dur_new, n, dur_old
            );
        }
        (true, false) => {
            eprintln!("new_api total {:?} ({} iters)", dur_new, n);
        }
        (false, true) => {
            eprintln!("legacy total {:?} ({} iters)", dur_old, n);
        }
        (false, false) => unreachable!(),
    }
}
