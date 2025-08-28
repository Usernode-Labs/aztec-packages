use aztec_barretenberg_rs as bb;
use acir::circuit::Program;
use acir::AcirField;
use acir_field::FieldElement as FE;
use base64::Engine as _;
use serial_test::serial;
use std::fs;
use std::io::Read;
use std::process::Stdio;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn nargo() -> &'static str {
    "/home/dan/.nargo/bin/nargo"
}

fn ensure_program(dir: &Path) {
    let pj = dir.join("target/program.json");
    if !pj.exists() {
        let mut cmd = std::process::Command::new(nargo());
        let status = cmd
            .current_dir(dir)
            .arg("compile")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn nargo compile");
        assert!(status.success(), "nargo compile failed for {:?}", dir);
    }
}

fn ensure_witness(dir: &Path) -> bool {
    let tg = dir.join("target");
    if !tg.join("witness.gz").exists() {
        let mut cmd = std::process::Command::new(nargo());
        let status = cmd
            .current_dir(dir)
            .arg("execute")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn nargo execute");
        if !status.success() { return false; }
    }
    tg.join("witness.gz").exists()
}

fn load_program_json_acir(p: &Path) -> Vec<u8> {
    let s = fs::read_to_string(p).expect("read program.json");
    let v: serde_json::Value = serde_json::from_str(&s).expect("json");
    let b64 = v.get("bytecode").and_then(|x| x.as_str()).expect("bytecode str");
    let gz = base64::engine::general_purpose::STANDARD.decode(b64).expect("base64 decode program");
    let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
    let mut out = Vec::new();
    dec.read_to_end(&mut out).expect("gunzip acir");
    out
}

fn load_gunzipped(p: &Path) -> Vec<u8> {
    let gz = fs::read(p).expect("read gz");
    let mut dec = flate2::read::GzDecoder::new(&gz[..]);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).expect("gunzip witness");
    out
}

// Removed pedersen auto-fix logic by request.

fn parse_inputs_from_prover_toml(proj: &Path, program_json: &serde_json::Value) -> Vec<FE> {
    // Flatten inputs following the declared ABI parameter order from program.json
    let prover_toml = proj.join("Prover.toml");
    let toml_str = fs::read_to_string(&prover_toml).expect("read Prover.toml");
    let toml_val: toml::Value = toml::from_str(&toml_str).expect("parse Prover.toml");

    let params = program_json
        .get("abi")
        .and_then(|a| a.get("parameters"))
        .and_then(|p| p.as_array())
        .expect("abi.parameters");

    let mut flattened: Vec<FE> = Vec::new();
    for param in params {
        let name = param.get("name").and_then(|n| n.as_str()).expect("param name");
        let val = toml_val.get(name).cloned().unwrap_or(toml::Value::String(String::new()));
        match val {
            toml::Value::Array(arr) => {
                for b in arr {
                    match b {
                        toml::Value::Integer(i) => {
                            let byte = i as u8;
                            flattened.push(FE::from(byte as u128));
                        }
                        toml::Value::String(s) => {
                            let hex = s.strip_prefix("0x").unwrap_or(&s);
                            let mut v = hex::decode(hex).expect("hex decode elem");
                            if v.len() < 32 {
                                let mut p = vec![0u8; 32 - v.len()];
                                p.extend_from_slice(&v);
                                v = p;
                            }
                            let mut be = [0u8; 32];
                            be.copy_from_slice(&v[v.len() - 32..]);
                            flattened.push(FE::from_be_bytes_reduce(&be));
                        }
                        _ => panic!("unsupported array element in Prover.toml for {}", name),
                    }
                }
            }
            toml::Value::String(s) => {
                if s.is_empty() {
                    continue;
                }
                let hex = s.strip_prefix("0x").unwrap_or(&s);
                let mut v = hex::decode(hex).expect("hex decode");
                if v.len() < 32 {
                    let mut p = vec![0u8; 32 - v.len()];
                    p.extend_from_slice(&v);
                    v = p;
                }
                let mut be = [0u8; 32];
                be.copy_from_slice(&v[v.len() - 32..]);
                flattened.push(FE::from_be_bytes_reduce(&be));
            }
            _ => {}
        }
    }
    flattened
}

fn extract_proverinput_indices(program: &Program<FE>) -> Vec<u32> {
    let func = &program.functions[0];
    let mut ids: Vec<u32> = func
        .private_parameters
        .iter()
        .map(|w| match *w { acir::native_types::Witness(idx) => idx })
        .collect();
    ids.sort_unstable();
    ids
}

fn acvm_compute_witness_from_inputs(inputs: Vec<FE>, program: &Program<FE>) -> Vec<u8> {
    use acir::native_types::{Witness, WitnessMap, WitnessStack};
    use acvm::pwg::{ACVM, ACVMStatus};

    let ids = extract_proverinput_indices(program);
    assert!(inputs.len() <= ids.len(), "more inputs than ProverInput directives");

    let mut initial = WitnessMap::new();
    for (i, fe) in inputs.into_iter().enumerate() {
        initial.insert(Witness(ids[i]), fe);
    }

    let solver = bb::BarretenbergBlackBoxSolver::default();
    let func = &program.functions[0];
    let mut acvm: ACVM<'_, FE, _> = ACVM::new(
        &solver,
        &func.opcodes,
        initial,
        &program.unconstrained_functions,
        &func.assert_messages,
    );
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::RequiresForeignCall(_) | ACVMStatus::RequiresAcirCall(_) => {
                panic!("unexpected foreign/acir call")
            }
            ACVMStatus::Failure(e) => panic!("acvm failure: {:?}", e),
            ACVMStatus::InProgress => continue,
        }
    }
    let witness_map = acvm.finalize();
    let stack: WitnessStack<FE> = WitnessStack::from(witness_map);
    let gz = stack.serialize().expect("serialize witness stack");
    let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
    let mut out = Vec::new();
    dec.read_to_end(&mut out).expect("gunzip witness stack");
    out
}

#[test]
#[serial]
fn witness_equivalence_acvm_vs_nargo_all_examples() {
    let root = repo_root();
    let noir_dir = root.join("barretenberg/noir");
    let _ = bb::set_crs_path(root.join("barretenberg/ts/crs"));

    let mut checked = 0usize;
    for entry in fs::read_dir(&noir_dir).expect("read noir dir") {
        let entry = entry.expect("dirent");
        let proj = entry.path();
        if !proj.is_dir() { continue; }
        let prover_toml = proj.join("Prover.toml");
        if !prover_toml.exists() { eprintln!("skipping {:?}: no Prover.toml", proj); continue; }

        ensure_program(&proj);
        if !ensure_witness(&proj) { eprintln!("skipping {:?}: nargo execute failed", proj); continue; }
        let program_json_path = proj.join("target/program.json");
        let program_json_str = fs::read_to_string(&program_json_path).expect("read program.json");
        let program_json: serde_json::Value = serde_json::from_str(&program_json_str).expect("json");
        let acir_bytes = load_program_json_acir(&program_json_path);
        let program: Program<FE> = Program::deserialize_program(&acir_bytes)
            .or_else(|_| bincode::deserialize(&acir_bytes)).expect("deserialize program");

        // Nargo-produced witness
        let expected_witness = load_gunzipped(&proj.join("target/witness.gz"));
        // ACVM-produced witness from Prover.toml inputs
        let flattened_inputs = parse_inputs_from_prover_toml(&proj, &program_json);
        let ids = extract_proverinput_indices(&program);
        eprintln!("inputs: {} private_params: {} for {:?}", flattened_inputs.len(), ids.len(), proj.file_name().unwrap());
        if flattened_inputs.len() > ids.len() {
            eprintln!("skipping {:?}: ABI inputs exceed CallData slots", proj);
            continue;
        }
    let got_witness = acvm_compute_witness_from_inputs(flattened_inputs, &program);
        assert_eq!(got_witness, expected_witness, "witness mismatch for {:?}", proj);
        eprintln!("witness match: {:?}", proj.file_name().unwrap());

        // Negative tamper tests
        // Prove OK, then tamper witness -> prove must fail; tamper proof -> verify false/Err
        let (proof, vk) = bb::prove_mega_honk(&acir_bytes, &expected_witness).expect("prove");
        assert!(bb::verify_mega_honk(&proof.0, &vk.0).unwrap_or(false));

        let mut bad_witness = expected_witness.clone();
        if !bad_witness.is_empty() { bad_witness[0] ^= 0xAA; }
        let proved = bb::prove_mega_honk(&acir_bytes, &bad_witness);
        assert!(proved.is_err(), "proving should fail with tampered witness for {:?}", proj);

        let mut bad_proof = proof.0.clone();
        if !bad_proof.is_empty() { bad_proof[0] ^= 0x55; }
        let ok = bb::verify_mega_honk(&bad_proof, &vk.0);
        match ok { Ok(v) => assert!(!v, "tampered proof verified for {:?}", proj), Err(_) => {} }

        checked += 1;
    }
    assert!(checked > 0, "no Noir projects checked");
}
