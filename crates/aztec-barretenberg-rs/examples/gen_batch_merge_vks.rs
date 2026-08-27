use std::{env, fs, path::PathBuf};

use acir::circuit::{Circuit, Program};
use acir::native_types::{Witness, WitnessMap, WitnessStack};
use acir_field::FieldElement;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;

const FORMAT_MSGPACK_COMPACT: u8 = 3;

fn read_b64(path: &str) -> Vec<u8> {
    let text = fs::read_to_string(path).expect("read base64 input");
    STANDARD
        .decode(text.trim())
        .expect("decode standard base64 input")
}

fn serialize_msgpack_compact<T: Serialize>(value: &T) -> Vec<u8> {
    let mut payload = Vec::new();
    value
        .serialize(
            &mut rmp_serde::Serializer::new(&mut payload)
                .with_bytes(rmp_serde::config::BytesMode::ForceAll),
        )
        .expect("serialize msgpack-compact payload");
    let mut bytes = Vec::with_capacity(payload.len() + 1);
    bytes.push(FORMAT_MSGPACK_COMPACT);
    bytes.extend(payload);
    bytes
}

fn generate_smoke_leaf() -> (Vec<u8>, Vec<u8>) {
    // The batch-merge leaf circuit consumes five semantic public inputs before
    // Barretenberg's DefaultIO values. This small ACIR program is sufficient to
    // regenerate the merge circuit VKs without depending on Usernode artifacts.
    let circuit = Circuit::from_str(
        r#"
        private parameters: [w1, w2, w3, w4, w5]
        public parameters: []
        return values: [w1, w2, w3, w4, w5]
        "#,
    )
    .expect("parse smoke leaf circuit");
    let program = Program {
        functions: vec![circuit],
        unconstrained_functions: Vec::new(),
    };
    let acir = serialize_msgpack_compact(&program);

    let mut witness_map = WitnessMap::new();
    for index in 1..=5 {
        witness_map.insert(Witness(index), FieldElement::from(index as u128));
    }
    let witness = serialize_msgpack_compact(&WitnessStack::from(witness_map));
    let (proof, vk) =
        aztec_barretenberg_rs::prove_mega_honk(&acir, &witness).expect("prove smoke leaf");
    (proof.0, vk.0)
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let (leaf_proof, leaf_vk, out_dir) = if args.len() == 2 && args[0] == "--smoke" {
        let out_dir = PathBuf::from(args.pop().expect("out dir"));
        let (proof, vk) = generate_smoke_leaf();
        (proof, vk, out_dir)
    } else if args.len() == 3 {
        let out_dir = PathBuf::from(args.pop().expect("out dir"));
        let leaf_vk = read_b64(&args.pop().expect("leaf vk"));
        let leaf_proof = read_b64(&args.pop().expect("leaf proof"));
        (leaf_proof, leaf_vk, out_dir)
    } else {
        eprintln!(
            "usage: gen_batch_merge_vks <leaf-proof-b64> <leaf-vk-b64> <out-dir>\n       gen_batch_merge_vks --smoke <out-dir>"
        );
        std::process::exit(2);
    };

    let (leaf_merge_proof, leaf_merge_vk) = aztec_barretenberg_rs::batch_merge_leaf_with_vk(
        &leaf_proof,
        &leaf_vk,
        &leaf_proof,
        &leaf_vk,
    )
    .expect("build leaf merge vk");
    let (_agg_merge_proof, agg_merge_vk) = aztec_barretenberg_rs::batch_merge_leaf_with_vk(
        &leaf_merge_proof.0,
        &leaf_merge_vk.0,
        &leaf_merge_proof.0,
        &leaf_merge_vk.0,
    )
    .expect("build aggregate merge vk");

    fs::create_dir_all(&out_dir).expect("create output directory");
    fs::write(out_dir.join("batch_merge_leaf_vk.bin"), &leaf_merge_vk.0)
        .expect("write leaf merge vk");
    fs::write(out_dir.join("batch_merge_agg_vk.bin"), &agg_merge_vk.0).expect("write agg merge vk");

    let leaf_hash =
        aztec_barretenberg_rs::mega_honk_vk_hash(&leaf_merge_vk.0).expect("hash leaf merge vk");
    let agg_hash =
        aztec_barretenberg_rs::mega_honk_vk_hash(&agg_merge_vk.0).expect("hash agg merge vk");
    println!("leaf_merge_vk_hash={}", hex::encode(leaf_hash));
    println!("agg_merge_vk_hash={}", hex::encode(agg_hash));
}
