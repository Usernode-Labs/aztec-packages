use std::{env, fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};

fn read_b64(path: &str) -> Vec<u8> {
    let text = fs::read_to_string(path).expect("read base64 input");
    STANDARD
        .decode(text.trim())
        .expect("decode standard base64 input")
}

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("usage: gen_batch_merge_vks <leaf-proof-b64> <leaf-vk-b64> <out-dir>");
        std::process::exit(2);
    }
    let out_dir = PathBuf::from(args.pop().expect("out dir"));
    let leaf_vk = read_b64(&args.pop().expect("leaf vk"));
    let leaf_proof = read_b64(&args.pop().expect("leaf proof"));

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
