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

    fs::create_dir_all(&out_dir).expect("create output directory");
    for arity in 2..=24 {
        let leaf_children = (0..arity)
            .map(|_| (leaf_proof.as_slice(), leaf_vk.as_slice()))
            .collect::<Vec<_>>();
        let (leaf_merge_proof, leaf_merge_vk) =
            aztec_barretenberg_rs::batch_merge_many_with_vk(&leaf_children)
                .expect("build leaf merge vk");

        let agg_children = (0..arity)
            .map(|_| (leaf_merge_proof.0.as_slice(), leaf_merge_vk.0.as_slice()))
            .collect::<Vec<_>>();
        let (_agg_merge_proof, agg_merge_vk) =
            aztec_barretenberg_rs::batch_merge_many_with_vk(&agg_children)
                .expect("build aggregate merge vk");

        let leaf_vk_path = if arity == 2 {
            out_dir.join("batch_merge_leaf_vk.bin")
        } else {
            out_dir.join(format!("batch_merge_leaf_{}_vk.bin", arity))
        };
        let agg_vk_path = if arity == 2 {
            out_dir.join("batch_merge_agg_vk.bin")
        } else {
            out_dir.join(format!("batch_merge_agg_{}_vk.bin", arity))
        };
        fs::write(leaf_vk_path, &leaf_merge_vk.0).expect("write leaf merge vk");
        fs::write(agg_vk_path, &agg_merge_vk.0).expect("write agg merge vk");

        let leaf_hash =
            aztec_barretenberg_rs::mega_honk_vk_hash(&leaf_merge_vk.0).expect("hash leaf merge vk");
        let agg_hash =
            aztec_barretenberg_rs::mega_honk_vk_hash(&agg_merge_vk.0).expect("hash agg merge vk");
        println!("leaf_merge_{}_vk_hash={}", arity, hex::encode(leaf_hash));
        println!("agg_merge_{}_vk_hash={}", arity, hex::encode(agg_hash));

        assert!(
            aztec_barretenberg_rs::verify_mega_honk_leaf(&leaf_merge_proof.0, &leaf_merge_vk.0)
                .expect("verify leaf merge"),
            "leaf merge proof verifies"
        );
        assert!(
            aztec_barretenberg_rs::verify_mega_honk_leaf(&_agg_merge_proof.0, &agg_merge_vk.0)
                .expect("verify agg merge"),
            "agg merge proof verifies"
        );

        let expected_public_input_count = 6 + 3 * 24;
        let expected_public_input_bytes = expected_public_input_count * 32;
        let leaf_public_inputs =
            aztec_barretenberg_rs::mega_honk_public_inputs(&leaf_merge_proof.0, &leaf_merge_vk.0)
                .expect("leaf public inputs");
        let agg_public_inputs =
            aztec_barretenberg_rs::mega_honk_public_inputs(&_agg_merge_proof.0, &agg_merge_vk.0)
                .expect("agg public inputs");
        assert_eq!(leaf_public_inputs.len(), expected_public_input_bytes);
        assert_eq!(agg_public_inputs.len(), expected_public_input_bytes);
    }
}
