use std::{env, fs};

use base64::{engine::general_purpose::STANDARD, Engine as _};

fn main() {
    let [vkey_path] = env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| {
            eprintln!("usage: validate_ultra_zk_vk <vkey-b64>");
            std::process::exit(2);
        });
    let vkey_b64 = fs::read_to_string(vkey_path).expect("read base64 verification key");
    let vkey = STANDARD
        .decode(vkey_b64.trim())
        .expect("decode standard base64 verification key");

    let wrapper_vk = aztec_barretenberg_rs::mega_honk_vk_for_ultra_zk_leaf_wrapper(&vkey)
        .expect("derive MegaHonk UltraZK wrapper verification key");
    let wrapper_hash = aztec_barretenberg_rs::mega_honk_vk_hash(&wrapper_vk.0)
        .expect("hash wrapper verification key");

    println!("ultra_zk_vk_bytes={}", vkey.len());
    println!("wrapper_vk_bytes={}", wrapper_vk.0.len());
    println!("wrapper_vk_hash={}", hex::encode(wrapper_hash));
}
