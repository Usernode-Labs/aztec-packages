use std::hash::pedersen_hash;
use std::ecdsa_secp256k1 as ecdsa;

fn main(
    message_bytes: [u8; 256],
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    signature: [u8; 64], // (r||s), normalized s
) {
    // Compute Pedersen hash over bytes by mapping each byte to a Field element
    let mut fields: [Field; 256] = [0; 256];
    for i in 0..256 {
        fields[i] = message_bytes[i] as Field;
    }
    let digest_f: Field = pedersen_hash(fields);
    let digest: [u8; 32] = digest_f.to_be_bytes();

    // Verify ECDSA over secp256k1 with the Pedersen-based digest
    let ok = ecdsa::verify_signature(pubkey_x, pubkey_y, signature, digest);
    assert(ok);
}

#[test]
fn api_shape_test() {
    // Minimal shape test (does not check real signature)
    // Unused placeholders for local dev; prefix with underscore to silence warnings.
    let _msg: [u8; 256] = [0; 256];
    let _pkx: [u8; 32] = [0; 32];
    let _pky: [u8; 32] = [0; 32];
    let _sig: [u8; 64] = [0; 64];
    // This will fail assert in a real run; just ensures compilation and function wiring
    // Uncomment to run as a negative test with expect-failure infra if desired.
    // let _ = ecdsa::verify_signature(pkx, pky, sig, [0; 32]);
}
