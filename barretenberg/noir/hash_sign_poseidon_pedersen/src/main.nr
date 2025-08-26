// Poseidon2-based Schnorr verification with Pedersen prehash (barretenberg-compatible)
use std::embedded_curve_ops::EmbeddedCurvePoint;
mod poseidon_pedersen_schnorr;

fn main(
    message_bytes: [u8; 256],
    pubkey_x: Field,
    pubkey_y: Field,
    signature: [u8; 64],
) {
    let pubkey = EmbeddedCurvePoint { x: pubkey_x, y: pubkey_y, is_infinite: false };
    let ok = poseidon_pedersen_schnorr::verify_signature(pubkey, signature, message_bytes);
    assert(ok);
}