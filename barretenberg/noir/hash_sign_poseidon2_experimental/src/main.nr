// Poseidon2-based Schnorr verification in-circuit over Grumpkin.
use std::embedded_curve_ops::EmbeddedCurvePoint;
mod poseidon_schnorr;

fn main(
    // (unused hash inputs kept for compatibility)
    _message_fr_be: [Field; 8],
    _expected_digest: Field,
    // Signature inputs are accepted but not verified in-circuit for Poseidon2 challenge
    message_bytes: [u8; 256],
    pubkey_x: Field,
    pubkey_y: Field,
    signature: [u8; 64],
) {
    // Optional: keep digest input for hash-only measurements if needed
    // assert(poseidon2::hash(message_fr_be) == expected_digest);
    let pubkey = EmbeddedCurvePoint { x: pubkey_x, y: pubkey_y, is_infinite: false };
    // Debug: compute and print circuit challenge vs sig e
    let ok = poseidon_schnorr::verify_signature(pubkey, signature, message_bytes);
    assert(ok);
}
