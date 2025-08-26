use dep::schnorr;
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn main(
    message_bytes: [u8; 256],
    pubkey_x: Field,
    pubkey_y: Field,
    signature: [u8; 64],
) {
    let pubkey = EmbeddedCurvePoint { x: pubkey_x, y: pubkey_y, is_infinite: false };
    let ok = schnorr::verify_signature(pubkey, signature, message_bytes);
    assert(ok);
}
