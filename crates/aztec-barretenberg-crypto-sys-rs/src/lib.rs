#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use libc::{c_int, size_t};

extern "C" {
    pub fn bb_schnorr_blake2s_sign(
        msg: *const u8,
        msg_len: size_t,
        sk32: *const u8,
        sig64_out: *mut u8,
    ) -> c_int;

    pub fn bb_schnorr_blake2s_verify_xy(
        msg: *const u8,
        msg_len: size_t,
        sig64: *const u8,
        pkx32: *const u8,
        pky32: *const u8,
        out_ok: *mut bool,
    ) -> c_int;

    pub fn bb_grumpkin_derive_pubkey(
        sk32: *const u8,
        out_x_be: *mut u8,
        out_y_be: *mut u8,
    ) -> c_int;

    pub fn bb_free(ptr: *mut u8);

    pub fn bb_poseidon2_permutation_bn254(
        inputs_be: *const u8,
        element_count: size_t,
        out_be: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    pub fn bb_grumpkin_ec_add(
        pk1_x_be: *const u8,
        pk1_y_be: *const u8,
        pk2_x_be: *const u8,
        pk2_y_be: *const u8,
        out_x_be: *mut u8,
        out_y_be: *mut u8,
    ) -> c_int;

    pub fn bb_grumpkin_compress(
        pk_x_be: *const u8,
        pk_y_be: *const u8,
        out_comp_be: *mut u8,
    ) -> c_int;

    pub fn bb_grumpkin_decompress(
        comp_be: *const u8,
        out_x_be: *mut u8,
        out_y_be: *mut u8,
    ) -> c_int;

    pub fn bb_grumpkin_msm(
        xs_be: *const u8,
        ys_be: *const u8,
        inf_flags: *const u8,
        n_points: size_t,
        scalars_lo_be16: *const u8,
        scalars_hi_be16: *const u8,
        out_x_be: *mut u8,
        out_y_be: *mut u8,
        out_infinite: *mut u8,
    ) -> c_int;

    pub fn bb_grumpkin_hash_to_curve(
        inputs_be: *const u8,
        n_elems: size_t,
        domain: u32,
        out_x_be: *mut u8,
        out_y_be: *mut u8,
    ) -> c_int;
}
