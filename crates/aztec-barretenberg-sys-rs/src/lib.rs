#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use libc::{c_char, c_int, size_t};

// Low-level FFI to the C++ shim. These symbols will be provided by the
// future `bb_rust_api` static library built via build.rs + CMake.

extern "C" {
    pub fn bb_set_crs_path(path: *const c_char);

    pub fn bb_acir_sizes(acir: *const u8, acir_len: size_t, out_total: *mut u32, out_subgroup: *mut u32) -> c_int;

    pub fn bb_mh_write_vk(acir: *const u8, acir_len: size_t, out_vk: *mut *mut u8, out_vk_len: *mut size_t)
        -> c_int;

    pub fn bb_mh_prove(
        acir: *const u8,
        acir_len: size_t,
        witness: *const u8,
        witness_len: size_t,
        out_proof: *mut *mut u8,
        out_proof_len: *mut size_t,
        out_vk: *mut *mut u8,
        out_vk_len: *mut size_t,
    ) -> c_int;

    pub fn bb_mh_verify(
        proof: *const u8,
        proof_len: size_t,
        vk: *const u8,
        vk_len: size_t,
        out_ok: *mut bool,
    ) -> c_int;

    pub fn bb_mh_public_inputs(
        proof: *const u8,
        proof_len: size_t,
        vk: *const u8,
        vk_len: size_t,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    pub fn bb_mh_vk_hash(
        vk: *const u8,
        vk_len: size_t,
        out_be32: *mut u8,
    ) -> c_int;

    pub fn bb_mh_proof_fields_hash(
        proof: *const u8,
        proof_len: size_t,
        tag: u32,
        out_be32: *mut u8,
    ) -> c_int;

    pub fn bb_merge_mega(
        proof_a: *const u8,
        len_a: size_t,
        vk_a: *const u8,
        len_vk_a: size_t,
        proof_b: *const u8,
        len_b: size_t,
        vk_b: *const u8,
        len_vk_b: size_t,
        out_merged_proof: *mut *mut u8,
        out_merged_proof_len: *mut size_t,
        out_merged_vk: *mut *mut u8,
        out_merged_vk_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge_h2(
        proof_a: *const u8,
        len_a: size_t,
        vk_a: *const u8,
        len_vk_a: size_t,
        proof_b: *const u8,
        len_b: size_t,
        vk_b: *const u8,
        len_vk_b: size_t,
        out_merged_proof: *mut *mut u8,
        out_merged_proof_len: *mut size_t,
        out_merged_vk: *mut *mut u8,
        out_merged_vk_len: *mut size_t,
    ) -> c_int;

    pub fn bb_schnorr_poseidon2_sign(
        msg: *const u8,
        msg_len: size_t,
        sk32: *const u8,
        sig64_out: *mut u8,
    ) -> c_int;

    pub fn bb_schnorr_poseidon2_verify(
        msg: *const u8,
        msg_len: size_t,
        sig64: *const u8,
        pk32: *const u8,
        out_ok: *mut bool,
    ) -> c_int;

    pub fn bb_schnorr_poseidon2_verify_xy(
        msg: *const u8,
        msg_len: size_t,
        sig64: *const u8,
        pkx32: *const u8,
        pky32: *const u8,
        out_ok: *mut bool,
    ) -> c_int;

    pub fn bb_schnorr_pedersen_sign(
        msg: *const u8,
        msg_len: size_t,
        sk32: *const u8,
        sig64_out: *mut u8,
    ) -> c_int;

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



    pub fn bb_schnorr_pedersen_verify_xy(
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

    // Additional FFI for blackbox solvers
    pub fn bb_poseidon2_permutation_bn254(
        inputs_be: *const u8,
        element_count: size_t,
        out_be: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    pub fn bb_pedersen_commit_grumpkin(
        inputs_be: *const u8,
        n_elems: size_t,
        domain: u32,
        out_x_be: *mut u8,
        out_y_be: *mut u8,
    ) -> c_int;

    pub fn bb_pedersen_hash_grumpkin(
        inputs_be: *const u8,
        n_elems: size_t,
        domain: u32,
        out_be: *mut u8,
    ) -> c_int;

    pub fn bb_grumpkin_ec_add(
        pk1_x_be: *const u8,
        pk1_y_be: *const u8,
        pk2_x_be: *const u8,
        pk2_y_be: *const u8,
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

    // Grumpkin scalar field arithmetic (32-byte big-endian inputs/outputs)
    pub fn bb_grumpkin_fr_add(
        a32: *const u8,
        b32: *const u8,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;
    pub fn bb_grumpkin_fr_sub(
        a32: *const u8,
        b32: *const u8,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;
    pub fn bb_grumpkin_fr_mul(
        a32: *const u8,
        b32: *const u8,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    // BN254 Fr arithmetic helpers (32-byte big-endian inputs/outputs)
    pub fn bb_fr_add(
        a32: *const u8,
        b32: *const u8,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;
    pub fn bb_fr_sub(
        a32: *const u8,
        b32: *const u8,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;
    pub fn bb_fr_mul(
        a32: *const u8,
        b32: *const u8,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;
    pub fn bb_fr_cmp(a32: *const u8, b32: *const u8) -> c_int;
}
