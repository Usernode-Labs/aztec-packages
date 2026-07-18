#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use libc::{c_int, size_t};

pub use aztec_barretenberg_crypto_sys_rs::{
    bb_free, bb_grumpkin_compress, bb_grumpkin_decompress, bb_grumpkin_derive_pubkey,
    bb_grumpkin_ec_add, bb_grumpkin_hash_to_curve, bb_grumpkin_msm, bb_poseidon2_permutation_bn254,
    bb_schnorr_blake2s_sign, bb_schnorr_blake2s_verify_xy,
};

// Low-level prover/SRS FFI provided by `bb_rust_prover_api`. Primitive FFI is
// re-exported above so existing users of this crate keep the same source API.

pub mod crs_embedded {
    include!(concat!(env!("OUT_DIR"), "/crs_embedded.rs"));
}

extern "C" {
    pub fn srs_init_srs(points_buf: *const u8, num_points_be: *const u32, g2_point_buf: *const u8);
    pub fn srs_init_grumpkin_srs(points_buf: *const u8, num_points_be: *const u32);

    pub fn bb_mega_honk_vk_from_acir(
        acir: *const u8,
        acir_len: size_t,
        out_vk: *mut *mut u8,
        out_vk_len: *mut size_t,
    ) -> c_int;

    pub fn bb_mh_circuit_metadata(
        acir: *const u8,
        acir_len: size_t,
        out_log_dyadic_size: *mut u32,
        out_max_log_dyadic_size: *mut u32,
        out_num_public_inputs: *mut size_t,
    ) -> c_int;

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

    pub fn bb_mh_verify_default(
        proof: *const u8,
        proof_len: size_t,
        vk: *const u8,
        vk_len: size_t,
        out_ok: *mut bool,
    ) -> c_int;

    pub fn bb_verify_batch_merge_leaf(
        proof: *const u8,
        proof_len: size_t,
        out_ok: *mut bool,
    ) -> c_int;

    pub fn bb_verify_batch_merge(proof: *const u8, proof_len: size_t, out_ok: *mut bool) -> c_int;

    pub fn bb_mh_public_inputs(
        proof: *const u8,
        proof_len: size_t,
        vk: *const u8,
        vk_len: size_t,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge_public_inputs_leaf(
        proof: *const u8,
        proof_len: size_t,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge_public_inputs(
        proof: *const u8,
        proof_len: size_t,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge_leaf_vk(out_ptr: *mut *mut u8, out_len: *mut size_t) -> c_int;

    pub fn bb_batch_merge_agg_vk(out_ptr: *mut *mut u8, out_len: *mut size_t) -> c_int;

    pub fn bb_mh_vk_hash(vk: *const u8, vk_len: size_t, out_be32: *mut u8) -> c_int;

    pub fn bb_uhz_verify(
        proof: *const u8,
        proof_len: size_t,
        vk: *const u8,
        vk_len: size_t,
        out_ok: *mut bool,
    ) -> c_int;

    pub fn bb_uhz_public_inputs(
        proof: *const u8,
        proof_len: size_t,
        vk: *const u8,
        vk_len: size_t,
        out_ptr: *mut *mut u8,
        out_len: *mut size_t,
    ) -> c_int;

    pub fn bb_uhz_leaf_vk(
        vk: *const u8,
        vk_len: size_t,
        out_vk: *mut *mut u8,
        out_vk_len: *mut size_t,
    ) -> c_int;

    pub fn bb_uhz_leaf_wrap(
        proof: *const u8,
        proof_len: size_t,
        vk: *const u8,
        vk_len: size_t,
        expected_leaf_be32: *const u8,
        out_wrapped_proof: *mut *mut u8,
        out_wrapped_proof_len: *mut size_t,
        out_wrapped_vk: *mut *mut u8,
        out_wrapped_vk_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge_leaf(
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
    ) -> c_int;

    pub fn bb_batch_merge_leaf_with_vk(
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

    pub fn bb_batch_merge_from_leaf_merges(
        proof_a: *const u8,
        len_a: size_t,
        proof_b: *const u8,
        len_b: size_t,
        out_merged_proof: *mut *mut u8,
        out_merged_proof_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge_from_leaf_merges_with_vk(
        proof_a: *const u8,
        len_a: size_t,
        proof_b: *const u8,
        len_b: size_t,
        out_merged_proof: *mut *mut u8,
        out_merged_proof_len: *mut size_t,
        out_merged_vk: *mut *mut u8,
        out_merged_vk_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge(
        proof_a: *const u8,
        len_a: size_t,
        proof_b: *const u8,
        len_b: size_t,
        out_merged_proof: *mut *mut u8,
        out_merged_proof_len: *mut size_t,
    ) -> c_int;

    pub fn bb_batch_merge_with_vk(
        proof_a: *const u8,
        len_a: size_t,
        proof_b: *const u8,
        len_b: size_t,
        out_merged_proof: *mut *mut u8,
        out_merged_proof_len: *mut size_t,
        out_merged_vk: *mut *mut u8,
        out_merged_vk_len: *mut size_t,
    ) -> c_int;

}
