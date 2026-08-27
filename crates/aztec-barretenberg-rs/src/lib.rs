use acir::AcirField;
use acir_field::FieldElement as FE;
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum BbError {
    #[error("ffi not linked: {0}")]
    FfiUnavailable(&'static str),
    #[error("circuit exceeds proof size limit")]
    SizeLimit,
    #[error("operation failed: {0}")]
    Failure(&'static str),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("malformed proof blob")]
    MalformedProof,
    #[error("malformed verification key blob")]
    MalformedVk,
    #[error("proof/vk exceeds size limit")]
    SizeLimit,
    #[error("proof/vk layout does not match verifier endpoint")]
    WrongProofType,
    #[error("verification backend failed")]
    Internal,
}

pub struct Vk(pub Vec<u8>);
pub struct Proof(pub Vec<u8>);
pub struct Witness(pub Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MegaHonkCircuitMetadata {
    pub log_dyadic_size: u32,
    pub max_log_dyadic_size: u32,
    pub num_public_inputs: usize,
}

fn init_crs_from_bytes(
    bn254_g1: &[u8],
    bn254_g1_points: u32,
    bn254_g2: &[u8],
    grumpkin_g1: &[u8],
    grumpkin_points: u32,
) -> std::result::Result<(), BbError> {
    const POINT_SIZE: usize = 64;
    let expected_g1_bytes = bn254_g1_points as usize * POINT_SIZE;
    let expected_grumpkin_bytes = grumpkin_points as usize * POINT_SIZE;
    if bn254_g1.len() != expected_g1_bytes {
        return Err(BbError::Failure("bn254_g1 length mismatch"));
    }
    if bn254_g2.len() != 128 {
        return Err(BbError::Failure("bn254_g2 length mismatch"));
    }
    if grumpkin_g1.len() != expected_grumpkin_bytes {
        return Err(BbError::Failure("grumpkin_g1 length mismatch"));
    }

    let bn254_points_be = bn254_g1_points.to_be();
    let grumpkin_points_be = grumpkin_points.to_be();
    unsafe {
        aztec_barretenberg_sys_rs::srs_init_srs(
            bn254_g1.as_ptr(),
            &bn254_points_be as *const u32,
            bn254_g2.as_ptr(),
        );
        aztec_barretenberg_sys_rs::srs_init_grumpkin_srs(
            grumpkin_g1.as_ptr(),
            &grumpkin_points_be as *const u32,
        );
    }
    Ok(())
}

static CRS_INIT: OnceLock<std::result::Result<(), BbError>> = OnceLock::new();

fn init_embedded_crs_internal() -> std::result::Result<(), BbError> {
    CRS_INIT
        .get_or_init(|| {
            init_crs_from_bytes(
                aztec_barretenberg_sys_rs::crs_embedded::BN254_G1,
                aztec_barretenberg_sys_rs::crs_embedded::BN254_G1_POINTS,
                aztec_barretenberg_sys_rs::crs_embedded::BN254_G2,
                aztec_barretenberg_sys_rs::crs_embedded::GRUMPKIN_G1,
                aztec_barretenberg_sys_rs::crs_embedded::GRUMPKIN_POINTS,
            )
        })
        .clone()
}

fn ensure_crs() -> std::result::Result<(), BbError> {
    init_embedded_crs_internal()
}

pub fn mega_honk_vk_from_acir(_acir: &[u8]) -> std::result::Result<Vk, BbError> {
    ensure_crs()?;
    unsafe {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_mega_honk_vk_from_acir(
            _acir.as_ptr(),
            _acir.len(),
            &mut out_ptr,
            &mut out_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("mega_honk_vk_from_acir"));
        }
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let vk = Vk(slice.to_vec());
        aztec_barretenberg_sys_rs::bb_free(out_ptr);
        Ok(vk)
    }
}

pub fn mega_honk_circuit_metadata(
    _acir: &[u8],
) -> std::result::Result<MegaHonkCircuitMetadata, BbError> {
    ensure_crs()?;
    unsafe {
        let mut log_dyadic_size: u32 = 0;
        let mut max_log_dyadic_size: u32 = 0;
        let mut num_public_inputs: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_mh_circuit_metadata(
            _acir.as_ptr(),
            _acir.len(),
            &mut log_dyadic_size,
            &mut max_log_dyadic_size,
            &mut num_public_inputs,
        );
        if rc != 0 {
            return Err(BbError::Failure("mega_honk_circuit_metadata"));
        }
        Ok(MegaHonkCircuitMetadata {
            log_dyadic_size,
            max_log_dyadic_size,
            num_public_inputs,
        })
    }
}

pub fn prove_mega_honk(_acir: &[u8], _witness: &[u8]) -> std::result::Result<(Proof, Vk), BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_mh_prove(
            _acir.as_ptr(),
            _acir.len(),
            _witness.as_ptr(),
            _witness.len(),
            &mut p_ptr,
            &mut p_len,
            &mut v_ptr,
            &mut v_len,
        );
        if rc != 0 {
            if rc == 4 {
                return Err(BbError::SizeLimit);
            }
            return Err(BbError::Failure("prove_mega_honk"));
        }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok((proof, vk))
    }
}

fn map_verify_rc(rc: i32) -> std::result::Result<(), VerifyError> {
    match rc {
        0 => Ok(()),
        2 => Err(VerifyError::MalformedProof),
        3 => Err(VerifyError::MalformedVk),
        4 => Err(VerifyError::SizeLimit),
        5 => Err(VerifyError::WrongProofType),
        _ => Err(VerifyError::Internal),
    }
}

/// Verify a MegaHonk leaf-style proof (default IO layout).
pub fn verify_mega_honk_leaf(_proof: &[u8], _vk: &[u8]) -> std::result::Result<bool, VerifyError> {
    ensure_crs().map_err(|_| VerifyError::Internal)?;
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_mh_verify_default(
            _proof.as_ptr(),
            _proof.len(),
            _vk.as_ptr(),
            _vk.len(),
            &mut ok,
        );
        map_verify_rc(rc)?;
        Ok(ok)
    }
}

/// Verify an UltraZK Honk proof with the provided VK bytes.
///
/// Semantics:
/// - `Ok(true)`: proof is valid.
/// - `Ok(false)`: proof/VK are well-formed but verification failed.
/// - `Err(_)`: malformed blobs, size-limit rejection, or internal failure.
pub fn verify_ultra_zk_honk(_proof: &[u8], _vk: &[u8]) -> std::result::Result<bool, VerifyError> {
    ensure_crs().map_err(|_| VerifyError::Internal)?;
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_uhz_verify(
            _proof.as_ptr(),
            _proof.len(),
            _vk.as_ptr(),
            _vk.len(),
            &mut ok,
        );
        map_verify_rc(rc)?;
        Ok(ok)
    }
}

/// Return Mega proof public inputs as concatenated 32-byte big-endian field bytes.
/// The number of public inputs is determined from the provided VK.
pub fn mega_honk_public_inputs(_proof: &[u8], _vk: &[u8]) -> std::result::Result<Vec<u8>, BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_mh_public_inputs(
            _proof.as_ptr(),
            _proof.len(),
            _vk.as_ptr(),
            _vk.len(),
            &mut p_ptr,
            &mut p_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("mega_honk_public_inputs"));
        }
        let out = std::slice::from_raw_parts(p_ptr, p_len).to_vec();
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(out)
    }
}

/// Return UltraZK proof public inputs as concatenated 32-byte big-endian field bytes.
/// The number of public inputs is determined from the provided VK.
pub fn ultra_zk_public_inputs(_proof: &[u8], _vk: &[u8]) -> std::result::Result<Vec<u8>, BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_uhz_public_inputs(
            _proof.as_ptr(),
            _proof.len(),
            _vk.as_ptr(),
            _vk.len(),
            &mut p_ptr,
            &mut p_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("ultra_zk_public_inputs"));
        }
        let out = std::slice::from_raw_parts(p_ptr, p_len).to_vec();
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(out)
    }
}

/// Compute the Mega VK hash (32-byte big-endian field element) from VK bytes.
pub fn mega_honk_vk_hash(_vk: &[u8]) -> std::result::Result<[u8; 32], BbError> {
    ensure_crs()?;
    unsafe {
        let mut out = [0u8; 32];
        let rc =
            aztec_barretenberg_sys_rs::bb_mh_vk_hash(_vk.as_ptr(), _vk.len(), out.as_mut_ptr());
        if rc != 0 {
            return Err(BbError::Failure("mega_honk_vk_hash"));
        }
        Ok(out)
    }
}

/// Derive the Mega wrapper VK used to recursive-verify an UltraZK proof and expose
/// a Poseidon2 commitment to all inner UltraZK public inputs as the sole *semantic* outer public input
/// (in addition to DefaultIO pairing-point public inputs used for recursive aggregation).
pub fn mega_honk_vk_for_ultra_zk_leaf_wrapper(_vk: &[u8]) -> std::result::Result<Vk, VerifyError> {
    ensure_crs().map_err(|_| VerifyError::Internal)?;
    unsafe {
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_uhz_leaf_vk(
            _vk.as_ptr(),
            _vk.len(),
            &mut v_ptr,
            &mut v_len,
        );
        match map_verify_rc(rc) {
            Ok(()) => {
                let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
                aztec_barretenberg_sys_rs::bb_free(v_ptr);
                Ok(vk)
            }
            Err(err) => Err(err),
        }
    }
}

/// Wrap an UltraZK proof into a Mega leaf proof.
///
/// The wrapper circuit enforces:
/// - inner UltraZK proof verifies against `vk`,
/// - Poseidon2(inner_public_inputs[]) equals `expected_leaf_be32`,
/// - outer proof exposes exactly that commitment as its sole *semantic* public input
///   (plus DefaultIO pairing-point public inputs for recursive aggregation).
pub fn wrap_ultra_zk_as_mega_honk_leaf(
    _proof: &[u8],
    _vk: &[u8],
    expected_scoped_nullifier: [u8; 32],
) -> std::result::Result<(Proof, Vk), VerifyError> {
    ensure_crs().map_err(|_| VerifyError::Internal)?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_uhz_leaf_wrap(
            _proof.as_ptr(),
            _proof.len(),
            _vk.as_ptr(),
            _vk.len(),
            expected_scoped_nullifier.as_ptr(),
            &mut p_ptr,
            &mut p_len,
            &mut v_ptr,
            &mut v_len,
        );
        match map_verify_rc(rc) {
            Ok(()) => {
                let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
                let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
                aztec_barretenberg_sys_rs::bb_free(p_ptr);
                aztec_barretenberg_sys_rs::bb_free(v_ptr);
                Ok((proof, vk))
            }
            Err(err) => Err(err),
        }
    }
}

/// Merge two leaf proofs (children with potentially different VKs).
pub fn batch_merge_leaf(
    pa: &[u8],
    vka: &[u8],
    pb: &[u8],
    vkb: &[u8],
) -> std::result::Result<Proof, BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_leaf(
            pa.as_ptr(),
            pa.len(),
            vka.as_ptr(),
            vka.len(),
            pb.as_ptr(),
            pb.len(),
            vkb.as_ptr(),
            vkb.len(),
            &mut p_ptr,
            &mut p_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_leaf"));
        }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(proof)
    }
}

/// Merge two leaf proofs and return both the merged proof and the verifier key
/// for the resulting level-1 merge circuit.
pub fn batch_merge_leaf_with_vk(
    pa: &[u8],
    vka: &[u8],
    pb: &[u8],
    vkb: &[u8],
) -> std::result::Result<(Proof, Vk), BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_leaf_with_vk(
            pa.as_ptr(),
            pa.len(),
            vka.as_ptr(),
            vka.len(),
            pb.as_ptr(),
            pb.len(),
            vkb.as_ptr(),
            vkb.len(),
            &mut p_ptr,
            &mut p_len,
            &mut v_ptr,
            &mut v_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_leaf_with_vk"));
        }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok((proof, vk))
    }
}

/// Merge two merge-proofs whose children are leaf-merge proofs.
pub fn batch_merge_from_leaf_merges(pa: &[u8], pb: &[u8]) -> std::result::Result<Proof, BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_from_leaf_merges(
            pa.as_ptr(),
            pa.len(),
            pb.as_ptr(),
            pb.len(),
            &mut p_ptr,
            &mut p_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_from_leaf_merges"));
        }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(proof)
    }
}

/// Merge two level-1 merge proofs and return both the merged proof and the
/// verifier key for the resulting aggregate merge circuit.
pub fn batch_merge_from_leaf_merges_with_vk(
    pa: &[u8],
    pb: &[u8],
) -> std::result::Result<(Proof, Vk), BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_from_leaf_merges_with_vk(
            pa.as_ptr(),
            pa.len(),
            pb.as_ptr(),
            pb.len(),
            &mut p_ptr,
            &mut p_len,
            &mut v_ptr,
            &mut v_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_from_leaf_merges_with_vk"));
        }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok((proof, vk))
    }
}

/// Merge two aggregate merge-proofs (depth >= 2).
pub fn batch_merge(pa: &[u8], pb: &[u8]) -> std::result::Result<Proof, BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge(
            pa.as_ptr(),
            pa.len(),
            pb.as_ptr(),
            pb.len(),
            &mut p_ptr,
            &mut p_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge"));
        }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(proof)
    }
}

/// Merge two aggregate merge-proofs and return both the merged proof and the
/// verifier key for the resulting aggregate merge circuit.
pub fn batch_merge_with_vk(pa: &[u8], pb: &[u8]) -> std::result::Result<(Proof, Vk), BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_with_vk(
            pa.as_ptr(),
            pa.len(),
            pb.as_ptr(),
            pb.len(),
            &mut p_ptr,
            &mut p_len,
            &mut v_ptr,
            &mut v_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_with_vk"));
        }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok((proof, vk))
    }
}

/// Verify a leaf-level merge proof against the embedded leaf-merge VK.
pub fn verify_batch_merge_leaf(proof: &[u8]) -> std::result::Result<bool, VerifyError> {
    ensure_crs().map_err(|_| VerifyError::Internal)?;
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_verify_batch_merge_leaf(
            proof.as_ptr(),
            proof.len(),
            &mut ok,
        );
        map_verify_rc(rc)?;
        Ok(ok)
    }
}

/// Verify a merge-proof of merge-proofs against the embedded aggregate-merge VK.
pub fn verify_batch_merge(proof: &[u8]) -> std::result::Result<bool, VerifyError> {
    ensure_crs().map_err(|_| VerifyError::Internal)?;
    unsafe {
        let mut ok = false;
        let rc =
            aztec_barretenberg_sys_rs::bb_verify_batch_merge(proof.as_ptr(), proof.len(), &mut ok);
        map_verify_rc(rc)?;
        Ok(ok)
    }
}

/// Extract leaf-level merge proof public inputs using the embedded leaf-merge VK.
pub fn batch_merge_public_inputs_leaf(proof: &[u8]) -> std::result::Result<Vec<u8>, BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_public_inputs_leaf(
            proof.as_ptr(),
            proof.len(),
            &mut p_ptr,
            &mut p_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_public_inputs_leaf"));
        }
        let out = std::slice::from_raw_parts(p_ptr, p_len).to_vec();
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(out)
    }
}

/// Extract merge-proof public inputs using the embedded aggregate-merge VK.
pub fn batch_merge_public_inputs(proof: &[u8]) -> std::result::Result<Vec<u8>, BbError> {
    ensure_crs()?;
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_public_inputs(
            proof.as_ptr(),
            proof.len(),
            &mut p_ptr,
            &mut p_len,
        );
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_public_inputs"));
        }
        let out = std::slice::from_raw_parts(p_ptr, p_len).to_vec();
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(out)
    }
}

/// Return the embedded VK bytes used for leaf-level merge proofs.
pub fn batch_merge_leaf_vk() -> std::result::Result<Vk, BbError> {
    ensure_crs()?;
    unsafe {
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_leaf_vk(&mut v_ptr, &mut v_len);
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_leaf_vk"));
        }
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok(vk)
    }
}

/// Return the embedded VK bytes used for aggregate merge proofs.
pub fn batch_merge_agg_vk() -> std::result::Result<Vk, BbError> {
    ensure_crs()?;
    unsafe {
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_agg_vk(&mut v_ptr, &mut v_len);
        if rc != 0 {
            return Err(BbError::Failure("batch_merge_agg_vk"));
        }
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok(vk)
    }
}

pub mod acvm_exec {
    use super::{BbError, Witness};
    use crate::BarretenbergBlackBoxSolver;
    use crate::FE;
    use acir::circuit::Program;
    use acir::native_types::{WitnessMap, WitnessStack};
    use acvm::pwg::{ACVMStatus, ACVM};
    use bincode;

    // Public API: compute witness from a flat list of field elements, mapped in order to
    // the circuit's private_parameters (sorted by witness index). This avoids any Prover.toml or ABI parsing.
    pub fn compute_witness_from_private_inputs(
        acir_bytes: &[u8],
        private_inputs: &[FE],
    ) -> std::result::Result<Witness, BbError> {
        // Deserialize ACIR program
        let program: Program<FE> = match acir::circuit::Program::deserialize_program(acir_bytes) {
            Ok(p) => p,
            Err(_) => bincode::deserialize(acir_bytes)
                .map_err(|_| BbError::Failure("deserialize ACIR program"))?,
        };
        if program.functions.is_empty() {
            return Err(BbError::Failure("empty program"));
        }

        // Seed private parameters (in sorted index order) with provided inputs.
        let func = &program.functions[0];
        let mut indices: Vec<u32> = func
            .private_parameters
            .iter()
            .map(|w| match *w {
                acir::native_types::Witness(idx) => idx,
            })
            .collect();
        indices.sort_unstable();
        if private_inputs.len() > indices.len() {
            return Err(BbError::Failure("more inputs than private parameters"));
        }
        let mut initial = WitnessMap::new();
        for (i, fe) in private_inputs.iter().enumerate() {
            initial.insert(acir::native_types::Witness(indices[i]), *fe);
        }

        // Solve with Barretenberg-backed solver
        let solver = BarretenbergBlackBoxSolver;
        let mut acvm: ACVM<'_, FE, _> = ACVM::new(
            &solver,
            &func.opcodes,
            initial,
            &program.unconstrained_functions,
            &func.assert_messages,
        );
        loop {
            match acvm.solve() {
                ACVMStatus::Solved => break,
                ACVMStatus::RequiresForeignCall(_) | ACVMStatus::RequiresAcirCall(_) => {
                    return Err(BbError::Failure("unsupported: foreign/acir call in ACVM"));
                }
                ACVMStatus::Failure(_) => return Err(BbError::Failure("acvm failure")),
                ACVMStatus::InProgress => continue,
            }
        }
        let witness_map = acvm.finalize();
        let stack: WitnessStack<FE> = WitnessStack::from(witness_map);
        let gz = stack
            .serialize()
            .map_err(|_| BbError::Failure("witness stack serialize"))?;
        let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
        let mut out = Vec::new();
        use std::io::Read;
        dec.read_to_end(&mut out)
            .map_err(|_| BbError::Failure("gunzip witness stack"))?;
        Ok(Witness(out))
    }
}

#[derive(Default, Clone, Copy)]
pub struct BarretenbergBlackBoxSolver;

impl BarretenbergBlackBoxSolver {
    pub fn is_supported_environment(&self) -> bool {
        // For now, this solver only wires Schnorr(Poseidon2) when the optional
        // experimental functionality is compiled in. Extend as needed.
        true
    }
}

impl acvm::blackbox_solver::BlackBoxFunctionSolver<FE> for BarretenbergBlackBoxSolver {
    fn multi_scalar_mul(
        &self,
        _points: &[FE],
        _scalars_lo: &[FE],
        _scalars_hi: &[FE],
        _predicate: bool,
    ) -> std::result::Result<(FE, FE), acvm::BlackBoxResolutionError> {
        if !_predicate {
            return Ok((FE::zero(), FE::zero()));
        }
        if _points.len() % 2 != 0
            || _scalars_lo.len() != _scalars_hi.len()
            || _points.len() / 2 != _scalars_lo.len()
        {
            return Err(acvm::BlackBoxResolutionError::Failed(
                acir::BlackBoxFunc::MultiScalarMul,
                "length mismatch: points must be pairs and match scalars".into(),
            ));
        }
        let n = _scalars_lo.len();
        let mut xs = Vec::with_capacity(n * 32);
        let mut ys = Vec::with_capacity(n * 32);
        let mut inf = Vec::with_capacity(n);
        for i in 0..n {
            let x = _points[2 * i];
            let y = _points[2 * i + 1];
            let x_be = x.to_be_bytes();
            let y_be = y.to_be_bytes();
            xs.extend_from_slice(&x_be[x_be.len() - 32..]);
            ys.extend_from_slice(&y_be[y_be.len() - 32..]);
            // Noir beta.22 represents the point at infinity as (0, 0).
            inf.push(u8::from(x.is_zero() && y.is_zero()));
        }
        // scalars are split into two 128-bit limbs, big-endian each
        let mut slo = Vec::with_capacity(n * 16);
        let mut shi = Vec::with_capacity(n * 16);
        for i in 0..n {
            let Some(lo) = _scalars_lo[i].try_into_u128() else {
                return Err(acvm::BlackBoxResolutionError::Failed(
                    acir::BlackBoxFunc::MultiScalarMul,
                    "low scalar limb is not less than 2^128".into(),
                ));
            };
            let Some(hi) = _scalars_hi[i].try_into_u128() else {
                return Err(acvm::BlackBoxResolutionError::Failed(
                    acir::BlackBoxFunc::MultiScalarMul,
                    "high scalar limb is not less than 2^128".into(),
                ));
            };
            let mut scalar_be = [0u8; 32];
            scalar_be[..16].copy_from_slice(&hi.to_be_bytes());
            scalar_be[16..].copy_from_slice(&lo.to_be_bytes());
            const GRUMPKIN_SCALAR_MODULUS_BE: [u8; 32] = [
                0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
                0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16,
                0xd8, 0x7c, 0xfd, 0x47,
            ];
            if scalar_be >= GRUMPKIN_SCALAR_MODULUS_BE {
                return Err(acvm::BlackBoxResolutionError::Failed(
                    acir::BlackBoxFunc::MultiScalarMul,
                    "scalar is not in the Grumpkin scalar field".into(),
                ));
            }
            slo.extend_from_slice(&scalar_be[16..]);
            shi.extend_from_slice(&scalar_be[..16]);
        }
        let mut out_x = [0u8; 32];
        let mut out_y = [0u8; 32];
        let mut out_inf = 0u8;
        let rc = unsafe {
            aztec_barretenberg_sys_rs::bb_grumpkin_msm(
                xs.as_ptr(),
                ys.as_ptr(),
                inf.as_ptr(),
                n as _,
                slo.as_ptr(),
                shi.as_ptr(),
                out_x.as_mut_ptr(),
                out_y.as_mut_ptr(),
                &mut out_inf as *mut u8,
            )
        };
        if rc != 0 {
            return Err(acvm::BlackBoxResolutionError::Failed(
                acir::BlackBoxFunc::MultiScalarMul,
                "bb grumpkin msm failed".into(),
            ));
        }
        if out_inf != 0 {
            Ok((FE::zero(), FE::zero()))
        } else {
            Ok((
                FE::from_be_bytes_reduce(&out_x),
                FE::from_be_bytes_reduce(&out_y),
            ))
        }
    }

    fn ec_add(
        &self,
        _input1_x: &FE,
        _input1_y: &FE,
        _input2_x: &FE,
        _input2_y: &FE,
        _predicate: bool,
    ) -> std::result::Result<(FE, FE), acvm::BlackBoxResolutionError> {
        if !_predicate {
            return Ok((FE::zero(), FE::zero()));
        }
        let input1_infinite = _input1_x.is_zero() && _input1_y.is_zero();
        let input2_infinite = _input2_x.is_zero() && _input2_y.is_zero();
        if input1_infinite {
            return Ok((*_input2_x, *_input2_y));
        }
        if input2_infinite {
            return Ok((*_input1_x, *_input1_y));
        }
        let x1 = _input1_x.to_be_bytes();
        let y1 = _input1_y.to_be_bytes();
        let x2 = _input2_x.to_be_bytes();
        let y2 = _input2_y.to_be_bytes();
        let mut out_x = [0u8; 32];
        let mut out_y = [0u8; 32];
        let rc = unsafe {
            aztec_barretenberg_sys_rs::bb_grumpkin_ec_add(
                x1.as_ptr().add(x1.len() - 32),
                y1.as_ptr().add(y1.len() - 32),
                x2.as_ptr().add(x2.len() - 32),
                y2.as_ptr().add(y2.len() - 32),
                out_x.as_mut_ptr(),
                out_y.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(acvm::BlackBoxResolutionError::Failed(
                acir::BlackBoxFunc::EmbeddedCurveAdd,
                "bb grumpkin ec_add failed".into(),
            ));
        }
        Ok((
            FE::from_be_bytes_reduce(&out_x),
            FE::from_be_bytes_reduce(&out_y),
        ))
    }

    fn poseidon2_permutation(
        &self,
        _inputs: &[FE],
    ) -> std::result::Result<Vec<FE>, acvm::BlackBoxResolutionError> {
        if _inputs.len() != 4 {
            return Err(acvm::BlackBoxResolutionError::Failed(
                acir::BlackBoxFunc::Poseidon2Permutation,
                "only t=4 supported".into(),
            ));
        }
        let mut buf = Vec::with_capacity(4 * 32);
        for fe in _inputs {
            let be = fe.to_be_bytes();
            buf.extend_from_slice(&be[be.len() - 32..]);
        }
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            aztec_barretenberg_sys_rs::bb_poseidon2_permutation_bn254(
                buf.as_ptr(),
                4,
                &mut out_ptr,
                &mut out_len,
            )
        };
        if rc != 0 || out_len != 128 {
            return Err(acvm::BlackBoxResolutionError::Failed(
                acir::BlackBoxFunc::Poseidon2Permutation,
                "bb poseidon2 failed".into(),
            ));
        }
        let out_slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
        let mut res = Vec::with_capacity(4);
        for i in 0..4 {
            let mut be = [0u8; 32];
            be.copy_from_slice(&out_slice[i * 32..(i + 1) * 32]);
            res.push(FE::from_be_bytes_reduce(&be));
        }
        unsafe { aztec_barretenberg_sys_rs::bb_free(out_ptr) };
        Ok(res)
    }
}

pub fn grumpkin_derive_pubkey(
    sk32: &[u8; 32],
) -> std::result::Result<([u8; 32], [u8; 32]), BbError> {
    unsafe {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let rc = aztec_barretenberg_sys_rs::bb_grumpkin_derive_pubkey(
            sk32.as_ptr(),
            x.as_mut_ptr(),
            y.as_mut_ptr(),
        );
        if rc != 0 {
            return Err(BbError::Failure("grumpkin_derive_pubkey"));
        }
        Ok((x, y))
    }
}

/// Compress a Grumpkin affine point (x,y) into the 32-byte legacy format.
pub fn grumpkin_compress(x_be: [u8; 32], y_be: [u8; 32]) -> std::result::Result<[u8; 32], BbError> {
    unsafe {
        let mut out = [0u8; 32];
        let rc = aztec_barretenberg_sys_rs::bb_grumpkin_compress(
            x_be.as_ptr(),
            y_be.as_ptr(),
            out.as_mut_ptr(),
        );
        if rc != 0 {
            return Err(BbError::Failure("grumpkin_compress"));
        }
        Ok(out)
    }
}

/// Decompress a 32-byte Grumpkin point encoding back into affine coordinates.
pub fn grumpkin_decompress(
    comp_be: [u8; 32],
) -> std::result::Result<([u8; 32], [u8; 32]), BbError> {
    unsafe {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let rc = aztec_barretenberg_sys_rs::bb_grumpkin_decompress(
            comp_be.as_ptr(),
            x.as_mut_ptr(),
            y.as_mut_ptr(),
        );
        if rc != 0 {
            return Err(BbError::Failure("grumpkin_decompress"));
        }
        Ok((x, y))
    }
}

pub fn schnorr_blake2s_sign(msg: &[u8], sk32: &[u8; 32]) -> std::result::Result<[u8; 64], BbError> {
    unsafe {
        let mut sig = [0u8; 64];
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_blake2s_sign(
            msg.as_ptr(),
            msg.len(),
            sk32.as_ptr(),
            sig.as_mut_ptr(),
        );
        if rc != 0 {
            return Err(BbError::Failure("schnorr_blake2s_sign"));
        }
        Ok(sig)
    }
}

pub fn schnorr_blake2s_verify_xy(
    msg: &[u8],
    sig64: &[u8; 64],
    pkx32: &[u8; 32],
    pky32: &[u8; 32],
) -> std::result::Result<bool, BbError> {
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_blake2s_verify_xy(
            msg.as_ptr(),
            msg.len(),
            sig64.as_ptr(),
            pkx32.as_ptr(),
            pky32.as_ptr(),
            &mut ok,
        );
        if rc != 0 {
            return Err(BbError::Failure("schnorr_blake2s_verify_xy"));
        }
        Ok(ok)
    }
}

/// Map a single 32-byte big-endian field element into a Grumpkin curve point.
pub fn grumpkin_hash_to_curve(
    field_be: [u8; 32],
    domain: u32,
) -> std::result::Result<([u8; 32], [u8; 32]), BbError> {
    unsafe {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let rc = aztec_barretenberg_sys_rs::bb_grumpkin_hash_to_curve(
            field_be.as_ptr(),
            1,
            domain as u32,
            x.as_mut_ptr(),
            y.as_mut_ptr(),
        );
        if rc != 0 {
            return Err(BbError::Failure("grumpkin_hash_to_curve"));
        }
        Ok((x, y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acvm::blackbox_solver::BlackBoxFunctionSolver;

    fn scalar_bytes(val: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&val.to_be_bytes());
        out
    }

    #[test]
    fn grumpkin_compression_roundtrip_generator() {
        let sk = scalar_bytes(1);
        let (x, y) = grumpkin_derive_pubkey(&sk).expect("derive");
        let comp = grumpkin_compress(x, y).expect("compress");
        let (rx, ry) = grumpkin_decompress(comp).expect("decompress");
        assert_eq!(rx, x);
        assert_eq!(ry, y);
    }

    #[test]
    fn grumpkin_compression_roundtrip_multiple_scalars() {
        for scalar in [2u64, 42, 1_234_567, 0xdead_beef] {
            let sk = scalar_bytes(scalar);
            let (x, y) = grumpkin_derive_pubkey(&sk).expect("derive");
            let comp = grumpkin_compress(x, y).expect("compress");
            let (rx, ry) = grumpkin_decompress(comp).expect("decompress");
            assert_eq!(rx, x);
            assert_eq!(ry, y);
        }
    }

    #[test]
    fn grumpkin_decompress_rejects_invalid_bytes() {
        assert!(grumpkin_decompress([0u8; 32]).is_err());
    }

    #[test]
    fn legacy_schnorr_blake2s_roundtrip_and_tamper_rejection() {
        let sk = scalar_bytes(7);
        let message = [42u8; 32];
        let (x, y) = grumpkin_derive_pubkey(&sk).expect("derive");
        let signature = schnorr_blake2s_sign(&message, &sk).expect("sign");

        assert!(
            schnorr_blake2s_verify_xy(&message, &signature, &x, &y).expect("verify"),
            "new signature should verify"
        );

        let mut tampered_message = message;
        tampered_message[0] ^= 1;
        assert!(
            !schnorr_blake2s_verify_xy(&tampered_message, &signature, &x, &y)
                .expect("verify tampered message"),
            "signature must be bound to the message"
        );

        let mut tampered_signature = signature;
        tampered_signature[0] ^= 1;
        assert!(
            !schnorr_blake2s_verify_xy(&message, &tampered_signature, &x, &y)
                .expect("verify tampered signature"),
            "tampered signature must fail"
        );
    }

    #[test]
    fn verifies_signature_created_by_usernode_4_2_release() {
        fn bytes<const N: usize>(value: &str) -> [u8; N] {
            hex::decode(value)
                .expect("valid hex")
                .try_into()
                .expect("correct byte length")
        }

        let message: [u8; 32] = std::array::from_fn(|index| index as u8);
        let public_key_x =
            bytes("0e602b9dd6a3e8d039a17f069add3f9c2a187a8f629a1de60a33a8067b9b2842");
        let public_key_y =
            bytes("14cc8e83df1b5cbb163bd2c94005cb0707fe570def5a165242b1c1419cb014cb");
        let signature = bytes(
            "1e2f50239bf4975346409430e614ecc1f112cecd7c8101eeaa0ccbd12f1259a5\
             7c82d485322deabf32d5d8333f6ecb77dcb712147c98e0683e10a2ca744013b3",
        );

        assert!(
            schnorr_blake2s_verify_xy(&message, &signature, &public_key_x, &public_key_y,)
                .expect("verify v4.2 signature"),
            "v5 shim must preserve signatures created by the previous Usernode release"
        );
    }

    #[test]
    fn beta_22_black_box_solver_preserves_jit_curve_semantics() {
        let solver = BarretenbergBlackBoxSolver;
        let (generator_x_bytes, generator_y_bytes) =
            grumpkin_derive_pubkey(&scalar_bytes(1)).expect("derive generator");
        let generator_x = FE::from_be_bytes_reduce(&generator_x_bytes);
        let generator_y = FE::from_be_bytes_reduce(&generator_y_bytes);

        let (msm_x, msm_y) = solver
            .multi_scalar_mul(
                &[generator_x, generator_y],
                &[FE::one()],
                &[FE::zero()],
                true,
            )
            .expect("one-point MSM");
        assert_eq!((msm_x, msm_y), (generator_x, generator_y));
        assert_eq!(
            solver
                .multi_scalar_mul(&[], &[], &[], false)
                .expect("disabled MSM"),
            (FE::zero(), FE::zero())
        );

        let high_limb_result = solver
            .multi_scalar_mul(
                &[generator_x, generator_y],
                &[FE::one()],
                &[FE::from(2u128)],
                true,
            )
            .expect("MSM with a nonzero high limb");
        assert_eq!(
            high_limb_result,
            (
                FE::from_be_bytes_reduce(
                    &hex::decode(
                        "0702ab9c7038eeecc179b4f209991bcb68c7cb05bf4c532d804ccac36199c9a9"
                    )
                    .expect("valid x coordinate"),
                ),
                FE::from_be_bytes_reduce(
                    &hex::decode(
                        "23f10e9e43a3ae8d75d24154e796aae12ae7af546716e8f81a2564f1b5814130"
                    )
                    .expect("valid y coordinate"),
                ),
            ),
            "split 128-bit scalar limbs must follow the beta.22 ordering"
        );

        assert_eq!(
            solver
                .ec_add(&FE::zero(), &FE::zero(), &generator_x, &generator_y, true,)
                .expect("infinity plus generator"),
            (generator_x, generator_y)
        );

        let (twice_x_bytes, twice_y_bytes) =
            grumpkin_derive_pubkey(&scalar_bytes(2)).expect("derive twice generator");
        let twice_generator = (
            FE::from_be_bytes_reduce(&twice_x_bytes),
            FE::from_be_bytes_reduce(&twice_y_bytes),
        );
        assert_eq!(
            solver
                .ec_add(&generator_x, &generator_y, &generator_x, &generator_y, true,)
                .expect("double generator"),
            twice_generator
        );
        assert_eq!(
            solver
                .ec_add(
                    &generator_x,
                    &generator_y,
                    &generator_x,
                    &(-generator_y),
                    true,
                )
                .expect("point plus inverse"),
            (FE::zero(), FE::zero())
        );
    }

    #[test]
    fn beta_22_black_box_solver_rejects_invalid_curve_inputs() {
        let solver = BarretenbergBlackBoxSolver;
        let (generator_x_bytes, generator_y_bytes) =
            grumpkin_derive_pubkey(&scalar_bytes(1)).expect("derive generator");
        let generator = [
            FE::from_be_bytes_reduce(&generator_x_bytes),
            FE::from_be_bytes_reduce(&generator_y_bytes),
        ];

        let mut too_wide_limb = [0u8; 32];
        too_wide_limb[15] = 1;
        let too_wide_limb = FE::from_be_bytes_reduce(&too_wide_limb);
        assert!(
            solver
                .multi_scalar_mul(&generator, &[too_wide_limb], &[FE::zero()], true)
                .is_err(),
            "scalar limbs wider than 128 bits must be rejected"
        );

        let modulus =
            hex::decode("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47")
                .expect("valid Grumpkin scalar modulus");
        let high = FE::from_be_bytes_reduce(&modulus[..16]);
        let low = FE::from_be_bytes_reduce(&modulus[16..]);
        assert!(
            solver
                .multi_scalar_mul(&generator, &[low], &[high], true)
                .is_err(),
            "the Grumpkin scalar modulus itself must be rejected"
        );

        assert!(
            solver
                .multi_scalar_mul(&[FE::one(), FE::one()], &[FE::one()], &[FE::zero()], true)
                .is_err(),
            "off-curve points must be rejected"
        );
        assert!(
            solver
                .ec_add(&FE::one(), &FE::one(), &generator[0], &generator[1], true,)
                .is_err(),
            "embedded curve addition must reject off-curve points"
        );

        assert_eq!(
            solver
                .multi_scalar_mul(
                    &[FE::one(), FE::one()],
                    &[too_wide_limb],
                    &[too_wide_limb],
                    false,
                )
                .expect("disabled MSM ignores invalid inputs"),
            (FE::zero(), FE::zero())
        );
    }
}
