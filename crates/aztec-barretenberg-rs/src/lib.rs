use std::path::Path;
use thiserror::Error;
use acir::AcirField;
use acir_field::FieldElement as FE;

#[derive(Debug, Error)]
pub enum BbError {
    #[error("ffi not linked: {0}")]
    FfiUnavailable(&'static str),
    #[error("operation failed: {0}")]
    Failure(&'static str),
}

pub type Result<T> = std::result::Result<T, BbError>;

pub struct Vk(pub Vec<u8>);
pub struct Proof(pub Vec<u8>);
pub struct Witness(pub Vec<u8>);

pub fn set_crs_path(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        use std::ffi::CString;
        let c = CString::new(path.as_ref().to_string_lossy().as_bytes()).unwrap();
        aztec_barretenberg_sys_rs::bb_set_crs_path(c.as_ptr());
        Ok(())
    }
}

pub fn acir_sizes(_acir: &[u8]) -> Result<(u32, u32)> {
    unsafe {
        let mut total: u32 = 0;
        let mut subgroup: u32 = 0;
        let rc = aztec_barretenberg_sys_rs::bb_acir_sizes(_acir.as_ptr(), _acir.len(), &mut total, &mut subgroup);
        if rc == 0 { Ok((total, subgroup)) } else { Err(BbError::Failure("acir_sizes")) }
    }
}

pub fn write_vk_mega_honk(_acir: &[u8]) -> Result<Vk> {
    unsafe {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_mh_write_vk(_acir.as_ptr(), _acir.len(), &mut out_ptr, &mut out_len);
        if rc != 0 { return Err(BbError::Failure("write_vk_mega_honk")); }
        let slice = std::slice::from_raw_parts(out_ptr, out_len);
        let vk = Vk(slice.to_vec());
        aztec_barretenberg_sys_rs::bb_free(out_ptr);
        Ok(vk)
    }
}

pub fn prove_mega_honk(_acir: &[u8], _witness: &[u8]) -> Result<(Proof, Vk)> {
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
        if rc != 0 { return Err(BbError::Failure("prove_mega_honk")); }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok((proof, vk))
    }
}

pub fn verify_mega_honk(_proof: &[u8], _vk: &[u8]) -> Result<bool> {
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_mh_verify(
            _proof.as_ptr(), _proof.len(), _vk.as_ptr(), _vk.len(), &mut ok,
        );
        if rc != 0 { return Err(BbError::Failure("verify_mega_honk")); }
        Ok(ok)
    }
}

/// Return Mega proof public inputs as concatenated 32-byte big-endian field bytes.
/// The number of public inputs is determined from the provided VK.
pub fn mega_public_inputs(_proof: &[u8], _vk: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_mh_public_inputs(
            _proof.as_ptr(), _proof.len(), _vk.as_ptr(), _vk.len(), &mut p_ptr, &mut p_len,
        );
        if rc != 0 { return Err(BbError::Failure("mega_public_inputs")); }
        let out = std::slice::from_raw_parts(p_ptr, p_len).to_vec();
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        Ok(out)
    }
}

/// Compute the Mega VK hash (32-byte big-endian field element) from VK bytes.
pub fn mega_vk_hash(_vk: &[u8]) -> Result<[u8; 32]> {
    unsafe {
        let mut out = [0u8; 32];
        let rc = aztec_barretenberg_sys_rs::bb_mh_vk_hash(_vk.as_ptr(), _vk.len(), out.as_mut_ptr());
        if rc != 0 { return Err(BbError::Failure("mega_vk_hash")); }
        Ok(out)
    }
}

/// Compute Poseidon2 hash (with a domain tag) over the proof fields parsed from bytes.
pub fn mega_proof_fields_hash(_proof: &[u8], tag: u32) -> Result<[u8; 32]> {
    unsafe {
        let mut out = [0u8; 32];
        let rc = aztec_barretenberg_sys_rs::bb_mh_proof_fields_hash(_proof.as_ptr(), _proof.len(), tag, out.as_mut_ptr());
        if rc != 0 { return Err(BbError::Failure("mega_proof_fields_hash")); }
        Ok(out)
    }
}

pub fn merge_mega(_pa: &[u8], _vka: &[u8], _pb: &[u8], _vkb: &[u8]) -> Result<(Proof, Vk)> {
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_merge_mega(
            _pa.as_ptr(), _pa.len(), _vka.as_ptr(), _vka.len(),
            _pb.as_ptr(), _pb.len(), _vkb.as_ptr(), _vkb.len(),
            &mut p_ptr, &mut p_len, &mut v_ptr, &mut v_len,
        );
        if rc != 0 { return Err(BbError::Failure("merge_mega")); }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok((proof, vk))
    }
}

/// Batch-merge two MegaHonk proofs and emit a merged proof+VK. This is currently
/// an alias to `merge_mega` (structural merge only). A dedicated batch-merge circuit
/// that computes and constrains `H2(left,right)` as public output will replace this.
pub fn batch_merge_h2(_pa: &[u8], _vka: &[u8], _pb: &[u8], _vkb: &[u8]) -> Result<(Proof, Vk)> {
    unsafe {
        let mut p_ptr: *mut u8 = std::ptr::null_mut();
        let mut p_len: usize = 0;
        let mut v_ptr: *mut u8 = std::ptr::null_mut();
        let mut v_len: usize = 0;
        let rc = aztec_barretenberg_sys_rs::bb_batch_merge_h2(
            _pa.as_ptr(), _pa.len(),
            _vka.as_ptr(), _vka.len(),
            _pb.as_ptr(), _pb.len(),
            _vkb.as_ptr(), _vkb.len(),
            &mut p_ptr, &mut p_len,
            &mut v_ptr, &mut v_len,
        );
        if rc != 0 { return Err(BbError::Failure("batch_merge_h2")); }
        let proof = Proof(std::slice::from_raw_parts(p_ptr, p_len).to_vec());
        let vk = Vk(std::slice::from_raw_parts(v_ptr, v_len).to_vec());
        aztec_barretenberg_sys_rs::bb_free(p_ptr);
        aztec_barretenberg_sys_rs::bb_free(v_ptr);
        Ok((proof, vk))
    }
}

pub mod acvm_exec {
    use super::{BbError, Result, Witness};
    use acir::circuit::Program;
    use acir::native_types::{WitnessMap, WitnessStack};
    use acvm::blackbox_solver::{BlackBoxFunctionSolver, StubbedBlackBoxSolver};
    use crate::BarretenbergBlackBoxSolver;
    use crate::FE;
    use acvm::pwg::{ACVM, ACVMStatus};
    use bincode;

    // Very small helper: construct an empty WitnessMap.
    fn empty_witness() -> WitnessMap<FE> { WitnessMap::new() }

    // Compute witness assignments for the provided ACIR program using default/private-parameter mapping only.
    pub fn compute_witness(acir_bytes: &[u8], _inputs: &std::collections::HashMap<String, Vec<u8>>) -> Result<Witness> {
        // Deserialize ACIR program from bytes emitted by Nargo.
        // Accept either gzipped (as in program.json bytecode) or raw bincode bytes.
        let program: Program<FE> = match acir::circuit::Program::deserialize_program(acir_bytes) {
            Ok(p) => p,
            Err(_) => bincode::deserialize(acir_bytes)
                .map_err(|_| BbError::Failure("deserialize ACIR program"))?,
        };

        if program.functions.is_empty() {
            return Err(BbError::Failure("empty program"));
        }

        // Build initial (possibly empty) witness map. Many fixtures bake inputs.
        let initial_witness = empty_witness();

        fn run<B: BlackBoxFunctionSolver<FE>>(backend: &B, program: &Program<FE>, initial: WitnessMap<FE>) -> Result<WitnessMap<FE>> {
            let func = &program.functions[0];
            let mut acvm: ACVM<'_, FE, B> = ACVM::new(
                backend,
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
            Ok(acvm.finalize())
        }

        // Prefer Barretenberg-backed solver when available; otherwise fall back to stub.
        let bb_solver = BarretenbergBlackBoxSolver;
        let witness_map = if bb_solver.is_supported_environment() {
            run(&bb_solver, &program, initial_witness)?
        } else {
            let stub = StubbedBlackBoxSolver::default();
            run(&stub, &program, initial_witness)?
        };

        // Build a WitnessStack and serialize (gzipped), then return the decompressed bytes
        let stack: WitnessStack<FE> = WitnessStack::from(witness_map);
        let gz = stack.serialize().map_err(|_| BbError::Failure("witness stack serialize"))?;
        let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
        let mut out = Vec::new();
        use std::io::Read;
        dec.read_to_end(&mut out).map_err(|_| BbError::Failure("gunzip witness stack"))?;
        Ok(Witness(out))
    }

    // Public API: compute witness from a flat list of field elements, mapped in order to
    // the circuit's private_parameters (sorted by witness index). This avoids any Prover.toml or ABI parsing.
    pub fn compute_witness_from_private_inputs(acir_bytes: &[u8], private_inputs: &[FE]) -> Result<Witness> {
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
            .map(|w| match *w { acir::native_types::Witness(idx) => idx })
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
        let gz = stack.serialize().map_err(|_| BbError::Failure("witness stack serialize"))?;
        let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
        let mut out = Vec::new();
        use std::io::Read;
        dec.read_to_end(&mut out).map_err(|_| BbError::Failure("gunzip witness stack"))?;
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
    fn pedantic_solving(&self) -> bool { true }

    fn multi_scalar_mul(
        &self,
        _points: &[FE],
        _scalars_lo: &[FE],
        _scalars_hi: &[FE],
    ) -> std::result::Result<(FE, FE, FE), acvm::BlackBoxResolutionError> {
        if _points.len() % 3 != 0 || _scalars_lo.len() != _scalars_hi.len() || _points.len() / 3 != _scalars_lo.len() {
            return Err(acvm::BlackBoxResolutionError::Failed(
                acir::BlackBoxFunc::MultiScalarMul,
                "length mismatch: points must be triplets and match scalars".into(),
            ));
        }
        let n = _scalars_lo.len();
        let mut xs = Vec::with_capacity(n * 32);
        let mut ys = Vec::with_capacity(n * 32);
        let mut inf = Vec::with_capacity(n);
        for i in 0..n {
            let x_be = _points[3 * i].to_be_bytes();
            let y_be = _points[3 * i + 1].to_be_bytes();
            let inf_fe = _points[3 * i + 2];
            xs.extend_from_slice(&x_be[x_be.len() - 32..]);
            ys.extend_from_slice(&y_be[y_be.len() - 32..]);
            // interpret non-zero as 1
            let is_inf = if inf_fe.is_zero() { 0u8 } else { 1u8 };
            inf.push(is_inf);
        }
        // scalars are split into two 128-bit limbs, big-endian each
        let mut slo = Vec::with_capacity(n * 16);
        let mut shi = Vec::with_capacity(n * 16);
        for i in 0..n {
            let lo_be = _scalars_lo[i].to_be_bytes();
            let hi_be = _scalars_hi[i].to_be_bytes();
            slo.extend_from_slice(&lo_be[lo_be.len() - 16..]);
            shi.extend_from_slice(&hi_be[hi_be.len() - 16..]);
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
        Ok((
            FE::from_be_bytes_reduce(&out_x),
            FE::from_be_bytes_reduce(&out_y),
            FE::from(out_inf as u128),
        ))
    }

    fn ec_add(
        &self,
        _input1_x: &FE,
        _input1_y: &FE,
        _input1_infinite: &FE,
        _input2_x: &FE,
        _input2_y: &FE,
        _input2_infinite: &FE,
    ) -> std::result::Result<(FE, FE, FE), acvm::BlackBoxResolutionError> {
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
        let inf = FE::zero();
        Ok((FE::from_be_bytes_reduce(&out_x), FE::from_be_bytes_reduce(&out_y), inf))
    }

    fn poseidon2_permutation(
        &self,
        _inputs: &[FE],
        _len: u32,
    ) -> std::result::Result<Vec<FE>, acvm::BlackBoxResolutionError> {
        if _len != 4 || _inputs.len() != 4 {
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
                buf.as_ptr(), 4, &mut out_ptr, &mut out_len,
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

pub fn schnorr_poseidon2_sign(msg: &[u8], sk32: &[u8; 32]) -> Result<[u8; 64]> {
    unsafe {
        let mut sig = [0u8; 64];
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_poseidon2_sign(
            msg.as_ptr(), msg.len(), sk32.as_ptr(), sig.as_mut_ptr(),
        );
        if rc != 0 { return Err(BbError::Failure("schnorr_poseidon2_sign")); }
        Ok(sig)
    }
}

pub fn schnorr_poseidon2_verify(msg: &[u8], sig64: &[u8; 64], pk32: &[u8; 32]) -> Result<bool> {
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_poseidon2_verify(
            msg.as_ptr(), msg.len(), sig64.as_ptr(), pk32.as_ptr(), &mut ok,
        );
        if rc != 0 { return Err(BbError::Failure("schnorr_poseidon2_verify")); }
        Ok(ok)
    }
}

pub fn schnorr_pedersen_sign(msg: &[u8], sk32: &[u8; 32]) -> Result<[u8; 64]> {
    unsafe {
        let mut sig = [0u8; 64];
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_pedersen_sign(
            msg.as_ptr(), msg.len(), sk32.as_ptr(), sig.as_mut_ptr(),
        );
        if rc != 0 { return Err(BbError::Failure("schnorr_pedersen_sign")); }
        Ok(sig)
    }
}

pub fn schnorr_pedersen_verify_xy(msg: &[u8], sig64: &[u8; 64], pkx32: &[u8; 32], pky32: &[u8; 32]) -> Result<bool> {
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_pedersen_verify_xy(
            msg.as_ptr(), msg.len(), sig64.as_ptr(), pkx32.as_ptr(), pky32.as_ptr(), &mut ok,
        );
        if rc != 0 { return Err(BbError::Failure("schnorr_pedersen_verify_xy")); }
        Ok(ok)
    }
}

pub fn grumpkin_derive_pubkey(sk32: &[u8; 32]) -> Result<([u8;32],[u8;32])> {
    unsafe {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let rc = aztec_barretenberg_sys_rs::bb_grumpkin_derive_pubkey(sk32.as_ptr(), x.as_mut_ptr(), y.as_mut_ptr());
        if rc != 0 { return Err(BbError::Failure("grumpkin_derive_pubkey")); }
        Ok((x,y))
    }
}


pub fn schnorr_blake2s_sign(msg: &[u8], sk32: &[u8; 32]) -> Result<[u8; 64]> {
    unsafe {
        let mut sig = [0u8; 64];
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_blake2s_sign(
            msg.as_ptr(), msg.len(), sk32.as_ptr(), sig.as_mut_ptr(),
        );
        if rc != 0 { return Err(BbError::Failure("schnorr_blake2s_sign")); }
        Ok(sig)
    }
}

pub fn schnorr_blake2s_verify_xy(
    msg: &[u8],
    sig64: &[u8; 64],
    pkx32: &[u8; 32],
    pky32: &[u8; 32],
) -> Result<bool> {
    unsafe {
        let mut ok = false;
        let rc = aztec_barretenberg_sys_rs::bb_schnorr_blake2s_verify_xy(
            msg.as_ptr(), msg.len(), sig64.as_ptr(), pkx32.as_ptr(), pky32.as_ptr(), &mut ok,
        );
        if rc != 0 { return Err(BbError::Failure("schnorr_blake2s_verify_xy")); }
        Ok(ok)
    }
}
