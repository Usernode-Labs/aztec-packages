//! Keep proof checking independent of the large, optionally external proving CRS.
#[cfg(feature = "external-crs")]
use std::sync::OnceLock;
use std::sync::{Mutex, RwLock, RwLockReadGuard};

use crate::BbError;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrsState {
    Empty,
    Verifier,
    Prover,
}
static STATE: RwLock<CrsState> = RwLock::new(CrsState::Empty);
static PROVER_INIT: Mutex<()> = Mutex::new(());

/// Canonical 64-byte affine point arrays for the configured Barretenberg limits.
/// The loader must authenticate the arrays before returning them.
pub struct ProverCrs {
    pub bn254_g1: Vec<u8>,
    pub grumpkin_g1: Vec<u8>,
}

#[cfg(feature = "external-crs")]
type Loader = Box<dyn Fn() -> Result<ProverCrs, String> + Send + Sync>;
#[cfg(feature = "external-crs")]
static LOADER: OnceLock<Loader> = OnceLock::new();

/// Install the process-wide loader. Called only for proving/VK generation, never
/// for proof checking, metadata, public-input extraction, or VK hashing.
/// Failed loads are retryable. The loader runs synchronously on the calling worker.
#[cfg(feature = "external-crs")]
pub fn configure_external_prover_crs(
    loader: impl Fn() -> Result<ProverCrs, String> + Send + Sync + 'static,
) -> Result<(), String> {
    LOADER
        .set(Box::new(loader))
        .map_err(|_| "external CRS loader already configured".to_owned())
}

pub fn prover_crs_initialized() -> bool {
    STATE.read().is_ok_and(|state| *state == CrsState::Prover)
}

/// Load proving data ahead of a proof request, outside RPC/state-machine handlers.
pub fn prepare_prover_crs() -> Result<(), BbError> {
    drop(prover()?);
    Ok(())
}

pub(crate) fn verifier() -> Result<RwLockReadGuard<'static, CrsState>, BbError> {
    let state = STATE
        .read()
        .map_err(|_| BbError::Failure("CRS lock poisoned"))?;
    if *state != CrsState::Empty {
        return Ok(state);
    }
    drop(state);
    let mut state = STATE
        .write()
        .map_err(|_| BbError::Failure("CRS lock poisoned"))?;
    if *state == CrsState::Empty {
        init_bn254(
            aztec_barretenberg_sys_rs::crs_verifier::BN254_G1,
            aztec_barretenberg_sys_rs::crs_verifier::BN254_G2,
        )?;
        *state = CrsState::Verifier;
    }
    drop(state);
    STATE
        .read()
        .map_err(|_| BbError::Failure("CRS lock poisoned"))
}

pub(crate) fn prover() -> Result<RwLockReadGuard<'static, CrsState>, BbError> {
    let state = verifier()?;
    if *state == CrsState::Prover {
        return Ok(state);
    }
    drop(state);
    let _initialization = PROVER_INIT
        .lock()
        .map_err(|_| BbError::Failure("CRS initialization lock poisoned"))?;
    let state = STATE
        .read()
        .map_err(|_| BbError::Failure("CRS lock poisoned"))?;
    if *state == CrsState::Prover {
        return Ok(state);
    }
    drop(state);

    // Download/read outside STATE's exclusive lock: existing verifiers continue
    // working while the first proving request prepares its parameters.
    #[cfg(feature = "external-crs")]
    let external = LOADER
        .get()
        .ok_or_else(|| BbError::Crs("external CRS loader is not configured".into()))?(
    )
    .map_err(BbError::Crs)?;
    #[cfg(feature = "external-crs")]
    let (bn254, grumpkin) = (
        external.bn254_g1.as_slice(),
        external.grumpkin_g1.as_slice(),
    );
    #[cfg(not(feature = "external-crs"))]
    let (bn254, grumpkin) = (
        aztec_barretenberg_sys_rs::crs_embedded::BN254_G1,
        aztec_barretenberg_sys_rs::crs_embedded::GRUMPKIN_G1,
    );

    validate_prover_lengths(bn254.len(), grumpkin.len())?;
    // Readers hold their guard across the complete FFI operation. Replacing the
    // global C++ factories can therefore never race an active verifier/prover.
    let mut state = STATE
        .write()
        .map_err(|_| BbError::Failure("CRS lock poisoned"))?;
    init_bn254(bn254, aztec_barretenberg_sys_rs::crs_verifier::BN254_G2)?;
    let count = (grumpkin.len() / 64) as u32;
    unsafe {
        aztec_barretenberg_sys_rs::srs_init_grumpkin_srs(grumpkin.as_ptr(), &count.to_be());
    }
    *state = CrsState::Prover;
    drop(state);
    STATE
        .read()
        .map_err(|_| BbError::Failure("CRS lock poisoned"))
}

fn validate_prover_lengths(bn254: usize, grumpkin: usize) -> Result<(), BbError> {
    if bn254 != 134_217_792 || grumpkin != 16_777_216 {
        return Err(BbError::Crs(
            "proving CRS length does not match the pinned point counts".into(),
        ));
    }
    Ok(())
}

fn init_bn254(g1: &[u8], g2: &[u8]) -> Result<(), BbError> {
    if g1.is_empty() || !g1.len().is_multiple_of(64) || g2.len() != 128 {
        return Err(BbError::Crs("invalid BN254 CRS lengths".into()));
    }
    let count =
        u32::try_from(g1.len() / 64).map_err(|_| BbError::Failure("too many BN254 points"))?;
    unsafe {
        aztec_barretenberg_sys_rs::srs_init_srs(g1.as_ptr(), &count.to_be(), g2.as_ptr());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_truncated_or_oversized_proving_data() {
        assert!(validate_prover_lengths(134_217_792, 16_777_216).is_ok());
        assert!(validate_prover_lengths(64, 16_777_216).is_err());
        assert!(validate_prover_lengths(134_217_856, 16_777_216).is_err());
        assert!(validate_prover_lengths(134_217_792, 64).is_err());
    }
}
