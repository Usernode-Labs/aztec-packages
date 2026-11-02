# Usernode Barretenberg wrapper

The default build embeds the proving CRS. Mobile builds can enable `external-crs`
to exclude the 128 MiB BN254 and 16 MiB Grumpkin point arrays entirely, including
build-time downloads. The 192 bytes needed by the MegaHonk/UltraZK verifier remain
embedded. Proof verification, public-input extraction, circuit metadata, embedded
merge VK access, and VK hashing do not invoke the external loader.

Install the process-wide loader with `configure_external_prover_crs`. The caller
owns persistent storage, authenticated downloads, and progress reporting. The
loader returns canonical affine point arrays, with exactly 2,097,153 BN254 points
and 262,144 Grumpkin points (64 bytes per point). Run `prepare_prover_crs` on a
worker before submitting proof/VK-generation requests. A failed load is retryable;
only successful initialization is retained. Applications should prepare parameters
before starting node paths that derive transaction verification keys.

The wrapper coordinates a verifier-to-prover CRS upgrade with active FFI calls.
An in-progress download does not exclude verifier calls. Raw sys-FFI callers must
provide their own coordination if they also initialize or access the global CRS.

This change requires the matching `v5.0.0-usernode.2` crypto and prover prebuilts.
Build/publish that version using `.github/workflows/bb-prebuilt.yml` before
consuming the revision through the normal prebuilt download path. Existing `.1`
prebuilts do not implement the required factory upgrade. For a manual release,
select the updated workflow ref and set `publish=true`. The optional `source_ref`
input selects the source tag, branch, or commit to build; by default it uses the
workflow commit. A resolver pins that source once, and every build and consumer
check uses its exact commit. Newly created release tags target that source commit.
Publication rejects an existing tag pointing elsewhere before replacing assets.
This allows rebuilding an existing tag with newer runners without moving it.
Apple jobs use macOS 15, which has precompiled Homebrew LLVM 19 packages.

## Tests

Run wrapper tests in both modes with matching native libraries:

```sh
cargo test --release -p aztec-barretenberg-rs --tests
BB_TEST_CRS_DIR=/path/to/downloaded/crs \
  cargo test --release -p aztec-barretenberg-rs --features external-crs --tests
```

The external-mode tests check a valid proof with verifier-only data, tampering,
retry after loader errors, VK generation, proving, aggregation, and unchanged
embedded batch verification keys. Regenerate the small addition test vector with:

```sh
BB_TEST_CRS_DIR=/path/to/downloaded/crs \
BB_TEST_WRITE_FIXTURE=crates/aztec-barretenberg-rs/tests/fixtures \
  cargo test --release -p aztec-barretenberg-rs --features external-crs \
  --test proof_smoke proves_and_verifies_beta_22_acir -- --exact
```
