# Barretenberg Benchmarks (Native + WASM)

This repo includes a consolidated benchmarking script that builds required components, runs native + WASM MegaHonk merge benches, and benchmarks signing circuits. Output metrics are written under `bench-out/`.

## Prerequisites

- CMake and a C++ toolchain (clang recommended)
- Node.js (>=18)
- Noir toolchain (nargo) in `~/.nargo/bin` (the script assumes this path)

Optional:
- Corepack/Yarn 4 (the script attempts to build `@aztec/bb.js` with threads-only wasm; if `ts/dest` is already built, no yarn is needed)

## One-Command Run

```
./barretenberg/scripts/run_all_benches.sh
```

What the script does:
- Builds native `bb` if missing (`barretenberg/cpp/build/bin/bb`).
- Builds threads-only wasm if missing (`barretenberg/cpp/build-wasm-threads/bin/barretenberg.wasm`).
- Optionally builds `@aztec/bb.js` dest output (threads-only wasm copy) if missing.
- Compiles Noir projects used in the benches:
  - `barretenberg/noir/hash_ecdsa`
  - `barretenberg/noir/hash_sign_blake`
  - `barretenberg/noir/hash_sign_poseidon2_experimental`
- Runs MegaHonk merge benches:
  - Native: `scripts/run_mega_merge_native.sh` → `bench-out/merge-native/metrics.json`
  - WASM: `scripts/merge_mega_wasm_demo.js` → `bench-out/merge-wasm/merge{1,2}/metrics.json`
- Runs signing benches (MegaHonk for native, MegaHonk on WASM via bb.js):
  - Native: `bench-out/sign-native/<project>/bench.bench.json`
  - WASM: `bench-out/sign-wasm/<project>/bench.bench.json`
- Consolidates into `bench-out/report.json` and prints it.

## Outputs

- `bench-out/merge-native/metrics.json`: `{ "gates", "prove_ms", "rss_mb" }`
- `bench-out/merge-wasm/merge1/metrics.json` and `merge2/metrics.json`: same keys
- `bench-out/sign-native/<project>/bench.bench.json`: array with seconds and proof_bytes entries
- `bench-out/sign-wasm/<project>/bench.bench.json`: array with seconds, memory MiB (bb_memory_pages), subgroup, proof_bytes, vk_bytes
- `bench-out/report.json`: consolidated report across all runs

## Notes

- For signing circuits, MegaHonk and UltraHonk have different trade-offs. This script uses MegaHonk for native + WASM signing metrics to align with recursive proving flows. If you need the exact figures from older UltraHonk-based reports, switch the scheme to `ultra_honk` in `sign_bench_native.sh` and `sign_bench_wasm.js`.
- Peak memory in fast native runs can be under-reported by polling scripts. For precise RSS on short jobs, consider using `/usr/bin/time -v` or a small C++ wrapper using `getrusage`.

