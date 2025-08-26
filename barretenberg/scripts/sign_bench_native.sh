#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
PATH="$HOME/.nargo/bin:$PATH"
BB="$ROOT_DIR/barretenberg/cpp/build/bin/bb"
OUT_ROOT="$ROOT_DIR/bench-out/sign-native"
mkdir -p "$OUT_ROOT"

function bench_project() {
  local proj_dir="$1"
  local name=$(basename "$proj_dir")
  local out_dir="$OUT_ROOT/$name"
  rm -rf "$out_dir" && mkdir -p "$out_dir"
  pushd "$proj_dir" >/dev/null
    rm -rf target
    nargo compile --silence-warnings
    nargo execute
    cp ./target/*.json ./target/program.json 2>/dev/null || true
    cp ./target/*.gz ./target/witness.gz 2>/dev/null || true
  popd >/dev/null

  # Prove (MegaHonk) direct timing
  start=$(date +%s%3N)
  "$BB" prove --scheme mega_honk -b "$proj_dir/target/program.json" -w "$proj_dir/target/witness.gz" -o "$out_dir" --output_format bytes >/dev/null
  prove_ms=$(( $(date +%s%3N) - start ))
  proof_bytes=$(stat -c%s "$out_dir/proof" 2>/dev/null || echo 0)

  cat > "$out_dir/bench.bench.json" <<JSON
[
  {"name":"$name/seconds","unit":"ms","value":$prove_ms},
  {"name":"$name/proof_bytes","unit":"bytes","value":$proof_bytes}
]
JSON
  echo "$name native: ms=$prove_ms proof_bytes=$proof_bytes"
}

for proj in \
  "$ROOT_DIR/barretenberg/noir/hash_ecdsa" \
  "$ROOT_DIR/barretenberg/noir/hash_sign_blake" \
  "$ROOT_DIR/barretenberg/noir/hash_sign_poseidon2_experimental"; do
  bench_project "$proj" || true
done
