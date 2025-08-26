#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
PATH="$HOME/.nargo/bin:$PATH"

DEMO_DIR="$ROOT_DIR/barretenberg/noir/mega_merge_demo"
OUT_DIR="$ROOT_DIR/bench-out/merge-wasm"

mkdir -p "$OUT_DIR"
pushd "$DEMO_DIR" >/dev/null
  rm -rf target
  nargo compile --silence-warnings
  nargo execute
  cp ./target/mega_merge_demo.json ./target/program.json
  cp ./target/mega_merge_demo.gz ./target/witness.gz
popd >/dev/null

pushd "$ROOT_DIR/barretenberg/ts" >/dev/null
  # Yarn 4 requires --silent after the command name
  yarn install --silent
  yarn build --silent
popd >/dev/null

BB_WASM_PATH="$ROOT_DIR/barretenberg/cpp/build-wasm-threads/bin/barretenberg.wasm" \
BB_CRS="$ROOT_DIR/barretenberg/ts/crs" \
BB_BYTECODE="$DEMO_DIR/target/program.json" \
BB_WITNESS="$DEMO_DIR/target/witness.gz" \
OUT_DIR="$OUT_DIR" \
  node "$ROOT_DIR/barretenberg/scripts/merge_mega_wasm_demo.js"

echo "Wasm merge metrics (first and second merge):"
cat "$OUT_DIR/merge1/metrics.json" || true
cat "$OUT_DIR/merge2/metrics.json" || true
