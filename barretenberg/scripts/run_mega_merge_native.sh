#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
PATH="$HOME/.nargo/bin:$PATH"

DEMO_DIR="$ROOT_DIR/barretenberg/noir/mega_merge_demo"
OUT_DIR="$ROOT_DIR/bench-out/merge-native"
BB_BIN="$ROOT_DIR/barretenberg/cpp/build/bin/bb"

mkdir -p "$OUT_DIR"
pushd "$DEMO_DIR" >/dev/null
  rm -rf target
  nargo compile --silence-warnings
  nargo execute
  # Normalize artifact names
  cp ./target/mega_merge_demo.json ./target/program.json
  cp ./target/mega_merge_demo.gz ./target/witness.gz
popd >/dev/null

mkdir -p "$OUT_DIR/tmp"

"$BB_BIN" write_vk --scheme mega_honk -b "$DEMO_DIR/target/program.json" -o "$OUT_DIR/tmp"
"$BB_BIN" prove --scheme mega_honk --output_format bytes --write_vk \
  -b "$DEMO_DIR/target/program.json" -k "$OUT_DIR/tmp/vk" -o "$OUT_DIR/tmp" -w "$DEMO_DIR/target/witness.gz"

# Merge proof with itself (smoke)
"$BB_BIN" merge_mega \
  --proofA_fields_path "$OUT_DIR/tmp/proof" \
  --vkA_path "$OUT_DIR/tmp/vk" \
  --proofB_fields_path "$OUT_DIR/tmp/proof" \
  --vkB_path "$OUT_DIR/tmp/vk" \
  -o "$OUT_DIR"

echo "Native merge metrics:"
cat "$OUT_DIR/metrics.json" || true
