#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(git rev-parse --show-toplevel)
export PATH="$HOME/.nargo/bin:$HOME/.local/bin:$PATH"

echo "[all] Ensuring native bb is built..."
if [ ! -x "$ROOT_DIR/barretenberg/cpp/build/bin/bb" ]; then
  (cd "$ROOT_DIR/barretenberg/cpp" && cmake --preset default && cmake --build --preset default -j$(nproc))
fi

echo "[all] Ensuring threads wasm is built..."
if [ ! -f "$ROOT_DIR/barretenberg/cpp/build-wasm-threads/bin/barretenberg.wasm" ]; then
  (cd "$ROOT_DIR/barretenberg/cpp" && cmake --preset wasm-threads && cmake --build --preset wasm-threads -j$(nproc))
fi

echo "[all] Ensuring bb.js dest is built (threads wasm only)..."
if [ ! -f "$ROOT_DIR/barretenberg/ts/dest/node/index.js" ]; then
  # try corepack yarn if available; otherwise rely on existing dest or skip
  corepack enable --install-directory "$HOME/.local/bin" || true
  corepack prepare yarn@4.5.2 --activate || true
  # Yarn 4 expects global flags after the command; use --silent post-command
  (cd "$ROOT_DIR/barretenberg/ts" && SKIP_CPP_BUILD=1 yarn install --silent || true && SKIP_CPP_BUILD=1 yarn build --silent || true)
fi

echo "[all] Compiling Noir projects..."
for proj in \
  "$ROOT_DIR/barretenberg/noir/hash_ecdsa" \
  "$ROOT_DIR/barretenberg/noir/hash_sign_blake" \
  "$ROOT_DIR/barretenberg/noir/hash_sign_poseidon2_experimental"; do
  (cd "$proj" && rm -rf target && nargo compile --silence-warnings && nargo execute && \
    cp ./target/*.json ./target/program.json 2>/dev/null || true && \
    cp ./target/*.gz ./target/witness.gz 2>/dev/null || true)
done

BB="$ROOT_DIR/barretenberg/cpp/build/bin/bb"
WASM_PATH="$ROOT_DIR/barretenberg/cpp/build-wasm-threads/bin/barretenberg.wasm"
CRS_PATH="$ROOT_DIR/barretenberg/ts/crs"
OUT_ROOT="$ROOT_DIR/bench-out"
mkdir -p "$OUT_ROOT"

echo "[all] Running native Mega merge bench..."
"$ROOT_DIR/barretenberg/scripts/run_mega_merge_native.sh" || true

echo "[all] Running wasm Mega merge bench..."
BB_WASM_PATH="$WASM_PATH" \
BB_CRS="$CRS_PATH" \
BB_BYTECODE="$ROOT_DIR/barretenberg/noir/mega_merge_demo/target/program.json" \
BB_WITNESS="$ROOT_DIR/barretenberg/noir/mega_merge_demo/target/witness.gz" \
BB_MEM_INITIAL=8192 \
OUT_DIR="$OUT_ROOT/merge-wasm" \
  node "$ROOT_DIR/barretenberg/scripts/merge_mega_wasm_demo.js" || true

echo "[all] Running native Mega signing benches..."
SIG_NATIVE_DIR="$OUT_ROOT/sign-native"
rm -rf "$SIG_NATIVE_DIR" && mkdir -p "$SIG_NATIVE_DIR"

function bench_sign_native() {
  local name="$1"; local proj="$2"; local out="$SIG_NATIVE_DIR/$name"; mkdir -p "$out"
  local start=$(date +%s%3N)
  "$BB" prove --scheme mega_honk -b "$proj/target/program.json" -w "$proj/target/witness.gz" -o "$out" --output_format bytes >/dev/null
  local ms=$(( $(date +%s%3N) - start ))
  local proof_bytes=$(stat -c%s "$out/proof" 2>/dev/null || echo 0)
  echo "[sign-native] $name ms=$ms proof_bytes=$proof_bytes"
  cat > "$out/bench.bench.json" <<JSON
[
  {"name":"$name/seconds","unit":"ms","value":$ms},
  {"name":"$name/proof_bytes","unit":"bytes","value":$proof_bytes}
]
JSON
}

bench_sign_native hash_ecdsa "$ROOT_DIR/barretenberg/noir/hash_ecdsa"
bench_sign_native hash_sign_blake "$ROOT_DIR/barretenberg/noir/hash_sign_blake"
bench_sign_native hash_sign_poseidon2_experimental "$ROOT_DIR/barretenberg/noir/hash_sign_poseidon2_experimental"

echo "[all] Running wasm Mega signing benches..."
SIG_WASM_DIR="$OUT_ROOT/sign-wasm"
rm -rf "$SIG_WASM_DIR" && mkdir -p "$SIG_WASM_DIR"
BB_WASM_PATH="$WASM_PATH" BB_CRS="$CRS_PATH" BB_MEM_INITIAL=8192 OUT_DIR="$SIG_WASM_DIR" node "$ROOT_DIR/barretenberg/scripts/sign_bench_wasm.js" || true

echo "[all] Consolidating results..."
node - <<'NODE'
const fs = require('fs');
const path = require('path');
const root = process.cwd();
const outRoot = path.join(root, 'bench-out');
function readJSON(p){ try { return JSON.parse(fs.readFileSync(p,'utf8')); } catch { return null; } }
function readText(p){ try { return fs.readFileSync(p,'utf8'); } catch { return null; } }
const report = { merge:{}, signing:{ native:{}, wasm:{} } };
// merge native
const mn = readJSON(path.join(outRoot,'merge-native','metrics.json')); if(mn) report.merge.native = mn;
// merge wasm
const m1 = readJSON(path.join(outRoot,'merge-wasm','merge1','metrics.json'));
const m2 = readJSON(path.join(outRoot,'merge-wasm','merge2','metrics.json'));
if(m1||m2) report.merge.wasm = { merge1: m1, merge2: m2 };
// signing native
['hash_ecdsa','hash_sign_blake','hash_sign_poseidon2_experimental'].forEach(n=>{
  const p = path.join(outRoot,'sign-native',n,'bench.bench.json');
  const j = readJSON(p); if(j) report.signing.native[n] = j;
});
// signing wasm
['hash_ecdsa','hash_sign_blake','hash_sign_poseidon2_experimental'].forEach(n=>{
  const p = path.join(outRoot,'sign-wasm',n,'bench.bench.json');
  const j = readJSON(p); if(j) report.signing.wasm[n] = j;
});
fs.writeFileSync(path.join(outRoot,'report.json'), JSON.stringify(report,null,2));
console.log(JSON.stringify(report,null,2));
NODE

echo "[all] Done. Consolidated report at bench-out/report.json"
