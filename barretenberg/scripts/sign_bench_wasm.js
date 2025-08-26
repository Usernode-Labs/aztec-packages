#!/usr/bin/env node
import { gunzipSync } from 'zlib';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { resolve } from 'path';
import { Barretenberg } from '../ts/dest/node/index.js';

function getBytecode(bytecodePath) {
  const ext = bytecodePath.substring(bytecodePath.lastIndexOf('.') + 1);
  if (ext === 'json') {
    const encoded = JSON.parse(readFileSync(bytecodePath, 'utf8'));
    return Uint8Array.from(gunzipSync(Buffer.from(encoded.bytecode, 'base64')));
  }
  return Uint8Array.from(gunzipSync(readFileSync(bytecodePath)));
}
function getWitness(witnessPath) {
  return Uint8Array.from(gunzipSync(readFileSync(witnessPath)));
}

async function memMiB(api) {
  try {
    const result = await api.getWasm().callWasmExport('bb_memory_pages', [], [4]);
    const dv = new DataView(result[0].buffer, result[0].byteOffset, result[0].byteLength);
    const pages = dv.getUint32(0, false);
    return pages / 16;
  } catch { return NaN; }
}

async function benchOne(api, name, projDir, outRoot) {
  const outDir = resolve(outRoot, name);
  mkdirSync(outDir, { recursive: true });
  const bytecode = getBytecode(resolve(projDir, 'target/program.json'));
  const witness = getWitness(resolve(projDir, 'target/witness.gz'));
  const [_total, subgroup] = await api.acirGetCircuitSizes(bytecode, false, true);
  await api.initSRSForCircuitSize(Math.max(subgroup, 1 << 16));
  const memBefore = await memMiB(api);
  const t0 = Date.now();
  const { proof, vk } = await api.acirProveMegaHonk(bytecode, witness);
  const proveMs = Date.now() - t0;
  const memAfter = await memMiB(api);
  writeFileSync(resolve(outDir, 'bench.bench.json'), JSON.stringify([
    { name: `${name}/seconds`, unit: 'ms', value: proveMs },
    { name: `${name}/memory`, unit: 'MiB', value: memAfter },
    { name: `${name}/subgroup`, unit: 'gates', value: subgroup },
    { name: `${name}/proof_bytes`, unit: 'bytes', value: proof.length },
    { name: `${name}/vk_bytes`, unit: 'bytes', value: vk.length },
  ], null, 2));
  console.log(`${name} wasm: ms=${proveMs} mem_mib=${memAfter} proof_bytes=${proof.length}`);
}

async function main() {
  const wasmPath = process.env.BB_WASM_PATH || resolve(process.cwd(), 'cpp/build-wasm-threads/bin/barretenberg.wasm');
  const crsPath = process.env.BB_CRS || resolve(process.cwd(), 'ts/crs');
  const outRoot = process.env.OUT_DIR || resolve(process.cwd(), 'bench-out/sign-wasm');
  mkdirSync(outRoot, { recursive: true });

  const api = await Barretenberg.new({ threads: Number(process.env.BB_THREADS || 4), wasmPath, crsPath, memory: { initial: Number(process.env.BB_MEM_INITIAL || 4096), maximum: Number(process.env.BB_MEM_MAX || 65536) } });
  try {
    await benchOne(api, 'hash_ecdsa', resolve(process.cwd(), 'barretenberg/noir/hash_ecdsa'), outRoot);
    await benchOne(api, 'hash_sign_blake', resolve(process.cwd(), 'barretenberg/noir/hash_sign_blake'), outRoot);
    await benchOne(api, 'hash_sign_poseidon2_experimental', resolve(process.cwd(), 'barretenberg/noir/hash_sign_poseidon2_experimental'), outRoot);
  } finally {
    await api.destroy();
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
