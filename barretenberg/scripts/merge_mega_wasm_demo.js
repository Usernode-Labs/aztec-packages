#!/usr/bin/env node
/*
  Demo: Generate two MegaHonk proofs (same circuit/witness), then merge twice via WASM export, emit metrics.
*/
import { gunzipSync } from 'zlib';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function getBytecode(bytecodePath) {
  const extension = bytecodePath.substring(bytecodePath.lastIndexOf('.') + 1);
  if (extension == 'json') {
    const encodedCircuit = JSON.parse(readFileSync(bytecodePath, 'utf8'));
    const decompressed = gunzipSync(Buffer.from(encodedCircuit.bytecode, 'base64'));
    return Uint8Array.from(decompressed);
  }
  const encodedCircuit = readFileSync(bytecodePath);
  const decompressed = gunzipSync(encodedCircuit);
  return Uint8Array.from(decompressed);
}
function getWitness(witnessPath) {
  const data = readFileSync(witnessPath);
  const decompressed = gunzipSync(data);
  return Uint8Array.from(decompressed);
}

async function importBarretenberg() {
  // Prefer built output; fallback to source
  try {
    return (await import(resolve(__dirname, '../ts/dest/node/index.js'))).Barretenberg;
  } catch {
    return (await import(resolve(__dirname, '../ts/src/barretenberg/index.js'))).Barretenberg;
  }
}

async function memMiB(api) {
  try {
    const result = await api.getWasm().callWasmExport('bb_memory_pages', [], [4]);
    const buf = result[0];
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const pages = dv.getUint32(0, false); // big endian
    return (pages / 16).toFixed(2);
  } catch {
    return 'n/a';
  }
}

async function main() {
  const bytecodePath = process.env.BB_BYTECODE || resolve(process.cwd(), 'docs/examples/fixtures/main/target/program.json');
  const witnessPath = process.env.BB_WITNESS || resolve(process.cwd(), 'docs/examples/fixtures/main/target/witness.gz');
  const crsPath = process.env.BB_CRS || resolve(process.cwd(), 'ts/crs');
  const outDir = process.env.OUT_DIR || resolve(process.cwd(), 'bench-out/merge-wasm-demo');
  mkdirSync(outDir, { recursive: true });

  const Barretenberg = await importBarretenberg();
  const api = await Barretenberg.new({
    threads: Number(process.env.BB_THREADS || 4),
    wasmPath: process.env.BB_WASM_PATH || resolve(process.cwd(), 'cpp/build-wasm-threads/bin/barretenberg.wasm'),
    memory: {
      initial: Number(process.env.BB_MEM_INITIAL || 2048),
      maximum: Number(process.env.BB_MEM_MAX || 65536),
    },
    crsPath,
  });
  try {
    const bytecode = getBytecode(bytecodePath);
    const [_total, subgroup] = await api.acirGetCircuitSizes(bytecode, false, true);
    await api.initSRSForCircuitSize(Math.max(subgroup, 1 << 16));
    const witness = getWitness(witnessPath);
    const { proof: proof1, vk: vk1 } = await api.acirProveMegaHonk(bytecode, witness);
    const { proof: proof2, vk: vk2 } = await api.acirProveMegaHonk(bytecode, witness);

    writeFileSync(`${outDir}/proof1.bin`, proof1);
    writeFileSync(`${outDir}/vk1.bin`, vk1);
    writeFileSync(`${outDir}/proof2.bin`, proof2);
    writeFileSync(`${outDir}/vk2.bin`, vk2);

    const { proof: m1p, vk: m1v, metrics: m1m } = await api.mergeMega(proof1, vk1, proof2, vk2);
    mkdirSync(`${outDir}/merge1`, { recursive: true });
    writeFileSync(`${outDir}/merge1/merged_proof`, m1p);
    writeFileSync(`${outDir}/merge1/merged_vk`, m1v);
    writeFileSync(`${outDir}/merge1/metrics.json`, m1m);
    console.log('merge1 metrics', m1m, 'memMiB=', await memMiB(api));

    const { proof: m2p, vk: m2v, metrics: m2m } = await api.mergeMega(proof1, vk1, m1p, m1v);
    mkdirSync(`${outDir}/merge2`, { recursive: true });
    writeFileSync(`${outDir}/merge2/merged_proof`, m2p);
    writeFileSync(`${outDir}/merge2/merged_vk`, m2v);
    writeFileSync(`${outDir}/merge2/metrics.json`, m2m);
    console.log('merge2 metrics', m2m, 'memMiB=', await memMiB(api));

    const t0 = Date.now();
    const ok = await api.acirVerifyMegaHonk(m2p, m2v);
    const verifyMs = Date.now() - t0;
    console.log('final verify', ok, 'verifyMs', verifyMs, 'memMiB=', await memMiB(api));
  } finally {
    await api.destroy();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

