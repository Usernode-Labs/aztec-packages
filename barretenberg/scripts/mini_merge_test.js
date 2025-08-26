#!/usr/bin/env node
import { gunzipSync } from 'zlib';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

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
  // Prefer built output; fallback to source if needed
  const built = resolve(__dirname, '../ts/dest/node/index.js');
  try {
    return (await import(built)).Barretenberg;
  } catch {
    const src = resolve(__dirname, '../ts/src/barretenberg/index.js');
    return (await import(src)).Barretenberg;
  }
}

async function main() {
  const bytecodePath = process.env.BB_BYTECODE || resolve(process.cwd(), 'docs/examples/fixtures/main/target/program.json');
  const witnessPath = process.env.BB_WITNESS || resolve(process.cwd(), 'docs/examples/fixtures/main/target/witness.gz');
  const wasmPath = process.env.BB_WASM_PATH || resolve(process.cwd(), 'cpp/build-wasm-threads/bin/barretenberg.wasm');
  const crsPath = process.env.BB_CRS || resolve(process.cwd(), 'ts/crs');
  const logger = (m) => console.log('[bb]', m);

  console.log('merge-mini: starting');
  const Barretenberg = await importBarretenberg();
  const api = await Barretenberg.new({ threads: 1, wasmPath, logger, memory: { initial: 32768, maximum: 65536 }, crsPath });
  console.log('merge-mini: api created');
  const bytecode = getBytecode(bytecodePath);
  const [total, subgroup] = await api.acirGetCircuitSizes(bytecode, false, true);
  console.log('merge-mini: sizes', total, subgroup);
  await api.initSRSForCircuitSize(Math.max(subgroup, 1 << 16));
  console.log('merge-mini: SRS initialized');
  const witness = getWitness(witnessPath);
  console.log('merge-mini: proving A');
  const { proof: proof1, vk: vk1 } = await api.acirProveMegaHonk(bytecode, witness);
  console.log('merge-mini: proving B');
  const { proof: proof2, vk: vk2 } = await api.acirProveMegaHonk(bytecode, witness);
  console.log('merge-mini: merging');
  const { proof: mp, vk: mvk, metrics } = await api.mergeMega(proof1, vk1, proof2, vk2);
  console.log('merge-mini: merged ok, metrics', metrics);
  const ok = await api.acirVerifyMegaHonk(mp, mvk);
  console.log('merge-mini: verify ok?', ok);
  await api.destroy();
  console.log('merge-mini: done');
}

main().catch((err) => {
  console.error('merge-mini: error', err);
  process.exit(1);
});

