/**
 * TypeScript SDK benchmarks.
 * Run: npx ts-node src/bench.ts
 * Outputs JSON to stdout for report generation.
 */

import {
  MldsaKeyPair,
  verify,
  signingMessage,
  ckbBlake2b,
  PUBLICKEY_BYTES,
  SIGNATURE_BYTES,
  ARGS_LEN,
} from './index';

interface BenchResult {
  name: string;
  iterations: number;
  totalMs: number;
  meanUs: number;
  throughputPerSec: number;
}

function bench(name: string, iterations: number, fn: () => unknown): BenchResult {
  // Warmup
  for (let i = 0; i < Math.min(3, iterations); i++) fn();

  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  const totalMs = performance.now() - start;
  const meanUs = (totalMs / iterations) * 1000;

  return { name, iterations, totalMs, meanUs, throughputPerSec: 1e6 / meanUs };
}

const results: BenchResult[] = [];

// Keygen (slow — fewer iterations)
results.push(bench('keygen', 20, () => MldsaKeyPair.generate()));

// Sign
const kp = MldsaKeyPair.generate();
const txHash = new Uint8Array(32).fill(0x42);
results.push(bench('sign_witness', 20, () => kp.signWitness(txHash)));

// Verify — extract sig first
const wa = kp.signWitness(txHash);
const wit = wa.slice(20);
const view = new DataView(wit.buffer, wit.byteOffset);
const f4Off = view.getUint32(20, true);
const f5Off = view.getUint32(24, true);
const pubkey = wit.slice(f4Off + 4, f4Off + 4 + PUBLICKEY_BYTES);
const sig = wit.slice(f5Off + 4, f5Off + 4 + SIGNATURE_BYTES);
results.push(bench('verify', 50, () => verify(pubkey, sig, txHash)));

// Fast operations
results.push(bench('signing_message (blake2b)', 2000, () => signingMessage(txHash)));
results.push(bench('pubkey_hash (blake2b 1952B)', 2000, () => ckbBlake2b(pubkey)));
results.push(bench('lock_args derivation', 2000, () => kp.lockArgs()));

// Output
console.log(JSON.stringify({
  platform: 'nodejs',
  nodeVersion: process.version,
  timestamp: new Date().toISOString(),
  results,
}));
