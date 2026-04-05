/**
 * CKB ML-DSA-65 lock script SDK.
 *
 * Provides key generation, signing, and witness serialization for interacting
 * with the mldsa-lock contract on CKB.
 *
 * @example
 * ```ts
 * import { MldsaKeyPair } from '@ckb-mldsa/sdk';
 *
 * const kp = MldsaKeyPair.generate();
 * console.log('lock args:', toHex(kp.lockArgs()));
 *
 * const txHash = new Uint8Array(32); // from CKB RPC
 * const witness = kp.signWitness(txHash);
 * ```
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { blake2b } from '@noble/hashes/blake2b';

// ── Constants ──────────────────────────────────────────────────────────────

export const PUBLICKEY_BYTES = 1952;
export const SIGNATURE_BYTES = 3309;
export const SECRETKEY_BYTES = 4032;
export const ARGS_LEN = 36;

export const ARGS_VERSION  = 0x01;
export const ARGS_ALGO_ID  = 0x02;
export const ARGS_PARAM_ID = 0x02;

/** Domain separation context string passed to ML-DSA sign/verify. */
export const DOMAIN = new TextEncoder().encode('CKB-MLDSA-LOCK');

/** CKB blake2b personalization (matches ckb-c-stdlib). */
const CKB_PERSONAL = new TextEncoder().encode('ckb-default-hash');

// ── Testnet deployment ─────────────────────────────────────────────────────

/** Testnet deployment constants for the mldsa-lock contract. */
export const TESTNET = {
  /** type_id code hash — use with hash_type "type". Stable across upgrades. */
  CODE_HASH_TYPE_ID: '0x8984f4230ded4ac1f5efee2b67fef45fcda08bd6344c133a2f378e2f469d310d',
  /** data_hash — use with hash_type "data1". Changes on redeploy. */
  CODE_HASH_DATA: '0x7dcb281583da642016be3a0a4a4d7d4c4d573df2ae10cd4fb4d1616d74007725',
  /** Deploy transaction hash. */
  TX_HASH: '0xba4a6560ef719b24d170bf678611b25b799c56e6a80f18ce9c79e9561085cba7',
  INDEX: 0,
} as const;

// ── Blake2b ────────────────────────────────────────────────────────────────

/**
 * CKB blake2b-256 with "ckb-default-hash" personalization.
 * Matches the blake2b used throughout ckb-c-stdlib.
 */
export function ckbBlake2b(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32, personalization: CKB_PERSONAL });
}

/**
 * Compute the CKB-MLDSA signing digest:
 *   blake2b_256("CKB-MLDSA-LOCK" || txHash)
 *
 * This is what the lock script verifies against.
 */
export function signingMessage(txHash: Uint8Array): Uint8Array {
  const h = blake2b.create({ dkLen: 32, personalization: CKB_PERSONAL });
  h.update(DOMAIN);
  h.update(txHash);
  return h.digest();
}

// ── Molecule serialization ─────────────────────────────────────────────────

function writeU32LE(view: DataView, offset: number, value: number): void {
  view.setUint32(offset, value, true /* little-endian */);
}

/**
 * Serialize an MldsaWitness Molecule table (6 fields).
 * Layout: full_size(4) | offsets[6](24) | version(1) | algo_id(1) |
 *         param_id(1) | flags(1) | pubkey(4+1952) | sig(4+3309)
 */
function serializeMldsaWitness(pubkey: Uint8Array, sig: Uint8Array): Uint8Array {
  const HDR = 4 + 6 * 4; // 28
  const TOTAL = HDR + 1 + 1 + 1 + 1 + 4 + PUBLICKEY_BYTES + 4 + SIGNATURE_BYTES;

  const buf = new Uint8Array(TOTAL);
  const view = new DataView(buf.buffer);

  writeU32LE(view, 0, TOTAL);

  let off = HDR;
  writeU32LE(view, 4,  off); off += 1; // version
  writeU32LE(view, 8,  off); off += 1; // algo_id
  writeU32LE(view, 12, off); off += 1; // param_id
  writeU32LE(view, 16, off); off += 1; // flags
  writeU32LE(view, 20, off); off += 4 + PUBLICKEY_BYTES; // pubkey
  writeU32LE(view, 24, off);            // sig

  let cursor = HDR;
  buf[cursor++] = ARGS_VERSION;
  buf[cursor++] = ARGS_ALGO_ID;
  buf[cursor++] = ARGS_PARAM_ID;
  buf[cursor++] = 0x00; // flags

  writeU32LE(view, cursor, PUBLICKEY_BYTES); cursor += 4;
  buf.set(pubkey, cursor); cursor += PUBLICKEY_BYTES;

  writeU32LE(view, cursor, SIGNATURE_BYTES); cursor += 4;
  buf.set(sig, cursor);

  return buf;
}

/**
 * Wrap lock data in a WitnessArgs Molecule table (lock field only).
 * Layout: total(4) | off[0..2](12) | Bytes_len(4) | lock_data
 */
function serializeWitnessArgs(lockData: Uint8Array): Uint8Array {
  const HDR = 4 + 3 * 4; // 16
  const TOTAL = HDR + 4 + lockData.length;

  const buf = new Uint8Array(TOTAL);
  const view = new DataView(buf.buffer);

  writeU32LE(view, 0, TOTAL);
  writeU32LE(view, 4, HDR);                    // lock offset
  writeU32LE(view, 8, HDR + 4 + lockData.length); // input_type (absent)
  writeU32LE(view, 12, HDR + 4 + lockData.length); // output_type (absent)

  writeU32LE(view, HDR, lockData.length);
  buf.set(lockData, HDR + 4);

  return buf;
}

/**
 * Build the full WitnessArgs bytes from a public key and signature.
 * This is the value to use for witnesses[0] in the transaction.
 */
export function buildWitness(pubkey: Uint8Array, sig: Uint8Array): Uint8Array {
  return serializeWitnessArgs(serializeMldsaWitness(pubkey, sig));
}

// ── MldsaKeyPair ──────────────────────────────────────────────────────────

/** An ML-DSA-65 key pair. */
export class MldsaKeyPair {
  readonly #secretKey: Uint8Array;
  readonly #publicKey: Uint8Array;

  private constructor(secretKey: Uint8Array, publicKey: Uint8Array) {
    this.#secretKey = secretKey;
    this.#publicKey = publicKey;
  }

  /** Generate a fresh key pair using the platform RNG. */
  static generate(): MldsaKeyPair {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const keys = ml_dsa65.keygen(seed);
    return new MldsaKeyPair(keys.secretKey, keys.publicKey);
  }

  /** Restore from a 32-byte seed (deterministic). */
  static fromSeed(seed: Uint8Array): MldsaKeyPair {
    if (seed.length !== 32) {
      throw new Error(`expected 32 seed bytes, got ${seed.length}`);
    }
    const keys = ml_dsa65.keygen(seed);
    return new MldsaKeyPair(keys.secretKey, keys.publicKey);
  }

  /** Raw public key bytes (1952 bytes). */
  publicKeyBytes(): Uint8Array {
    return this.#publicKey;
  }

  /** Secret key bytes (4032 bytes). Store securely. */
  secretKeyBytes(): Uint8Array {
    return this.#secretKey;
  }

  /** blake2b_256(pubkey) — the pubkey hash stored in lock args. */
  pubkeyHash(): Uint8Array {
    return ckbBlake2b(this.#publicKey);
  }

  /**
   * 36-byte lock args: version | algo_id | param_id | reserved | blake2b(pubkey).
   * Use as the args field in the lock script when creating a new cell.
   */
  lockArgs(): Uint8Array {
    const args = new Uint8Array(ARGS_LEN);
    args[0] = ARGS_VERSION;
    args[1] = ARGS_ALGO_ID;
    args[2] = ARGS_PARAM_ID;
    args[3] = 0x00;
    args.set(this.pubkeyHash(), 4);
    return args;
  }

  /**
   * Sign a transaction and return WitnessArgs Molecule bytes.
   * Pass as witnesses[0] when submitting the transaction.
   *
   * @param txHash - 32-byte RawTransaction hash from the CKB RPC
   */
  signWitness(txHash: Uint8Array): Uint8Array {
    const msg = signingMessage(txHash);
    const sig = ml_dsa65.sign(this.#secretKey, msg, DOMAIN);
    return buildWitness(this.#publicKey, sig);
  }
}

/**
 * Verify an ML-DSA-65 signature against a transaction hash.
 */
export function verify(
  publicKey: Uint8Array,
  sig: Uint8Array,
  txHash: Uint8Array,
): boolean {
  const msg = signingMessage(txHash);
  return ml_dsa65.verify(publicKey, msg, sig, DOMAIN);
}

// ── Hex helpers ────────────────────────────────────────────────────────────

/** Encode bytes to a 0x-prefixed hex string. */
export function toHex(bytes: Uint8Array): string {
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Decode a 0x-prefixed hex string to bytes. */
export function fromHex(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
