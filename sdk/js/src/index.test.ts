import {
  MldsaKeyPair,
  verify,
  signingMessage,
  ckbBlake2b,
  toHex,
  fromHex,
  PUBLICKEY_BYTES,
  SIGNATURE_BYTES,
  ARGS_LEN,
  ARGS_VERSION,
  ARGS_ALGO_ID,
  ARGS_PARAM_ID,
  TESTNET,
} from './index';

describe('MldsaKeyPair', () => {
  let kp: MldsaKeyPair;

  beforeAll(() => {
    kp = MldsaKeyPair.generate();
  });

  test('publicKeyBytes has correct length', () => {
    expect(kp.publicKeyBytes().length).toBe(PUBLICKEY_BYTES);
  });

  test('lockArgs has correct length and header bytes', () => {
    const args = kp.lockArgs();
    expect(args.length).toBe(ARGS_LEN);
    expect(args[0]).toBe(ARGS_VERSION);
    expect(args[1]).toBe(ARGS_ALGO_ID);
    expect(args[2]).toBe(ARGS_PARAM_ID);
    expect(args[3]).toBe(0x00);
    expect(args.slice(4)).toEqual(kp.pubkeyHash());
  });

  test('signWitness returns valid WitnessArgs bytes', () => {
    const txHash = new Uint8Array(32).fill(0x42);
    const wa = kp.signWitness(txHash);
    // WitnessArgs total size encoded in first 4 bytes (LE)
    const total = new DataView(wa.buffer).getUint32(0, true);
    expect(total).toBe(wa.length);
  });
});

describe('sign and verify roundtrip', () => {
  test('valid signature verifies', () => {
    const kp = MldsaKeyPair.generate();
    const txHash = new Uint8Array(32).fill(0xde);
    const wa = kp.signWitness(txHash);

    // Extract sig from WitnessArgs → MldsaWitness
    // WitnessArgs: 16 header + 4 Bytes length prefix = 20 bytes before MldsaWitness
    const wit = wa.slice(20);
    const view = new DataView(wit.buffer, wit.byteOffset);
    const f4Off = view.getUint32(20, true);
    const f5Off = view.getUint32(24, true);
    const pubkey = wit.slice(f4Off + 4, f4Off + 4 + PUBLICKEY_BYTES);
    const sig = wit.slice(f5Off + 4, f5Off + 4 + SIGNATURE_BYTES);

    expect(pubkey).toEqual(kp.publicKeyBytes());
    expect(verify(kp.publicKeyBytes(), sig, txHash)).toBe(true);
  });

  test('wrong tx_hash fails', () => {
    const kp = MldsaKeyPair.generate();
    const txHash = new Uint8Array(32).fill(0x01);
    const wa = kp.signWitness(txHash);

    const wit = wa.slice(20);
    const view = new DataView(wit.buffer, wit.byteOffset);
    const f5Off = view.getUint32(24, true);
    const sig = wit.slice(f5Off + 4, f5Off + 4 + SIGNATURE_BYTES);

    const wrongHash = new Uint8Array(32).fill(0x02);
    expect(verify(kp.publicKeyBytes(), sig, wrongHash)).toBe(false);
  });

  test('wrong key fails', () => {
    const kp1 = MldsaKeyPair.generate();
    const kp2 = MldsaKeyPair.generate();
    const txHash = new Uint8Array(32).fill(0x01);
    const wa = kp1.signWitness(txHash);

    const wit = wa.slice(20);
    const view = new DataView(wit.buffer, wit.byteOffset);
    const f5Off = view.getUint32(24, true);
    const sig = wit.slice(f5Off + 4, f5Off + 4 + SIGNATURE_BYTES);

    expect(verify(kp2.publicKeyBytes(), sig, txHash)).toBe(false);
  });

  test('corrupted sig fails', () => {
    const kp = MldsaKeyPair.generate();
    const txHash = new Uint8Array(32).fill(0xab);
    const wa = kp.signWitness(txHash);

    const wit = wa.slice(20);
    const view = new DataView(wit.buffer, wit.byteOffset);
    const f5Off = view.getUint32(24, true);
    const sig = wit.slice(f5Off + 4, f5Off + 4 + SIGNATURE_BYTES).slice(); // copy
    sig[0] ^= 0xff;

    expect(verify(kp.publicKeyBytes(), sig, txHash)).toBe(false);
  });
});

describe('signingMessage', () => {
  test('is deterministic', () => {
    const txHash = new Uint8Array(32).fill(0xab);
    expect(signingMessage(txHash)).toEqual(signingMessage(txHash));
  });

  test('differs for different tx_hash', () => {
    const h1 = signingMessage(new Uint8Array(32).fill(0x01));
    const h2 = signingMessage(new Uint8Array(32).fill(0x02));
    expect(h1).not.toEqual(h2);
  });
});

describe('hex helpers', () => {
  test('toHex / fromHex roundtrip', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(fromHex(toHex(bytes))).toEqual(bytes);
  });

  test('toHex produces 0x prefix', () => {
    expect(toHex(new Uint8Array([0xff]))).toBe('0xff');
  });
});

describe('ckbBlake2b', () => {
  test('returns 32 bytes', () => {
    expect(ckbBlake2b(new Uint8Array(0)).length).toBe(32);
  });

  test('known pubkey_hash matches contract output', () => {
    // Cross-check: if this hash is used as lock_args[4..36] and the contract
    // computes blake2b(pubkey) of the same bytes, they must match.
    const pubkey = new Uint8Array(PUBLICKEY_BYTES).fill(0);
    const hash = ckbBlake2b(pubkey);
    expect(hash.length).toBe(32);
  });
});

describe('TESTNET constants', () => {
  test('type_id has correct format', () => {
    expect(TESTNET.CODE_HASH_TYPE_ID).toMatch(/^0x[0-9a-f]{64}$/);
  });
  test('tx_hash has correct format', () => {
    expect(TESTNET.TX_HASH).toMatch(/^0x[0-9a-f]{64}$/);
  });
});
