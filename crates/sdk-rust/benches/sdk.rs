use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ckb_mldsa_sdk::{MldsaKeyPair, verify, signing_message, ckb_blake2b, PUBLICKEY_BYTES, SIGNATURE_BYTES};

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        b.iter(|| black_box(MldsaKeyPair::generate()))
    });
}

fn bench_sign(c: &mut Criterion) {
    let kp = MldsaKeyPair::generate();
    let tx_hash = [0x42u8; 32];
    c.bench_function("sign_witness", |b| {
        b.iter(|| black_box(kp.sign_witness(black_box(&tx_hash))))
    });
}

fn bench_verify(c: &mut Criterion) {
    let kp = MldsaKeyPair::generate();
    let tx_hash = [0x42u8; 32];
    let wa = kp.sign_witness(&tx_hash);
    // Extract sig from WitnessArgs → MldsaWitness
    let wit = &wa[20..];
    let f4_off = u32::from_le_bytes(wit[20..24].try_into().unwrap()) as usize;
    let f5_off = u32::from_le_bytes(wit[24..28].try_into().unwrap()) as usize;
    let pk: &[u8; PUBLICKEY_BYTES] = wit[f4_off+4..f4_off+4+PUBLICKEY_BYTES].try_into().unwrap();
    let sig: &[u8; SIGNATURE_BYTES] = wit[f5_off+4..f5_off+4+SIGNATURE_BYTES].try_into().unwrap();

    c.bench_function("verify", |b| {
        b.iter(|| black_box(verify(black_box(pk), black_box(sig), black_box(&tx_hash))))
    });
}

fn bench_signing_message(c: &mut Criterion) {
    let tx_hash = [0x42u8; 32];
    c.bench_function("signing_message (blake2b)", |b| {
        b.iter(|| black_box(signing_message(black_box(&tx_hash))))
    });
}

fn bench_pubkey_hash(c: &mut Criterion) {
    let kp = MldsaKeyPair::generate();
    let pk = kp.public_key_bytes();
    c.bench_function("pubkey_hash (blake2b 1952B)", |b| {
        b.iter(|| black_box(ckb_blake2b(black_box(pk))))
    });
}

fn bench_lock_args(c: &mut Criterion) {
    let kp = MldsaKeyPair::generate();
    c.bench_function("lock_args derivation", |b| {
        b.iter(|| black_box(kp.lock_args()))
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_signing_message,
    bench_pubkey_hash,
    bench_lock_args,
);
criterion_main!(benches);
