//! CKB ML-DSA-65 lock script SDK.
//!
//! Provides key generation, signing, and witness serialization for interacting
//! with the `mldsa-lock` contract deployed on CKB.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use ckb_mldsa_sdk::MldsaKeyPair;
//!
//! // Generate a new key pair
//! let keypair = MldsaKeyPair::generate();
//!
//! // Derive the lock args — put these in the script.args field when creating a cell
//! let lock_args = keypair.lock_args();
//! println!("lock args: {}", hex::encode(lock_args));
//!
//! // When spending: sign the tx_hash and build the witness
//! let tx_hash = [0u8; 32]; // obtain from CKB RPC / ckb_load_tx_hash
//! let witness = keypair.sign_witness(&tx_hash);
//! ```

use blake2b_ref::Blake2bBuilder;
use ckb_mldsa_molecule as molecule;
use fips204::ml_dsa_65::{self, SIG_LEN, SK_LEN};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

pub use ckb_mldsa_molecule::{
    ARGS_ALGO_ID, ARGS_LEN, ARGS_PARAM_ID, ARGS_VERSION, DOMAIN, PUBLICKEY_BYTES, SIGNATURE_BYTES,
};

/// CKB blake2b personalization (matches ckb-c-stdlib blake2b_init).
const CKB_BLAKE2B_PERSONAL: &[u8] = b"ckb-default-hash";

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("invalid secret key bytes")]
    InvalidSecretKey,
    #[error("signature verification failed")]
    VerificationFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

/// An ML-DSA-65 key pair.
#[derive(ZeroizeOnDrop)]
pub struct MldsaKeyPair {
    pk_bytes: [u8; PUBLICKEY_BYTES],
    sk: ml_dsa_65::PrivateKey,
}

impl MldsaKeyPair {
    /// Generate a fresh key pair using the OS RNG.
    pub fn generate() -> Self {
        let (pk, sk) = ml_dsa_65::KG::try_keygen().expect("OS RNG failed");
        Self { pk_bytes: pk.into_bytes(), sk }
    }

    /// Restore from raw secret key bytes (4032 bytes).
    pub fn from_secret_key_bytes(sk_bytes: &[u8; SK_LEN]) -> Result<Self> {
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(*sk_bytes)
            .map_err(|_| Error::InvalidSecretKey)?;
        let pk_bytes = sk.get_public_key().into_bytes();
        Ok(Self { pk_bytes, sk })
    }

    /// Raw public key bytes (1952 bytes).
    pub fn public_key_bytes(&self) -> &[u8; PUBLICKEY_BYTES] {
        &self.pk_bytes
    }

    /// `blake2b_256(pubkey)` — the pubkey hash stored in lock args.
    pub fn pubkey_hash(&self) -> [u8; 32] {
        ckb_blake2b(&self.pk_bytes)
    }

    /// 36-byte lock args: `version | algo_id | param_id | reserved | blake2b(pubkey)`.
    /// Use this as the `args` field in the lock script when creating a new cell.
    pub fn lock_args(&self) -> [u8; ARGS_LEN] {
        let mut args = [0u8; ARGS_LEN];
        args[0] = ARGS_VERSION;
        args[1] = ARGS_ALGO_ID;
        args[2] = ARGS_PARAM_ID;
        args[3] = 0x00; // reserved
        args[4..].copy_from_slice(&self.pubkey_hash());
        args
    }

    /// Sign a transaction and return the full `WitnessArgs` Molecule bytes ready
    /// to submit as `witnesses[0]` in the transaction.
    ///
    /// `tx_hash` is the 32-byte hash of the `RawTransaction` Molecule encoding,
    /// returned by `ckb_load_tx_hash()` in the VM or the CKB RPC `tx_hash` field.
    pub fn sign_witness(&self, tx_hash: &[u8; 32]) -> Vec<u8> {
        let msg = signing_message(tx_hash);
        let sig: [u8; SIG_LEN] = self.sk.try_sign(&msg, DOMAIN).expect("signing failed");
        molecule::build_witness(&self.pk_bytes, &sig)
    }
}

/// Compute the CKB-MLDSA signing digest:
///   `blake2b_256("CKB-MLDSA-LOCK" || tx_hash)`
pub fn signing_message(tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut b = Blake2bBuilder::new(32)
        .personal(CKB_BLAKE2B_PERSONAL)
        .build();
    b.update(DOMAIN);
    b.update(tx_hash);
    let mut out = [0u8; 32];
    b.finalize(&mut out);
    out
}

/// CKB blake2b-256 with the "ckb-default-hash" personalization.
pub fn ckb_blake2b(data: &[u8]) -> [u8; 32] {
    let mut b = Blake2bBuilder::new(32)
        .personal(CKB_BLAKE2B_PERSONAL)
        .build();
    b.update(data);
    let mut out = [0u8; 32];
    b.finalize(&mut out);
    out
}

/// Verify an ML-DSA-65 signature against a transaction hash.
pub fn verify(
    pubkey_bytes: &[u8; PUBLICKEY_BYTES],
    sig_bytes: &[u8; SIGNATURE_BYTES],
    tx_hash: &[u8; 32],
) -> Result<()> {
    let pk = ml_dsa_65::PublicKey::try_from_bytes(*pubkey_bytes)
        .map_err(|_| Error::InvalidPublicKey)?;
    let msg = signing_message(tx_hash);
    if pk.verify(&msg, sig_bytes, DOMAIN) {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

/// Testnet deployment constants for `mldsa-lock`.
pub mod testnet {
    /// `type_id` code hash — use with `hash_type: "type"`. Stable across upgrades.
    pub const CODE_HASH_TYPE_ID: &str =
        "0x8984f4230ded4ac1f5efee2b67fef45fcda08bd6344c133a2f378e2f469d310d";
    /// `data_hash` — use with `hash_type: "data1"`. Changes on redeploy.
    pub const CODE_HASH_DATA: &str =
        "0x7dcb281583da642016be3a0a4a4d7d4c4d573df2ae10cd4fb4d1616d74007725";
    /// Deploy transaction hash.
    pub const TX_HASH: &str =
        "0xba4a6560ef719b24d170bf678611b25b799c56e6a80f18ce9c79e9561085cba7";
    /// Output index in the deploy transaction.
    pub const INDEX: u32 = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify() {
        let kp = MldsaKeyPair::generate();
        let tx_hash = [0x42u8; 32];
        let wa = kp.sign_witness(&tx_hash);

        // Parse WitnessArgs → MldsaWitness field offsets
        // WitnessArgs: total(4) + 3 offsets(12) + Bytes len(4) = 20 bytes before MldsaWitness
        let wit = &wa[20..]; // skip WitnessArgs header(16) + Bytes length prefix(4)
        let f4_off = u32::from_le_bytes(wit[20..24].try_into().unwrap()) as usize;
        let f5_off = u32::from_le_bytes(wit[24..28].try_into().unwrap()) as usize;
        let pk: &[u8; PUBLICKEY_BYTES] = wit[f4_off+4..f4_off+4+PUBLICKEY_BYTES].try_into().unwrap();
        let sig: &[u8; SIGNATURE_BYTES] = wit[f5_off+4..f5_off+4+SIGNATURE_BYTES].try_into().unwrap();

        assert_eq!(pk, kp.public_key_bytes());
        verify(pk, sig, &tx_hash).expect("verify failed");
    }

    #[test]
    fn lock_args_format() {
        let kp = MldsaKeyPair::generate();
        let args = kp.lock_args();
        assert_eq!(args.len(), ARGS_LEN);
        assert_eq!(args[0], ARGS_VERSION);
        assert_eq!(args[1], ARGS_ALGO_ID);
        assert_eq!(args[2], ARGS_PARAM_ID);
        assert_eq!(args[3], 0x00);
        assert_eq!(&args[4..], kp.pubkey_hash());
    }

    #[test]
    fn signing_message_deterministic() {
        let tx = [0xabu8; 32];
        assert_eq!(signing_message(&tx), signing_message(&tx));
    }

    #[test]
    fn wrong_sig_fails() {
        let kp = MldsaKeyPair::generate();
        let tx_hash = [0x01u8; 32];
        let bad_sig = [0u8; SIGNATURE_BYTES];
        assert!(verify(kp.public_key_bytes(), &bad_sig, &tx_hash).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = MldsaKeyPair::generate();
        let kp2 = MldsaKeyPair::generate();
        let tx_hash = [0x01u8; 32];
        let wa = kp1.sign_witness(&tx_hash);
        let wit = &wa[20..];
        let f5_off = u32::from_le_bytes(wit[24..28].try_into().unwrap()) as usize;
        let sig: &[u8; SIGNATURE_BYTES] = wit[f5_off+4..f5_off+4+SIGNATURE_BYTES].try_into().unwrap();
        // Verify kp1's sig against kp2's pubkey — must fail
        assert!(verify(kp2.public_key_bytes(), sig, &tx_hash).is_err());
    }
}
