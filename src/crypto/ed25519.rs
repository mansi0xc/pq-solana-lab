//! Ed25519 adapter (RFC 8032, deterministic signing) via `ed25519-dalek`.
//!
//! Byte encodings are the canonical ones: 32-byte compressed public key,
//! 32-byte secret seed, 64-byte signature.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::{CryptoError, KeyPair, Scheme};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

pub fn keygen() -> Result<KeyPair, CryptoError> {
    let mut seed = [0u8; SECRET_KEY_LEN];
    getrandom::fill(&mut seed).map_err(|e| CryptoError::Rng(e.to_string()))?;
    let sk = SigningKey::from_bytes(&seed);
    Ok(KeyPair {
        scheme: Scheme::Ed25519,
        public: sk.verifying_key().to_bytes().to_vec(),
        secret: seed.to_vec(),
    })
}

pub fn sign(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed: &[u8; SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "ed25519 secret key",
                expected: SECRET_KEY_LEN,
                actual: secret_key.len(),
            })?;
    let sk = SigningKey::from_bytes(seed);
    Ok(sk.sign(msg).to_bytes().to_vec())
}

pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
    let pk_bytes: &[u8; PUBLIC_KEY_LEN] =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "ed25519 public key",
                expected: PUBLIC_KEY_LEN,
                actual: public_key.len(),
            })?;
    let vk = VerifyingKey::from_bytes(pk_bytes)
        .map_err(|_| CryptoError::MalformedEncoding("ed25519 public key"))?;
    let sig_bytes: &[u8; SIGNATURE_LEN] =
        sig.try_into().map_err(|_| CryptoError::InvalidLength {
            what: "ed25519 signature",
            expected: SIGNATURE_LEN,
            actual: sig.len(),
        })?;
    Ok(vk.verify(msg, &Signature::from_bytes(sig_bytes)).is_ok())
}
