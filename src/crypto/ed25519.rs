//! Ed25519 adapter (RFC 8032, deterministic signing) via `ed25519-dalek`.
//!
//! Byte encodings are the canonical ones: 32-byte compressed public key,
//! 32-byte secret seed, 64-byte signature.
//!
//! Verification semantics: `ed25519-dalek` 3.0's `VerifyingKey::from_bytes`
//! validates the point under ZIP-215 rules (not the stricter RFC 8032/NIST
//! criteria). [`super::CryptoError::WeakKey`] is reported separately via
//! `is_weak`, because a low-order key decompresses successfully yet is
//! cryptographically unusable (it lets an attacker forge signatures with no
//! secret key). The authorization path therefore uses `verify_strict`, which
//! denies weak keys, and registration rejects weak keys outright.

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
    prepare_signer(secret_key)?.sign(msg)
}

pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
    prepare_verifier(public_key)?.verify(msg, sig)
}

pub fn verify_strict(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
    prepare_verifier(public_key)?.verify_strict(msg, sig)
}

pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
    let verifier = prepare_verifier(public_key)?;
    if verifier.is_weak() {
        return Err(CryptoError::WeakKey);
    }
    Ok(())
}

/// A secret key parsed once, for repeated signing without reconstruction.
pub struct PreparedSigner(SigningKey);

/// A public key parsed once, for repeated verification without reconstruction.
pub struct PreparedVerifier(VerifyingKey);

pub fn prepare_signer(secret_key: &[u8]) -> Result<PreparedSigner, CryptoError> {
    let seed: &[u8; SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "ed25519 secret key",
                expected: SECRET_KEY_LEN,
                actual: secret_key.len(),
            })?;
    Ok(PreparedSigner(SigningKey::from_bytes(seed)))
}

pub fn prepare_verifier(public_key: &[u8]) -> Result<PreparedVerifier, CryptoError> {
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
    Ok(PreparedVerifier(vk))
}

impl PreparedSigner {
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.0.sign(msg).to_bytes().to_vec())
    }

    /// Derive the public key from the secret seed (used by known-answer tests
    /// to check key expansion against an external vector).
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
}

impl PreparedVerifier {
    pub fn is_weak(&self) -> bool {
        self.0.is_weak()
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        let sig_bytes = signature_bytes(sig)?;
        Ok(self
            .0
            .verify(msg, &Signature::from_bytes(sig_bytes))
            .is_ok())
    }

    pub fn verify_strict(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        let sig_bytes = signature_bytes(sig)?;
        Ok(self
            .0
            .verify_strict(msg, &Signature::from_bytes(sig_bytes))
            .is_ok())
    }
}

fn signature_bytes(sig: &[u8]) -> Result<&[u8; SIGNATURE_LEN], CryptoError> {
    sig.try_into().map_err(|_| CryptoError::InvalidLength {
        what: "ed25519 signature",
        expected: SIGNATURE_LEN,
        actual: sig.len(),
    })
}
