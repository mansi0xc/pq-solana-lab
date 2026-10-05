//! ML-DSA-65 adapter (FIPS 204) via the `fips204` crate.
//!
//! Configuration recorded for the benchmark metadata:
//! - Parameter set: ML-DSA-65 (claimed NIST security strength category 3).
//! - Mode: pure ML-DSA (not pre-hashed), context string = empty (`b""`).
//! - Signing randomness: randomized ("hedged") signing, the library default.
//! - Key generation randomness: OS-backed via the crate's `default-rng`.
//!
//! ML-DSA has no "strict" vs "weak key" distinction; `verify_strict` is an
//! alias for `verify` here.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};

use super::{CryptoError, KeyPair, Scheme};

pub const PUBLIC_KEY_LEN: usize = ml_dsa_65::PK_LEN;
pub const SECRET_KEY_LEN: usize = ml_dsa_65::SK_LEN;
pub const SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

/// FIPS 204 context string. Empty: application domain separation lives in the
/// canonical intent encoding (domain prefix + identifiers), not here.
const CONTEXT: &[u8] = b"";

pub fn keygen() -> Result<KeyPair, CryptoError> {
    let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(KeyPair {
        scheme: Scheme::MlDsa65,
        public: pk.into_bytes().to_vec(),
        secret: sk.into_bytes().to_vec(),
    })
}

pub fn sign(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    prepare_signer(secret_key)?.sign(msg)
}

pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
    prepare_verifier(public_key)?.verify(msg, sig)
}

pub fn verify_strict(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
    prepare_verifier(public_key)?.verify(msg, sig)
}

pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
    prepare_verifier(public_key).map(|_| ())
}

/// A secret key parsed once (key expansion happens here, not per sign).
pub struct PreparedSigner(ml_dsa_65::PrivateKey);

/// A public key parsed once (verification precomputation happens here).
pub struct PreparedVerifier(ml_dsa_65::PublicKey);

pub fn prepare_signer(secret_key: &[u8]) -> Result<PreparedSigner, CryptoError> {
    let sk_bytes: [u8; SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "ml-dsa-44 secret key",
                expected: SECRET_KEY_LEN,
                actual: secret_key.len(),
            })?;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
        .map_err(|_| CryptoError::MalformedEncoding("ml-dsa-44 secret key"))?;
    Ok(PreparedSigner(sk))
}

pub fn prepare_verifier(public_key: &[u8]) -> Result<PreparedVerifier, CryptoError> {
    let pk_bytes: [u8; PUBLIC_KEY_LEN] =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "ml-dsa-44 public key",
                expected: PUBLIC_KEY_LEN,
                actual: public_key.len(),
            })?;
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
        .map_err(|_| CryptoError::MalformedEncoding("ml-dsa-44 public key"))?;
    Ok(PreparedVerifier(pk))
}

impl PreparedSigner {
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0
            .try_sign(msg, CONTEXT)
            .map(|sig| sig.to_vec())
            .map_err(|e| CryptoError::Sign(e.to_string()))
    }
}

impl PreparedVerifier {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        let sig_bytes: [u8; SIGNATURE_LEN] =
            sig.try_into().map_err(|_| CryptoError::InvalidLength {
                what: "ml-dsa-44 signature",
                expected: SIGNATURE_LEN,
                actual: sig.len(),
            })?;
        Ok(self.0.verify(msg, &sig_bytes, CONTEXT))
    }

    pub fn verify_strict(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        self.verify(msg, sig)
    }
}
