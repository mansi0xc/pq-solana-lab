//! SLH-DSA-SHA2-128s adapter (FIPS 205) via the `fips205` crate.
//!
//! Configuration recorded for the benchmark metadata:
//! - Parameter set: SLH-DSA-SHA2-128s (claimed NIST security strength category 1).
//! - Mode: pure SLH-DSA, context string = empty (`b""`).
//! - Signing randomness: hedged (randomized) signing, the FIPS 205 default.
//!
//! SLH-DSA has no "strict" vs "weak key" distinction; `verify_strict` is an
//! alias for `verify` here.

use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer, Verifier};

use super::{CryptoError, KeyPair, Scheme};

pub const PUBLIC_KEY_LEN: usize = slh_dsa_sha2_128s::PK_LEN;
pub const SECRET_KEY_LEN: usize = slh_dsa_sha2_128s::SK_LEN;
pub const SIGNATURE_LEN: usize = slh_dsa_sha2_128s::SIG_LEN;

/// FIPS 205 context string. Empty, matching the ML-DSA adapters' convention:
/// application domain separation lives in the canonical intent encoding.
const CONTEXT: &[u8] = b"";
/// Hedged (randomized) signing, the FIPS 205 default for the external API.
const HEDGED: bool = true;

pub fn keygen() -> Result<KeyPair, CryptoError> {
    let (pk, sk) = slh_dsa_sha2_128s::try_keygen().map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(KeyPair {
        scheme: Scheme::SlhDsaSha2128s,
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

/// A secret key parsed once.
pub struct PreparedSigner(slh_dsa_sha2_128s::PrivateKey);

/// A public key parsed once.
pub struct PreparedVerifier(slh_dsa_sha2_128s::PublicKey);

pub fn prepare_signer(secret_key: &[u8]) -> Result<PreparedSigner, CryptoError> {
    let sk_bytes: [u8; SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "slh-dsa-sha2-128s secret key",
                expected: SECRET_KEY_LEN,
                actual: secret_key.len(),
            })?;
    let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&sk_bytes)
        .map_err(|_| CryptoError::MalformedEncoding("slh-dsa-sha2-128s secret key"))?;
    Ok(PreparedSigner(sk))
}

pub fn prepare_verifier(public_key: &[u8]) -> Result<PreparedVerifier, CryptoError> {
    let pk_bytes: [u8; PUBLIC_KEY_LEN] =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "slh-dsa-sha2-128s public key",
                expected: PUBLIC_KEY_LEN,
                actual: public_key.len(),
            })?;
    let pk = slh_dsa_sha2_128s::PublicKey::try_from_bytes(&pk_bytes)
        .map_err(|_| CryptoError::MalformedEncoding("slh-dsa-sha2-128s public key"))?;
    Ok(PreparedVerifier(pk))
}

impl PreparedSigner {
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0
            .try_sign(msg, CONTEXT, HEDGED)
            .map(|sig| sig.to_vec())
            .map_err(|e| CryptoError::Sign(e.to_string()))
    }
}

impl PreparedVerifier {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        let sig_bytes: [u8; SIGNATURE_LEN] =
            sig.try_into().map_err(|_| CryptoError::InvalidLength {
                what: "slh-dsa-sha2-128s signature",
                expected: SIGNATURE_LEN,
                actual: sig.len(),
            })?;
        Ok(self.0.verify(msg, &sig_bytes, CONTEXT))
    }

    pub fn verify_strict(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        self.verify(msg, sig)
    }
}
