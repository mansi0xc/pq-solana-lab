//! ML-DSA-44 adapter (FIPS 204) via the `fips204` crate.
//!
//! Configuration recorded for the benchmark metadata:
//! - Parameter set: ML-DSA-44 (claimed NIST security strength category 2).
//! - Mode: pure ML-DSA (not pre-hashed), context string = empty (`b""`).
//! - Signing randomness: randomized ("hedged") signing, the library default.
//! - Key generation randomness: OS-backed via the crate's `default-rng`.

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};

use super::{CryptoError, KeyPair, Scheme};

pub const PUBLIC_KEY_LEN: usize = ml_dsa_44::PK_LEN;
pub const SECRET_KEY_LEN: usize = ml_dsa_44::SK_LEN;
pub const SIGNATURE_LEN: usize = ml_dsa_44::SIG_LEN;

/// FIPS 204 context string. Empty: application domain separation lives in the
/// canonical intent encoding (domain prefix + identifiers), not here.
const CONTEXT: &[u8] = b"";

pub fn keygen() -> Result<KeyPair, CryptoError> {
    let (pk, sk) = ml_dsa_44::try_keygen().map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(KeyPair {
        scheme: Scheme::MlDsa44,
        public: pk.into_bytes().to_vec(),
        secret: sk.into_bytes().to_vec(),
    })
}

pub fn sign(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk_bytes: [u8; SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "ml-dsa-44 secret key",
                expected: SECRET_KEY_LEN,
                actual: secret_key.len(),
            })?;
    let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes)
        .map_err(|_| CryptoError::MalformedEncoding("ml-dsa-44 secret key"))?;
    let sig = sk
        .try_sign(msg, CONTEXT)
        .map_err(|e| CryptoError::Sign(e.to_string()))?;
    Ok(sig.to_vec())
}

pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
    let pk_bytes: [u8; PUBLIC_KEY_LEN] =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                what: "ml-dsa-44 public key",
                expected: PUBLIC_KEY_LEN,
                actual: public_key.len(),
            })?;
    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes)
        .map_err(|_| CryptoError::MalformedEncoding("ml-dsa-44 public key"))?;
    let sig_bytes: [u8; SIGNATURE_LEN] =
        sig.try_into().map_err(|_| CryptoError::InvalidLength {
            what: "ml-dsa-44 signature",
            expected: SIGNATURE_LEN,
            actual: sig.len(),
        })?;
    Ok(pk.verify(msg, &sig_bytes, CONTEXT))
}
