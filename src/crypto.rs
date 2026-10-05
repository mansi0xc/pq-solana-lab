//! Shared signature-scheme interface.
//!
//! The interface is byte-oriented: keys and signatures cross module and
//! (later) process boundaries as canonical byte strings. Each adapter
//! converts bytes into its library's typed values at the boundary and reports
//! malformed input as an explicit error instead of panicking.
//!
//! # Verification result contract
//!
//! [`Scheme::verify`] and [`Scheme::verify_strict`] return:
//!
//! - `Ok(true)` — the verifier backend accepted the signature.
//! - `Ok(false)` — the backend rejected the signature. This is an *opaque*
//!   rejection: the backend performs its own internal checks (for Ed25519,
//!   for example, the S-range and point-decompression checks happen inside
//!   `ed25519-dalek`), and `Ok(false)` does not identify which check failed.
//!   Do not infer an input class (e.g. "correctly sized corrupted signature")
//!   from `Ok(false)` alone; benchmark input classes are constructed from
//!   their documented fixtures, not inferred from the verdict.
//! - `Err(CryptoError::InvalidLength)` — the adapter detected a wrong byte
//!   length before invoking the backend.
//! - `Err(CryptoError::MalformedEncoding)` — the adapter failed to parse a
//!   public key from its bytes (for Ed25519, point decompression failed).
//!
//! The only difference between [`Scheme::verify`] and
//! [`Scheme::verify_strict`] is the Ed25519 backend mode: `verify_strict`
//! additionally rejects weak (low-order) public keys and signatures with
//! small-order components. ML-DSA has no such distinction, so the two paths
//! are identical there. Authorization uses [`Scheme::verify_strict`].
//!
//! # Prepared keys
//!
//! The byte-oriented [`Scheme::sign`] / [`Scheme::verify`] paths reconstruct a
//! typed key from bytes on every call (ML-DSA reconstruction includes key
//! expansion). [`Scheme::prepare_signer`] and [`Scheme::prepare_verifier`]
//! parse the key once into a [`PreparedSigner`] / [`PreparedVerifier`], for
//! measurements that want to exclude reconstruction and allocation.

pub mod ed25519;
pub mod ml_dsa;

use std::fmt;

/// Signature schemes supported by this prototype.
///
/// The `u8` discriminant is the stable identifier used inside signed
/// application intents (see M2). Do not renumber existing schemes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Scheme {
    /// Ed25519 (RFC 8032), classical comparison baseline.
    Ed25519 = 1,
    /// ML-DSA-44 (FIPS 204), claimed NIST security strength category 2.
    MlDsa44 = 2,
}

impl Scheme {
    pub const ALL: [Scheme; 2] = [Scheme::Ed25519, Scheme::MlDsa44];

    pub fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(id: u8) -> Result<Scheme, CryptoError> {
        match id {
            1 => Ok(Scheme::Ed25519),
            2 => Ok(Scheme::MlDsa44),
            other => Err(CryptoError::UnknownScheme(other)),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Scheme::Ed25519 => "ed25519",
            Scheme::MlDsa44 => "ml-dsa-44",
        }
    }

    /// Human-facing security-category label. Categories are not comparable
    /// across classical and post-quantum regimes; never collapse them.
    pub fn category_label(self) -> &'static str {
        match self {
            Scheme::Ed25519 => "classical (~128-bit classical security)",
            Scheme::MlDsa44 => "NIST category 2 (post-quantum)",
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            Scheme::Ed25519 => ed25519::PUBLIC_KEY_LEN,
            Scheme::MlDsa44 => ml_dsa::PUBLIC_KEY_LEN,
        }
    }

    pub fn secret_key_len(self) -> usize {
        match self {
            Scheme::Ed25519 => ed25519::SECRET_KEY_LEN,
            Scheme::MlDsa44 => ml_dsa::SECRET_KEY_LEN,
        }
    }

    pub fn signature_len(self) -> usize {
        match self {
            Scheme::Ed25519 => ed25519::SIGNATURE_LEN,
            Scheme::MlDsa44 => ml_dsa::SIGNATURE_LEN,
        }
    }

    /// Generate a fresh key pair using OS-backed randomness.
    pub fn keygen(self) -> Result<KeyPair, CryptoError> {
        match self {
            Scheme::Ed25519 => ed25519::keygen(),
            Scheme::MlDsa44 => ml_dsa::keygen(),
        }
    }

    /// Sign `msg` with the secret key bytes of this scheme (byte path).
    ///
    /// ML-DSA is used in pure mode with an empty context string and
    /// randomized (hedged) signing; Ed25519 is deterministic RFC 8032.
    pub fn sign(self, secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Scheme::Ed25519 => ed25519::sign(secret_key, msg),
            Scheme::MlDsa44 => ml_dsa::sign(secret_key, msg),
        }
    }

    /// Verify `sig` on `msg` under `public_key` (byte path). See the module
    /// documentation for the precise `Ok(bool)` versus `Err` contract.
    pub fn verify(self, public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        match self {
            Scheme::Ed25519 => ed25519::verify(public_key, msg, sig),
            Scheme::MlDsa44 => ml_dsa::verify(public_key, msg, sig),
        }
    }

    /// Strict verification (byte path). For Ed25519 this additionally rejects
    /// weak public keys and small-order signature components; ML-DSA is
    /// unchanged. The authorization path uses this.
    pub fn verify_strict(
        self,
        public_key: &[u8],
        msg: &[u8],
        sig: &[u8],
    ) -> Result<bool, CryptoError> {
        match self {
            Scheme::Ed25519 => ed25519::verify_strict(public_key, msg, sig),
            Scheme::MlDsa44 => ml_dsa::verify_strict(public_key, msg, sig),
        }
    }

    /// Validate a public key for registration into the trusted registry.
    ///
    /// Ed25519 rejects both non-decompressible encodings
    /// ([`CryptoError::MalformedEncoding`]) and weak (low-order) keys
    /// ([`CryptoError::WeakKey`]). ML-DSA validates that the fixed-size key
    /// deserializes; FIPS 204 defines no analogous "weak public key" concept.
    pub fn validate_public_key(self, public_key: &[u8]) -> Result<(), CryptoError> {
        match self {
            Scheme::Ed25519 => ed25519::validate_public_key(public_key),
            Scheme::MlDsa44 => ml_dsa::validate_public_key(public_key),
        }
    }

    /// Parse a secret key once into a prepared signer.
    pub fn prepare_signer(self, secret_key: &[u8]) -> Result<PreparedSigner, CryptoError> {
        match self {
            Scheme::Ed25519 => Ok(PreparedSigner::Ed25519(Box::new(ed25519::prepare_signer(
                secret_key,
            )?))),
            Scheme::MlDsa44 => Ok(PreparedSigner::MlDsa44(Box::new(ml_dsa::prepare_signer(
                secret_key,
            )?))),
        }
    }

    /// Parse a public key once into a prepared verifier.
    pub fn prepare_verifier(self, public_key: &[u8]) -> Result<PreparedVerifier, CryptoError> {
        match self {
            Scheme::Ed25519 => Ok(PreparedVerifier::Ed25519(Box::new(
                ed25519::prepare_verifier(public_key)?,
            ))),
            Scheme::MlDsa44 => Ok(PreparedVerifier::MlDsa44(Box::new(
                ml_dsa::prepare_verifier(public_key)?,
            ))),
        }
    }
}

/// A generated key pair in canonical byte form.
///
/// `secret` is held as plain heap bytes: acceptable for this local research
/// prototype, and not a custody design. Never print or serialize `secret`
/// into logs or results.
pub struct KeyPair {
    pub scheme: Scheme,
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

/// A secret key parsed once, so repeated signing avoids per-call
/// reconstruction and allocation.
pub enum PreparedSigner {
    Ed25519(Box<ed25519::PreparedSigner>),
    MlDsa44(Box<ml_dsa::PreparedSigner>),
}

impl PreparedSigner {
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            PreparedSigner::Ed25519(s) => s.sign(msg),
            PreparedSigner::MlDsa44(s) => s.sign(msg),
        }
    }
}

/// A public key parsed once, so repeated verification avoids per-call
/// reconstruction and allocation.
pub enum PreparedVerifier {
    Ed25519(Box<ed25519::PreparedVerifier>),
    MlDsa44(Box<ml_dsa::PreparedVerifier>),
}

impl PreparedVerifier {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        match self {
            PreparedVerifier::Ed25519(v) => v.verify(msg, sig),
            PreparedVerifier::MlDsa44(v) => v.verify(msg, sig),
        }
    }

    pub fn verify_strict(&self, msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        match self {
            PreparedVerifier::Ed25519(v) => v.verify_strict(msg, sig),
            PreparedVerifier::MlDsa44(v) => v.verify_strict(msg, sig),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// OS randomness or library-internal failure.
    Rng(String),
    /// Input byte slice had the wrong length for the scheme.
    InvalidLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
    /// Input had the right length but failed to decode.
    MalformedEncoding(&'static str),
    /// A public key that is cryptographically weak (Ed25519 low-order point).
    WeakKey,
    /// Scheme identifier byte did not name a supported scheme.
    UnknownScheme(u8),
    /// Signing failed inside the library.
    Sign(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Rng(e) => write!(f, "randomness failure: {e}"),
            CryptoError::InvalidLength {
                what,
                expected,
                actual,
            } => write!(
                f,
                "invalid {what} length: expected {expected} bytes, got {actual}"
            ),
            CryptoError::MalformedEncoding(what) => {
                write!(f, "malformed {what} encoding")
            }
            CryptoError::WeakKey => write!(f, "weak (low-order) public key"),
            CryptoError::UnknownScheme(id) => write!(f, "unknown scheme id {id}"),
            CryptoError::Sign(e) => write!(f, "signing failure: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}
