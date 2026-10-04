//! Shared signature-scheme interface.
//!
//! The interface is byte-oriented: keys and signatures cross module and
//! (later) process boundaries as canonical byte strings. Each adapter
//! converts bytes into its library's typed values at the boundary and reports
//! malformed input as an explicit error instead of panicking.
//!
//! Verdict semantics of [`verify`]:
//! - `Ok(true)` / `Ok(false)` — inputs were structurally well-formed; the
//!   signature is cryptographically valid or invalid.
//! - `Err(CryptoError::InvalidLength | CryptoError::MalformedEncoding)` —
//!   input could not be parsed. This is a different workload from
//!   cryptographic rejection and is reported separately in benchmarks.

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

    /// Sign `msg` with the secret key bytes of this scheme.
    ///
    /// ML-DSA is used in pure mode with an empty context string and
    /// randomized (hedged) signing; Ed25519 is deterministic RFC 8032.
    pub fn sign(self, secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Scheme::Ed25519 => ed25519::sign(secret_key, msg),
            Scheme::MlDsa44 => ml_dsa::sign(secret_key, msg),
        }
    }

    /// Verify `sig` on `msg` under `public_key`. See module docs for the
    /// `Ok(bool)` versus `Err` distinction.
    pub fn verify(self, public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        match self {
            Scheme::Ed25519 => ed25519::verify(public_key, msg, sig),
            Scheme::MlDsa44 => ml_dsa::verify(public_key, msg, sig),
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
            CryptoError::UnknownScheme(id) => write!(f, "unknown scheme id {id}"),
            CryptoError::Sign(e) => write!(f, "signing failure: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}
