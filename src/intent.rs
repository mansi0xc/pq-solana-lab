//! Canonical withdrawal intent encoding (v1). Spec: `docs/encoding.md`.

use crate::crypto::{CryptoError, Scheme};

/// Domain separation prefix, fixed at the front of every intent.
pub const DOMAIN_PREFIX: [u8; 8] = *b"PQSOL-WD";
/// Current encoding version. A byte outside {1} is rejected at decode.
pub const ENCODING_VERSION: u8 = 1;
/// Total encoded length in bytes (see `docs/encoding.md` layout table).
pub const INTENT_LEN: usize = 166;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WithdrawalIntent {
    pub domain: [u8; 8],
    pub version: u8,
    pub scheme: Scheme,
    pub key_id: u32,
    pub network_id: [u8; 32],
    pub program_id: [u8; 32],
    pub asset: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
    pub expiry_slot: u64,
}

impl WithdrawalIntent {
    /// Build an intent with the canonical domain and version filled in.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scheme: Scheme,
        key_id: u32,
        network_id: [u8; 32],
        program_id: [u8; 32],
        asset: [u8; 32],
        recipient: [u8; 32],
        amount: u64,
        nonce: u64,
        expiry_slot: u64,
    ) -> Self {
        Self {
            domain: DOMAIN_PREFIX,
            version: ENCODING_VERSION,
            scheme,
            key_id,
            network_id,
            program_id,
            asset,
            recipient,
            amount,
            nonce,
            expiry_slot,
        }
    }

    /// Serialize to the canonical 166-byte form.
    pub fn encode(&self) -> [u8; INTENT_LEN] {
        let mut out = [0u8; INTENT_LEN];
        out[0..8].copy_from_slice(&self.domain);
        out[8] = self.version;
        out[9] = self.scheme.id();
        out[10..14].copy_from_slice(&self.key_id.to_be_bytes());
        out[14..46].copy_from_slice(&self.network_id);
        out[46..78].copy_from_slice(&self.program_id);
        out[78..110].copy_from_slice(&self.asset);
        out[110..142].copy_from_slice(&self.recipient);
        out[142..150].copy_from_slice(&self.amount.to_be_bytes());
        out[150..158].copy_from_slice(&self.nonce.to_be_bytes());
        out[158..166].copy_from_slice(&self.expiry_slot.to_be_bytes());
        out
    }

    /// Parse canonical bytes. Rejects wrong length, unsupported version, and
    /// unknown scheme; everything else is the authorizer's policy, not the
    /// decoder's.
    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        if bytes.len() != INTENT_LEN {
            return Err(IntentError::InvalidLength {
                expected: INTENT_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[8];
        if version != ENCODING_VERSION {
            return Err(IntentError::UnsupportedVersion(version));
        }
        let scheme = match Scheme::from_id(bytes[9]) {
            Ok(s) => s,
            Err(CryptoError::UnknownScheme(id)) => return Err(IntentError::UnknownScheme(id)),
            Err(_) => unreachable!("Scheme::from_id only fails with UnknownScheme"),
        };
        Ok(Self {
            domain: bytes[0..8].try_into().unwrap(),
            version,
            scheme,
            key_id: u32::from_be_bytes(bytes[10..14].try_into().unwrap()),
            network_id: bytes[14..46].try_into().unwrap(),
            program_id: bytes[46..78].try_into().unwrap(),
            asset: bytes[78..110].try_into().unwrap(),
            recipient: bytes[110..142].try_into().unwrap(),
            amount: u64::from_be_bytes(bytes[142..150].try_into().unwrap()),
            nonce: u64::from_be_bytes(bytes[150..158].try_into().unwrap()),
            expiry_slot: u64::from_be_bytes(bytes[158..166].try_into().unwrap()),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IntentError {
    InvalidLength { expected: usize, actual: usize },
    UnsupportedVersion(u8),
    UnknownScheme(u8),
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid intent length: expected {expected} bytes, got {actual}"
                )
            }
            IntentError::UnsupportedVersion(v) => write!(f, "unsupported encoding version {v}"),
            IntentError::UnknownScheme(id) => write!(f, "unknown scheme id {id}"),
        }
    }
}

impl std::error::Error for IntentError {}
