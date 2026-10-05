//! Local withdrawal-authorization policy.
//!
//! Replay state (`next_nonce` and `ledger`) is in-memory only: it does not
//! survive a process restart. See `docs/threat-model.md`.

use std::collections::HashMap;

use crate::crypto::{CryptoError, Scheme};
use crate::intent::{IntentError, WithdrawalIntent, DOMAIN_PREFIX};

/// Expected application environment. A request must bind to these before it
/// is authorized.
///
/// The encoding *version* is deliberately not a field here: it is a format
/// version enforced by the intent decoder (`ENCODING_VERSION`), not a
/// configurable environment attribute. Only encoding version 1 exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Environment {
    pub domain: [u8; 8],
    pub network_id: [u8; 32],
    pub program_id: [u8; 32],
}

impl Environment {
    pub fn new(network_id: [u8; 32], program_id: [u8; 32]) -> Self {
        Self {
            domain: DOMAIN_PREFIX,
            network_id,
            program_id,
        }
    }
}

/// A trusted registration: which scheme and public key a given `key_id` is
/// permitted to use. Verification keys are selected *only* from this registry,
/// never from bytes supplied with a request.
#[derive(Clone, Debug)]
pub struct RegisteredKey {
    pub key_id: u32,
    pub scheme: Scheme,
    pub public_key: Vec<u8>,
}

/// A mock ledger entry recording one authorized withdrawal. The signed asset
/// identifier is preserved so requests for different assets stay
/// distinguishable. (Preserving the full validated intent or a digest would
/// improve traceability further but is out of scope to avoid a hashing
/// dependency; the asset field covers the reported ambiguity.)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthorizationRecord {
    pub key_id: u32,
    pub asset: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
    pub at_slot: u64,
}

#[derive(Debug, Default)]
pub struct KeyRegistry {
    keys: HashMap<u32, RegisteredKey>,
}

impl KeyRegistry {
    /// Register a key. Rejects duplicates, wrong-length key material, weak
    /// (low-order) Ed25519 keys, and non-decompressible encodings via
    /// [`Scheme::validate_public_key`].
    pub fn register(&mut self, key: RegisteredKey) -> Result<(), AuthError> {
        if self.keys.contains_key(&key.key_id) {
            return Err(AuthError::DuplicateRegistration(key.key_id));
        }
        key.scheme
            .validate_public_key(&key.public_key)
            .map_err(|e| match e {
                CryptoError::WeakKey => AuthError::WeakKey(key.key_id),
                _ => AuthError::MalformedRegistration(key.key_id),
            })?;
        self.keys.insert(key.key_id, key);
        Ok(())
    }

    pub fn get(&self, key_id: u32) -> Option<&RegisteredKey> {
        self.keys.get(&key_id)
    }
}

pub struct Authorizer {
    env: Environment,
    registry: KeyRegistry,
    next_nonce: HashMap<u32, u64>,
    ledger: Vec<AuthorizationRecord>,
}

impl Authorizer {
    pub fn new(env: Environment, registry: KeyRegistry) -> Self {
        Self {
            env,
            registry,
            next_nonce: HashMap::new(),
            ledger: Vec::new(),
        }
    }

    /// Current expected nonce for a key (0 if no request has been seen).
    pub fn expected_nonce(&self, key_id: u32) -> u64 {
        self.next_nonce.get(&key_id).copied().unwrap_or(0)
    }

    pub fn ledger(&self) -> &[AuthorizationRecord] {
        &self.ledger
    }

    /// Authorize a signed intent. Consumes exactly one nonce on success and
    /// leaves all state unchanged on any rejection.
    pub fn authorize(
        &mut self,
        intent_bytes: &[u8],
        signature: &[u8],
        current_slot: u64,
    ) -> Result<AuthorizationRecord, AuthError> {
        let intent = WithdrawalIntent::decode(intent_bytes).map_err(AuthError::MalformedIntent)?;

        if intent.amount == 0 {
            return Err(AuthError::ZeroAmount);
        }

        let registered = self
            .registry
            .get(intent.key_id)
            .ok_or(AuthError::UnregisteredKey(intent.key_id))?
            .clone();

        if registered.scheme != intent.scheme {
            return Err(AuthError::SchemeMismatch {
                key_id: intent.key_id,
                registered: registered.scheme,
                requested: intent.scheme,
            });
        }

        // Strict verification: for Ed25519 this denies weak keys and
        // small-order signature components in addition to the ordinary
        // checks. Registration also rejects weak keys; this is defense in
        // depth at the verification step.
        match registered
            .scheme
            .verify_strict(&registered.public_key, intent_bytes, signature)
        {
            Ok(true) => {}
            Ok(false) => return Err(AuthError::InvalidSignature),
            Err(e) => return Err(AuthError::MalformedSignature(e)),
        }

        if intent.domain != self.env.domain {
            return Err(AuthError::DomainMismatch);
        }
        if intent.network_id != self.env.network_id {
            return Err(AuthError::NetworkMismatch);
        }
        if intent.program_id != self.env.program_id {
            return Err(AuthError::ProgramMismatch);
        }
        // Encoding version is enforced by the decoder; there is no separate
        // configurable environment version.

        if current_slot > intent.expiry_slot {
            return Err(AuthError::Expired {
                expiry_slot: intent.expiry_slot,
                current_slot,
            });
        }

        let expected = self.next_nonce.get(&intent.key_id).copied().unwrap_or(0);
        if intent.nonce != expected {
            return Err(AuthError::NonceMismatch {
                expected,
                actual: intent.nonce,
            });
        }

        let next = expected.checked_add(1).ok_or(AuthError::NonceOverflow)?;

        // Commit: atomic within this single-threaded process.
        self.next_nonce.insert(intent.key_id, next);
        let record = AuthorizationRecord {
            key_id: intent.key_id,
            asset: intent.asset,
            recipient: intent.recipient,
            amount: intent.amount,
            nonce: intent.nonce,
            at_slot: current_slot,
        };
        self.ledger.push(record.clone());
        Ok(record)
    }

    #[cfg(test)]
    fn force_expected_nonce(&mut self, key_id: u32, nonce: u64) {
        self.next_nonce.insert(key_id, nonce);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    MalformedIntent(IntentError),
    MalformedSignature(CryptoError),
    MalformedRegistration(u32),
    WeakKey(u32),
    DuplicateRegistration(u32),
    UnregisteredKey(u32),
    SchemeMismatch {
        key_id: u32,
        registered: Scheme,
        requested: Scheme,
    },
    ZeroAmount,
    InvalidSignature,
    DomainMismatch,
    NetworkMismatch,
    ProgramMismatch,
    Expired {
        expiry_slot: u64,
        current_slot: u64,
    },
    NonceMismatch {
        expected: u64,
        actual: u64,
    },
    NonceOverflow,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MalformedIntent(e) => write!(f, "malformed intent: {e}"),
            AuthError::MalformedSignature(e) => write!(f, "malformed signature: {e}"),
            AuthError::MalformedRegistration(id) => {
                write!(f, "registration for key {id} has malformed key material")
            }
            AuthError::WeakKey(id) => {
                write!(
                    f,
                    "registration for key {id} rejected: weak (low-order) key"
                )
            }
            AuthError::DuplicateRegistration(id) => write!(f, "key {id} is already registered"),
            AuthError::UnregisteredKey(id) => write!(f, "key {id} is not registered"),
            AuthError::SchemeMismatch {
                key_id,
                registered,
                requested,
            } => write!(
                f,
                "key {key_id} is registered for {} but the intent requests {}",
                registered.name(),
                requested.name()
            ),
            AuthError::ZeroAmount => write!(f, "withdrawal amount must be non-zero"),
            AuthError::InvalidSignature => write!(f, "signature is not valid for the intent"),
            AuthError::DomainMismatch => write!(f, "intent domain does not match the environment"),
            AuthError::NetworkMismatch => {
                write!(f, "intent network id does not match the environment")
            }
            AuthError::ProgramMismatch => {
                write!(f, "intent program id does not match the environment")
            }
            AuthError::Expired {
                expiry_slot,
                current_slot,
            } => write!(
                f,
                "intent expired: expiry slot {expiry_slot} < current slot {current_slot}"
            ),
            AuthError::NonceMismatch { expected, actual } => {
                write!(f, "nonce mismatch: expected {expected}, got {actual}")
            }
            AuthError::NonceOverflow => write!(f, "nonce counter overflow"),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::WithdrawalIntent;

    #[test]
    fn nonce_overflow_is_rejected() {
        let mut registry = KeyRegistry::default();
        let kp = Scheme::Ed25519.keygen().unwrap();
        registry
            .register(RegisteredKey {
                key_id: 1,
                scheme: Scheme::Ed25519,
                public_key: kp.public.clone(),
            })
            .unwrap();
        let mut authorizer = Authorizer::new(Environment::new([0; 32], [0; 32]), registry);
        authorizer.force_expected_nonce(1, u64::MAX);

        let it = WithdrawalIntent::new(
            Scheme::Ed25519,
            1,
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            1,
            u64::MAX,
            u64::MAX,
        );
        let bytes = it.encode();
        let sig = Scheme::Ed25519.sign(&kp.secret, &bytes).unwrap();
        assert_eq!(
            authorizer.authorize(&bytes, &sig, 0).unwrap_err(),
            AuthError::NonceOverflow
        );
        assert_eq!(authorizer.expected_nonce(1), u64::MAX);
        assert!(authorizer.ledger().is_empty());
    }

    // Regression test for the reviewer's "secretless authorization" finding.
    // Bypass registration validation to force a weak (identity-point) Ed25519
    // key into the registry, then show that strict verification still rejects
    // the identity-R/zero-S forgery without touching nonce or ledger state.
    #[test]
    fn secretless_authorization_via_weak_key_is_rejected_by_verify_strict() {
        // Identity point: y = 1, x sign bit = 0.
        let weak_pk = {
            let mut v = vec![0u8; 32];
            v[0] = 1;
            v
        };
        // Forgery: R = identity point, S = 0.
        let mut sig = vec![0u8; 64];
        sig[0] = 1;

        let mut authorizer = Authorizer::new(
            Environment::new([0xab; 32], [0xcd; 32]),
            KeyRegistry::default(),
        );
        // Force the weak key into the registry, skipping validation, to model
        // "a weak key was admitted to the trusted registry".
        authorizer.registry.keys.insert(
            42,
            RegisteredKey {
                key_id: 42,
                scheme: Scheme::Ed25519,
                public_key: weak_pk,
            },
        );

        let it = WithdrawalIntent::new(
            Scheme::Ed25519,
            42,
            [0xab; 32],
            [0xcd; 32],
            [0x01; 32],
            [0x02; 32],
            100,
            0,
            1000,
        );
        let bytes = it.encode();

        assert_eq!(
            authorizer.authorize(&bytes, &sig, 500).unwrap_err(),
            AuthError::InvalidSignature
        );
        // State unchanged.
        assert_eq!(authorizer.expected_nonce(42), 0);
        assert!(authorizer.ledger().is_empty());
    }
}
