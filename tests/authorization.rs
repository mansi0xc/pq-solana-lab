//! Application-policy and integrity tests for the local authorization module.
//! Distinguishes signature-integrity rejections from application-policy
//! rejections. Behavioral evidence only; not a security proof.
//!
//! Most scenarios are exercised for both Ed25519 and ML-DSA-44 via `EACH`.

use pq_solana_lab::authorization::{
    AuthError, Authorizer, Environment, KeyRegistry, RegisteredKey,
};
use pq_solana_lab::crypto::Scheme;
use pq_solana_lab::intent::{IntentError, WithdrawalIntent};

const NETWORK: [u8; 32] = [0xab; 32];
const PROGRAM: [u8; 32] = [0xcd; 32];
const ASSET: [u8; 32] = [0x01; 32];
const RECIPIENT: [u8; 32] = [0x02; 32];

const EACH: [(Scheme, u32); 2] = [(Scheme::Ed25519, 1), (Scheme::MlDsa44, 2)];

struct Setup {
    authorizer: Authorizer,
    // (key_id, secret_key) for the two registered keys.
    ed: (u32, Vec<u8>),
    ml: (u32, Vec<u8>),
}

impl Setup {
    fn key(&self, scheme: Scheme) -> (u32, Vec<u8>) {
        match scheme {
            Scheme::Ed25519 => self.ed.clone(),
            Scheme::MlDsa44 => self.ml.clone(),
            other => panic!(
                "authorization test setup only registers ed25519 and ml-dsa-44, got {other:?}"
            ),
        }
    }
}

fn setup() -> Setup {
    let mut registry = KeyRegistry::default();
    let ed = Scheme::Ed25519.keygen().unwrap();
    let ml = Scheme::MlDsa44.keygen().unwrap();
    registry
        .register(RegisteredKey {
            key_id: 1,
            scheme: Scheme::Ed25519,
            public_key: ed.public.clone(),
        })
        .unwrap();
    registry
        .register(RegisteredKey {
            key_id: 2,
            scheme: Scheme::MlDsa44,
            public_key: ml.public.clone(),
        })
        .unwrap();
    Setup {
        authorizer: Authorizer::new(Environment::new(NETWORK, PROGRAM), registry),
        ed: (1, ed.secret),
        ml: (2, ml.secret),
    }
}

fn intent(scheme: Scheme, key_id: u32, nonce: u64, expiry_slot: u64) -> WithdrawalIntent {
    WithdrawalIntent::new(
        scheme,
        key_id,
        NETWORK,
        PROGRAM,
        ASSET,
        RECIPIENT,
        100,
        nonce,
        expiry_slot,
    )
}

fn submit(
    authorizer: &mut Authorizer,
    intent: &WithdrawalIntent,
    scheme: Scheme,
    secret: &[u8],
    slot: u64,
) -> Result<pq_solana_lab::authorization::AuthorizationRecord, AuthError> {
    let bytes = intent.encode();
    let sig = scheme.sign(secret, &bytes).unwrap();
    authorizer.authorize(&bytes, &sig, slot)
}

#[test]
fn valid_request_is_accepted_and_consumes_one_nonce() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = intent(scheme, key_id, 0, 1000);
        let rec = submit(&mut s.authorizer, &it, scheme, &secret, 500).unwrap();
        assert_eq!(rec.nonce, 0);
        assert_eq!(rec.amount, 100);
        assert_eq!(rec.asset, ASSET, "{scheme:?}");
        assert_eq!(s.authorizer.expected_nonce(key_id), 1, "{scheme:?}");
        assert_eq!(s.authorizer.ledger().len(), 1, "{scheme:?}");
    }
}

fn assert_tamper_rejected(scheme: Scheme, mutate: impl FnOnce(&mut WithdrawalIntent)) {
    let mut s = setup();
    let (key_id, secret) = s.key(scheme);
    let it = intent(scheme, key_id, 0, 1000);
    let sig = scheme.sign(&secret, &it.encode()).unwrap();
    let mut tampered = it.clone();
    mutate(&mut tampered);
    assert_eq!(
        s.authorizer
            .authorize(&tampered.encode(), &sig, 500)
            .unwrap_err(),
        AuthError::InvalidSignature,
        "{scheme:?}"
    );
}

#[test]
fn amount_changed_after_signing_is_rejected() {
    for (scheme, _) in EACH {
        assert_tamper_rejected(scheme, |it| it.amount = 101);
    }
}

#[test]
fn recipient_changed_after_signing_is_rejected() {
    for (scheme, _) in EACH {
        assert_tamper_rejected(scheme, |it| it.recipient = [0xff; 32]);
    }
}

#[test]
fn asset_changed_after_signing_is_rejected() {
    for (scheme, _) in EACH {
        assert_tamper_rejected(scheme, |it| it.asset = [0xee; 32]);
    }
}

#[test]
fn expiry_changed_after_signing_is_rejected() {
    for (scheme, _) in EACH {
        assert_tamper_rejected(scheme, |it| it.expiry_slot = 2000);
    }
}

#[test]
fn unregistered_key_is_rejected_even_with_valid_signature() {
    for (scheme, _) in EACH {
        let mut s = setup();
        let rogue = scheme.keygen().unwrap();
        let it = intent(scheme, 99, 0, 1000);
        let bytes = it.encode();
        let sig = scheme.sign(&rogue.secret, &bytes).unwrap();
        assert_eq!(
            s.authorizer.authorize(&bytes, &sig, 500).unwrap_err(),
            AuthError::UnregisteredKey(99),
            "{scheme:?}"
        );
    }
}

#[test]
fn wrong_network_signed_correctly_is_rejected_as_policy() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = WithdrawalIntent::new(
            scheme, key_id, [0x99; 32], PROGRAM, ASSET, RECIPIENT, 100, 0, 1000,
        );
        let sig = scheme.sign(&secret, &it.encode()).unwrap();
        assert_eq!(
            s.authorizer.authorize(&it.encode(), &sig, 500).unwrap_err(),
            AuthError::NetworkMismatch,
            "{scheme:?}"
        );
    }
}

#[test]
fn wrong_program_signed_correctly_is_rejected_as_policy() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = WithdrawalIntent::new(
            scheme, key_id, NETWORK, [0x88; 32], ASSET, RECIPIENT, 100, 0, 1000,
        );
        let sig = scheme.sign(&secret, &it.encode()).unwrap();
        assert_eq!(
            s.authorizer.authorize(&it.encode(), &sig, 500).unwrap_err(),
            AuthError::ProgramMismatch,
            "{scheme:?}"
        );
    }
}

#[test]
fn wrong_domain_signed_correctly_is_rejected_as_policy() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let mut it = intent(scheme, key_id, 0, 1000);
        it.domain = *b"EVIL-DOM";
        let sig = scheme.sign(&secret, &it.encode()).unwrap();
        assert_eq!(
            s.authorizer.authorize(&it.encode(), &sig, 500).unwrap_err(),
            AuthError::DomainMismatch,
            "{scheme:?}"
        );
    }
}

#[test]
fn replay_of_accepted_request_is_rejected() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = intent(scheme, key_id, 0, 1000);
        let bytes = it.encode();
        let sig = scheme.sign(&secret, &bytes).unwrap();
        s.authorizer.authorize(&bytes, &sig, 500).unwrap();
        assert_eq!(
            s.authorizer.authorize(&bytes, &sig, 500).unwrap_err(),
            AuthError::NonceMismatch {
                expected: 1,
                actual: 0
            },
            "{scheme:?}"
        );
    }
}

#[test]
fn nonce_other_than_expected_is_rejected() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = intent(scheme, key_id, 5, 1000);
        assert_eq!(
            submit(&mut s.authorizer, &it, scheme, &secret, 500).unwrap_err(),
            AuthError::NonceMismatch {
                expected: 0,
                actual: 5
            },
            "{scheme:?}"
        );
    }
}

#[test]
fn expiry_boundary_matches_documented_policy() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        // current_slot == expiry_slot is accepted.
        let it = intent(scheme, key_id, 0, 1000);
        submit(&mut s.authorizer, &it, scheme, &secret, 1000).unwrap();
        // current_slot == expiry_slot + 1 is rejected.
        let it2 = intent(scheme, key_id, 1, 1000);
        assert_eq!(
            submit(&mut s.authorizer, &it2, scheme, &secret, 1001).unwrap_err(),
            AuthError::Expired {
                expiry_slot: 1000,
                current_slot: 1001
            },
            "{scheme:?}"
        );
    }
}

#[test]
fn malformed_intent_errors_without_panic() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = intent(scheme, key_id, 0, 1000);
        let mut bytes = it.encode().to_vec();
        bytes.pop();
        let sig = scheme.sign(&secret, &bytes).unwrap();
        assert!(matches!(
            s.authorizer.authorize(&bytes, &sig, 500),
            Err(AuthError::MalformedIntent(_))
        ));
    }
}

#[test]
fn truncated_signature_errors_without_panic() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = intent(scheme, key_id, 0, 1000);
        let bytes = it.encode();
        let mut sig = scheme.sign(&secret, &bytes).unwrap();
        sig.pop();
        assert!(matches!(
            s.authorizer.authorize(&bytes, &sig, 500),
            Err(AuthError::MalformedSignature(_))
        ));
    }
}

#[test]
fn rejected_request_preserves_nonce_and_ledger() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let it = intent(scheme, key_id, 0, 1000);
        let err = submit(&mut s.authorizer, &it, scheme, &secret, 1001).unwrap_err();
        assert_eq!(
            err,
            AuthError::Expired {
                expiry_slot: 1000,
                current_slot: 1001
            }
        );
        assert_eq!(s.authorizer.expected_nonce(key_id), 0, "{scheme:?}");
        assert!(s.authorizer.ledger().is_empty(), "{scheme:?}");

        submit(&mut s.authorizer, &it, scheme, &secret, 500).unwrap();
        assert_eq!(s.authorizer.expected_nonce(key_id), 1, "{scheme:?}");
    }
}

#[test]
fn scheme_mismatch_is_rejected() {
    let mut s = setup();
    // Key 1 is registered for Ed25519; request it as ML-DSA-44.
    let it = intent(Scheme::MlDsa44, 1, 0, 1000);
    let bytes = it.encode();
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &bytes).unwrap();
    assert!(matches!(
        s.authorizer.authorize(&bytes, &sig, 500),
        Err(AuthError::SchemeMismatch { .. })
    ));
}

#[test]
fn zero_amount_is_rejected() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        let mut it = intent(scheme, key_id, 0, 1000);
        it.amount = 0;
        assert_eq!(
            submit(&mut s.authorizer, &it, scheme, &secret, 500).unwrap_err(),
            AuthError::ZeroAmount,
            "{scheme:?}"
        );
    }
}

#[test]
fn consecutive_successful_nonces() {
    for (scheme, key_id) in EACH {
        let mut s = setup();
        let (_, secret) = s.key(scheme);
        for nonce in 0..3u64 {
            let it = intent(scheme, key_id, nonce, 1000);
            let rec = submit(&mut s.authorizer, &it, scheme, &secret, 500).unwrap();
            assert_eq!(rec.nonce, nonce, "{scheme:?}");
        }
        assert_eq!(s.authorizer.expected_nonce(key_id), 3, "{scheme:?}");
        assert_eq!(s.authorizer.ledger().len(), 3, "{scheme:?}");
    }
}

#[test]
fn nonce_state_is_independent_per_key() {
    let mut s = setup();
    let it_ed = intent(Scheme::Ed25519, 1, 0, 1000);
    submit(&mut s.authorizer, &it_ed, Scheme::Ed25519, &s.ed.1, 500).unwrap();

    let it_ml = intent(Scheme::MlDsa44, 2, 0, 1000);
    submit(&mut s.authorizer, &it_ml, Scheme::MlDsa44, &s.ml.1, 500).unwrap();

    assert_eq!(s.authorizer.expected_nonce(1), 1);
    assert_eq!(s.authorizer.expected_nonce(2), 1);
}

#[test]
fn recorded_asset_matches_signed_asset_and_assets_are_distinguishable() {
    let mut s = setup();
    let asset_a = intent(Scheme::Ed25519, 1, 0, 1000);
    let rec_a = submit(&mut s.authorizer, &asset_a, Scheme::Ed25519, &s.ed.1, 500).unwrap();
    assert_eq!(rec_a.asset, ASSET);

    let mut it_b = intent(Scheme::Ed25519, 1, 1, 1000);
    it_b.asset = [0x99; 32];
    let rec_b = submit(&mut s.authorizer, &it_b, Scheme::Ed25519, &s.ed.1, 500).unwrap();
    assert_eq!(rec_b.asset, [0x99; 32]);
    assert_ne!(rec_a.asset, rec_b.asset);
}

#[test]
fn duplicate_registration_is_rejected() {
    let mut registry = KeyRegistry::default();
    let kp = Scheme::Ed25519.keygen().unwrap();
    let key = RegisteredKey {
        key_id: 7,
        scheme: Scheme::Ed25519,
        public_key: kp.public.clone(),
    };
    registry.register(key.clone()).unwrap();
    assert_eq!(
        registry.register(key).unwrap_err(),
        AuthError::DuplicateRegistration(7)
    );
}

#[test]
fn weak_ed25519_key_registration_is_rejected() {
    let mut registry = KeyRegistry::default();
    let mut weak_pk = vec![0u8; 32];
    weak_pk[0] = 1;
    assert_eq!(
        registry
            .register(RegisteredKey {
                key_id: 7,
                scheme: Scheme::Ed25519,
                public_key: weak_pk,
            })
            .unwrap_err(),
        AuthError::WeakKey(7)
    );
}

#[test]
fn malformed_ed25519_key_registration_is_rejected() {
    let mut registry = KeyRegistry::default();
    for bad in [vec![0x02u8; 32], vec![0x02u8; 31]] {
        assert_eq!(
            registry
                .register(RegisteredKey {
                    key_id: 7,
                    scheme: Scheme::Ed25519,
                    public_key: bad,
                })
                .unwrap_err(),
            AuthError::MalformedRegistration(7)
        );
    }
}

#[test]
fn wrong_encoding_version_is_rejected_at_decode() {
    let mut s = setup();
    let it = intent(Scheme::Ed25519, 1, 0, 1000);
    let mut bytes = it.encode();
    bytes[8] = 2; // unsupported encoding version
    let sig = Scheme::Ed25519.sign(&s.ed.1, &bytes).unwrap();
    assert_eq!(
        s.authorizer.authorize(&bytes, &sig, 500).unwrap_err(),
        AuthError::MalformedIntent(IntentError::UnsupportedVersion(2))
    );
    assert_eq!(s.authorizer.expected_nonce(1), 0);
    assert!(s.authorizer.ledger().is_empty());
}
