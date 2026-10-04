//! Application-policy and integrity tests for the local authorization module.
//! Distinguishes signature-integrity rejections from application-policy
//! rejections. Behavioral evidence only; not a security proof.

use pq_solana_lab::authorization::{
    AuthError, Authorizer, Environment, KeyRegistry, RegisteredKey,
};
use pq_solana_lab::crypto::Scheme;
use pq_solana_lab::intent::WithdrawalIntent;

const NETWORK: [u8; 32] = [0xab; 32];
const PROGRAM: [u8; 32] = [0xcd; 32];
const ASSET: [u8; 32] = [0x01; 32];
const RECIPIENT: [u8; 32] = [0x02; 32];

struct Setup {
    authorizer: Authorizer,
    // (key_id, secret_key) for the two registered keys.
    ed: (u32, Vec<u8>),
    ml: (u32, Vec<u8>),
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
    for (scheme, key_id) in [(Scheme::Ed25519, 1), (Scheme::MlDsa44, 2)] {
        let mut s = setup();
        let secret = if scheme == Scheme::Ed25519 {
            s.ed.1.clone()
        } else {
            s.ml.1.clone()
        };
        let it = intent(scheme, key_id, 0, 1000);
        let rec = submit(&mut s.authorizer, &it, scheme, &secret, 500).unwrap();
        assert_eq!(rec.nonce, 0);
        assert_eq!(rec.amount, 100);
        assert_eq!(s.authorizer.expected_nonce(key_id), 1, "{scheme:?}");
        assert_eq!(s.authorizer.ledger().len(), 1, "{scheme:?}");
    }
}

#[test]
fn amount_changed_after_signing_is_rejected() {
    let mut s = setup();
    let it = intent(Scheme::MlDsa44, 2, 0, 1000);
    let bytes = it.encode();
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &bytes).unwrap();

    let mut tampered = intent(Scheme::MlDsa44, 2, 0, 1000);
    tampered.amount = 101;
    let err = s
        .authorizer
        .authorize(&tampered.encode(), &sig, 500)
        .unwrap_err();
    assert_eq!(err, AuthError::InvalidSignature);
}

#[test]
fn recipient_changed_after_signing_is_rejected() {
    let mut s = setup();
    let it = intent(Scheme::MlDsa44, 2, 0, 1000);
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &it.encode()).unwrap();
    let mut tampered = it.clone();
    tampered.recipient = [0xff; 32];
    assert_eq!(
        s.authorizer
            .authorize(&tampered.encode(), &sig, 500)
            .unwrap_err(),
        AuthError::InvalidSignature
    );
}

#[test]
fn asset_changed_after_signing_is_rejected() {
    let mut s = setup();
    let it = intent(Scheme::MlDsa44, 2, 0, 1000);
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &it.encode()).unwrap();
    let mut tampered = it.clone();
    tampered.asset = [0xee; 32];
    assert_eq!(
        s.authorizer
            .authorize(&tampered.encode(), &sig, 500)
            .unwrap_err(),
        AuthError::InvalidSignature
    );
}

#[test]
fn expiry_changed_after_signing_is_rejected() {
    let mut s = setup();
    let it = intent(Scheme::MlDsa44, 2, 0, 1000);
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &it.encode()).unwrap();
    let mut tampered = it.clone();
    tampered.expiry_slot = 2000;
    assert_eq!(
        s.authorizer
            .authorize(&tampered.encode(), &sig, 500)
            .unwrap_err(),
        AuthError::InvalidSignature
    );
}

#[test]
fn unregistered_key_is_rejected_even_with_valid_signature() {
    let mut s = setup();
    let rogue = Scheme::MlDsa44.keygen().unwrap();
    let it = intent(Scheme::MlDsa44, 99, 0, 1000);
    let bytes = it.encode();
    let sig = Scheme::MlDsa44.sign(&rogue.secret, &bytes).unwrap();
    assert_eq!(
        s.authorizer.authorize(&bytes, &sig, 500).unwrap_err(),
        AuthError::UnregisteredKey(99)
    );
}

#[test]
fn wrong_network_signed_correctly_is_rejected_as_policy() {
    let mut s = setup();
    let it = WithdrawalIntent::new(
        Scheme::MlDsa44,
        2,
        [0x99; 32],
        PROGRAM,
        ASSET,
        RECIPIENT,
        100,
        0,
        1000,
    );
    // Sign the wrong-network bytes with the *registered* key: signature is
    // valid, so this is a policy rejection, not an integrity rejection.
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &it.encode()).unwrap();
    assert_eq!(
        s.authorizer.authorize(&it.encode(), &sig, 500).unwrap_err(),
        AuthError::NetworkMismatch
    );
}

#[test]
fn wrong_program_signed_correctly_is_rejected_as_policy() {
    let mut s = setup();
    let it = WithdrawalIntent::new(
        Scheme::MlDsa44,
        2,
        NETWORK,
        [0x88; 32],
        ASSET,
        RECIPIENT,
        100,
        0,
        1000,
    );
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &it.encode()).unwrap();
    assert_eq!(
        s.authorizer.authorize(&it.encode(), &sig, 500).unwrap_err(),
        AuthError::ProgramMismatch
    );
}

#[test]
fn wrong_domain_signed_correctly_is_rejected_as_policy() {
    let mut s = setup();
    let mut it = intent(Scheme::MlDsa44, 2, 0, 1000);
    it.domain = *b"EVIL-DOM";
    let sig = Scheme::MlDsa44.sign(&s.ml.1, &it.encode()).unwrap();
    assert_eq!(
        s.authorizer.authorize(&it.encode(), &sig, 500).unwrap_err(),
        AuthError::DomainMismatch
    );
}

#[test]
fn replay_of_accepted_request_is_rejected() {
    let mut s = setup();
    let it = intent(Scheme::Ed25519, 1, 0, 1000);
    let bytes = it.encode();
    let sig = Scheme::Ed25519.sign(&s.ed.1, &bytes).unwrap();
    s.authorizer.authorize(&bytes, &sig, 500).unwrap();
    // Same signed bytes submitted again.
    assert_eq!(
        s.authorizer.authorize(&bytes, &sig, 500).unwrap_err(),
        AuthError::NonceMismatch {
            expected: 1,
            actual: 0
        }
    );
}

#[test]
fn nonce_other_than_expected_is_rejected() {
    let mut s = setup();
    let it = intent(Scheme::Ed25519, 1, 5, 1000);
    let err = submit(&mut s.authorizer, &it, Scheme::Ed25519, &s.ed.1, 500).unwrap_err();
    assert_eq!(
        err,
        AuthError::NonceMismatch {
            expected: 0,
            actual: 5
        }
    );
}

#[test]
fn expiry_boundary_matches_documented_policy() {
    // Accept while current_slot <= expiry_slot.
    let mut s = setup();
    let it = intent(Scheme::Ed25519, 1, 0, 1000);
    submit(&mut s.authorizer, &it, Scheme::Ed25519, &s.ed.1, 1000).unwrap();

    // current_slot == expiry_slot + 1 must be rejected.
    let it2 = intent(Scheme::Ed25519, 1, 1, 1000);
    let err = submit(&mut s.authorizer, &it2, Scheme::Ed25519, &s.ed.1, 1001).unwrap_err();
    assert_eq!(
        err,
        AuthError::Expired {
            expiry_slot: 1000,
            current_slot: 1001
        }
    );
}

#[test]
fn malformed_intent_errors_without_panic() {
    let mut s = setup();
    let it = intent(Scheme::Ed25519, 1, 0, 1000);
    let mut bytes = it.encode().to_vec();
    bytes.pop();
    let sig = Scheme::Ed25519.sign(&s.ed.1, &bytes).unwrap();
    assert!(matches!(
        s.authorizer.authorize(&bytes, &sig, 500),
        Err(AuthError::MalformedIntent(_))
    ));
}

#[test]
fn truncated_signature_errors_without_panic() {
    let mut s = setup();
    let it = intent(Scheme::MlDsa44, 2, 0, 1000);
    let bytes = it.encode();
    let mut sig = Scheme::MlDsa44.sign(&s.ml.1, &bytes).unwrap();
    sig.pop();
    assert!(matches!(
        s.authorizer.authorize(&bytes, &sig, 500),
        Err(AuthError::MalformedSignature(_))
    ));
}

#[test]
fn rejected_request_leaves_nonce_unchanged() {
    let mut s = setup();
    // An expired request at nonce 0.
    let it = intent(Scheme::Ed25519, 1, 0, 1000);
    let err = submit(&mut s.authorizer, &it, Scheme::Ed25519, &s.ed.1, 1001).unwrap_err();
    assert_eq!(
        err,
        AuthError::Expired {
            expiry_slot: 1000,
            current_slot: 1001
        }
    );
    assert_eq!(s.authorizer.expected_nonce(1), 0);
    assert!(s.authorizer.ledger().is_empty());

    // A valid request still works afterwards.
    submit(&mut s.authorizer, &it, Scheme::Ed25519, &s.ed.1, 500).unwrap();
    assert_eq!(s.authorizer.expected_nonce(1), 1);
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
    let mut s = setup();
    let mut it = intent(Scheme::Ed25519, 1, 0, 1000);
    it.amount = 0;
    let err = submit(&mut s.authorizer, &it, Scheme::Ed25519, &s.ed.1, 500).unwrap_err();
    assert_eq!(err, AuthError::ZeroAmount);
}
