//! Correctness tests for the signature adapters: round-trip through canonical
//! bytes, and rejection of altered messages, wrong keys, and malformed input.
//! These are behavioral tests of the adapters, not a proof of the schemes.

use pq_solana_lab::crypto::{CryptoError, Scheme};

#[test]
fn sign_serialize_verify_roundtrip() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        assert_eq!(kp.public.len(), scheme.public_key_len(), "{scheme:?}");
        assert_eq!(kp.secret.len(), scheme.secret_key_len(), "{scheme:?}");

        let msg = b"canonical bytes round trip";
        let sig = scheme.sign(&kp.secret, msg).unwrap();
        assert_eq!(sig.len(), scheme.signature_len(), "{scheme:?}");

        // Verification uses only the serialized bytes, as a remote party would.
        let ok = scheme.verify(&kp.public, msg, &sig).unwrap();
        assert!(
            ok,
            "{scheme:?}: valid signature must verify after serialization"
        );
    }
}

#[test]
fn repeated_signing_verifies_after_serialization() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        for i in 0..8u8 {
            let msg = [b"repeat-".as_slice(), &[i]].concat();
            let sig = scheme.sign(&kp.secret, &msg).unwrap();
            assert!(
                scheme.verify(&kp.public, &msg, &sig).unwrap(),
                "{scheme:?} iteration {i}"
            );
        }
    }
}

#[test]
fn altered_message_is_rejected() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        let msg = b"withdraw 100";
        let sig = scheme.sign(&kp.secret, msg).unwrap();

        let mut altered = msg.to_vec();
        *altered.last_mut().unwrap() ^= 0x01;
        let ok = scheme.verify(&kp.public, &altered, &sig).unwrap();
        assert!(!ok, "{scheme:?}: altered message must not verify");
    }
}

#[test]
fn wrong_public_key_is_rejected() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        let other = scheme.keygen().unwrap();
        let msg = b"withdraw 100";
        let sig = scheme.sign(&kp.secret, msg).unwrap();

        let ok = scheme.verify(&other.public, msg, &sig).unwrap();
        assert!(
            !ok,
            "{scheme:?}: signature must not verify under an unrelated key"
        );
    }
}

#[test]
fn corrupted_signature_is_rejected_not_accepted() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        let msg = b"withdraw 100";
        let mut sig = scheme.sign(&kp.secret, msg).unwrap();
        // Flip one bit in a correctly sized signature: a cryptographic
        // rejection (Ok(false)) or a decode error are both acceptable, but
        // acceptance is not.
        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;
        assert!(
            !matches!(scheme.verify(&kp.public, msg, &sig), Ok(true)),
            "{scheme:?}: corrupted signature must not verify"
        );
    }
}

#[test]
fn truncated_signature_errors_without_panic() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        let msg = b"withdraw 100";
        let sig = scheme.sign(&kp.secret, msg).unwrap();
        let truncated = &sig[..sig.len() - 1];

        match scheme.verify(&kp.public, msg, truncated) {
            Err(CryptoError::InvalidLength { .. }) => {}
            other => panic!("{scheme:?}: truncated signature must be InvalidLength, got {other:?}"),
        }
    }
}

#[test]
fn wrong_length_inputs_error_without_panic() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        let msg = b"m";
        let sig = scheme.sign(&kp.secret, msg).unwrap();

        // Short public key.
        let short_pk = &kp.public[..kp.public.len() - 1];
        assert!(matches!(
            scheme.verify(short_pk, msg, &sig),
            Err(CryptoError::InvalidLength { .. })
        ));

        // Empty signature and empty public key.
        assert!(matches!(
            scheme.verify(&kp.public, msg, &[]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            scheme.verify(&[], msg, &sig),
            Err(CryptoError::InvalidLength { .. })
        ));

        // Signing with a wrong-length secret key.
        assert!(matches!(
            scheme.sign(&[0u8; 3], msg),
            Err(CryptoError::InvalidLength { .. })
        ));
    }
}

#[test]
fn empty_message_roundtrips() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        let sig = scheme.sign(&kp.secret, b"").unwrap();
        assert!(scheme.verify(&kp.public, b"", &sig).unwrap());
    }
}

#[test]
fn scheme_ids_are_stable() {
    assert_eq!(Scheme::Ed25519.id(), 1);
    assert_eq!(Scheme::MlDsa44.id(), 2);
    assert_eq!(Scheme::from_id(1).unwrap(), Scheme::Ed25519);
    assert_eq!(Scheme::from_id(2).unwrap(), Scheme::MlDsa44);
    assert!(matches!(
        Scheme::from_id(0),
        Err(CryptoError::UnknownScheme(0))
    ));
    assert!(matches!(
        Scheme::from_id(255),
        Err(CryptoError::UnknownScheme(255))
    ));
}

#[test]
fn published_sizes_match_the_standards() {
    // RFC 8032 / FIPS 204 parameter sizes; guards against a misconfigured
    // parameter set being benchmarked under a wrong label.
    assert_eq!(Scheme::Ed25519.public_key_len(), 32);
    assert_eq!(Scheme::Ed25519.signature_len(), 64);
    assert_eq!(Scheme::MlDsa44.public_key_len(), 1312);
    assert_eq!(Scheme::MlDsa44.secret_key_len(), 2560);
    assert_eq!(Scheme::MlDsa44.signature_len(), 2420);
    assert_eq!(Scheme::MlDsa65.public_key_len(), 1952);
    assert_eq!(Scheme::MlDsa65.secret_key_len(), 4032);
    assert_eq!(Scheme::MlDsa65.signature_len(), 3309);
    assert_eq!(Scheme::SlhDsaSha2128s.public_key_len(), 32);
    assert_eq!(Scheme::SlhDsaSha2128s.secret_key_len(), 64);
    assert_eq!(Scheme::SlhDsaSha2128s.signature_len(), 7856);
}

#[test]
fn ed25519_validate_public_key_rejects_weak_and_malformed_keys() {
    // Identity point (y = 1): decompresses fine but is low-order (weak).
    let identity = {
        let mut v = vec![0u8; 32];
        v[0] = 1;
        v
    };
    assert_eq!(
        Scheme::Ed25519.validate_public_key(&identity),
        Err(CryptoError::WeakKey)
    );

    // 0x02.. is a non-decompressible encoding (y = 2 has no square root).
    assert_eq!(
        Scheme::Ed25519.validate_public_key(&[0x02u8; 32]),
        Err(CryptoError::MalformedEncoding("ed25519 public key"))
    );

    // Note: ed25519-dalek's `from_bytes` validates under ZIP-215, which
    // accepts some non-canonical y encodings (e.g. 0xff..) as aliases of real
    // curve points; those are not rejected here and are not weak. `is_weak`
    // is the check that catches low-order points.

    // A freshly generated key must validate.
    let kp = Scheme::Ed25519.keygen().unwrap();
    Scheme::Ed25519.validate_public_key(&kp.public).unwrap();
}

#[test]
fn ed25519_strict_verification_rejects_identity_forgery_that_plain_verify_accepts() {
    // Reviewer's secretless-authorization fixture: identity public key,
    // R = identity point, S = 0.
    let mut weak_pk = vec![0u8; 32];
    weak_pk[0] = 1;
    let mut sig = vec![0u8; 64];
    sig[0] = 1;
    let msg = b"forgery fixture";

    // Plain (RFC 8032) verification accepts the low-order forgery.
    assert_eq!(Scheme::Ed25519.verify(&weak_pk, msg, &sig), Ok(true));

    // Strict verification rejects it.
    assert_eq!(
        Scheme::Ed25519.verify_strict(&weak_pk, msg, &sig),
        Ok(false)
    );
}

#[test]
fn prepared_keys_match_the_byte_path() {
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().unwrap();
        let msg = b"prepared vs byte path";

        let signer = scheme.prepare_signer(&kp.secret).unwrap();
        let verifier = scheme.prepare_verifier(&kp.public).unwrap();

        // ML-DSA signing is randomized, so two sign calls are not
        // byte-identical; assert functional equivalence instead.
        let sig = signer.sign(msg).unwrap();
        assert!(
            verifier.verify(msg, &sig).unwrap(),
            "{scheme:?} prepared verify"
        );
        assert!(
            verifier.verify_strict(msg, &sig).unwrap(),
            "{scheme:?} prepared strict"
        );
        assert!(
            scheme.verify(&kp.public, msg, &sig).unwrap(),
            "{scheme:?} byte-path verify"
        );
        assert!(
            scheme.verify_strict(&kp.public, msg, &sig).unwrap(),
            "{scheme:?} byte-path strict"
        );
    }
}
