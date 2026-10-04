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
}
