//! Ed25519 known-answer tests from RFC 8032 section 7.1.
//!
//! Provenance: vectors transcribed verbatim from RFC 8032 ("Edwards-Curve
//! Digital Signature Algorithm (EdDSA)", January 2017), section 7.1, which
//! states the Ed25519 vectors are taken from [ED25519-TEST-VECTORS] (Bernstein
//! et al., ed25519.cr.yp.to/python/sign.input) and
//! [ED25519-LIBGCRYPT-TEST-VECTORS]. These are pure Ed25519 (empty context, no
//! prehash), matching the adapter's deterministic signing mode.
//!
//! This is independent evidence for the *external* Ed25519 API: the expected
//! signature is fixed (Ed25519 signing is deterministic), so we can assert
//! key derivation, exact signature bytes, and verification against a primary
//! source rather than only a self round-trip.

use pq_solana_lab::crypto::ed25519;
use pq_solana_lab::crypto::Scheme;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct Vector {
    secret: &'static str,
    public: &'static str,
    message: &'static [u8],
    signature: &'static str,
}

// RFC 8032 §7.1 TEST 1 (empty message).
const TEST1: Vector = Vector {
    secret: "9d61b19deffd5a60ba844af492ec2cc4 4449c5697b326919703bac031cae7f60",
    public: "d75a980182b10ab7d54bfed3c964073a 0ee172f3daa62325af021a68f707511a",
    message: b"",
    signature: "e5564300c360ac729086e2cc806e828a 84877f1eb8e5d974d873e06522490155 \
                5fb8821590a33bacc61e39701cf9b46b d25bf5f0595bbe24655141438e7a100b",
};

// RFC 8032 §7.1 TEST 2 (one-byte message 0x72).
const TEST2: Vector = Vector {
    secret: "4ccd089b28ff96da9db6c346ec114e0f 5b8a319f35aba624da8cf6ed4fb8a6fb",
    public: "3d4017c3e843895a92b70aa74d1b7ebc 9c982ccf2ec4968cc0cd55f12af4660c",
    message: &[0x72],
    signature: "92a009a9f0d4cab8720e820b5f642540 a2b27b5416503f8fb3762223ebdb69da \
                085ac1e43e15996e458f3613d0f11d8c 387b2eaeb4302aeeb00d291612bb0c00",
};

#[test]
fn rfc8032_test_vectors_match_key_derivation_signing_and_verification() {
    for v in [&TEST1, &TEST2] {
        let secret = hex(v.secret);
        let public = hex(v.public);
        let sig = hex(v.signature);

        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 32);
        assert_eq!(sig.len(), 64);

        // Key expansion: secret seed derives the published public key.
        let derived_pk = ed25519::prepare_signer(&secret)
            .unwrap()
            .verifying_key_bytes();
        assert_eq!(derived_pk, public, "public key derivation");

        // Deterministic signing reproduces the published signature bytes.
        let produced = Scheme::Ed25519.sign(&secret, v.message).unwrap();
        assert_eq!(produced, sig, "signature bytes");

        // Verification (both ordinary and strict) accepts the signature.
        assert!(Scheme::Ed25519.verify(&public, v.message, &sig).unwrap());
        assert!(Scheme::Ed25519
            .verify_strict(&public, v.message, &sig)
            .unwrap());
    }
}
