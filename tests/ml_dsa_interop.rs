//! Independent ML-DSA-44 interoperability cross-check.
//!
//! `fips204` (the library behind `src/crypto/ml_dsa_44.rs`) and the RustCrypto
//! `ml-dsa` crate are two independent implementations of FIPS 204 (final).
//! Both are used in pure mode with an empty context string. This test checks
//! that a signature produced by one verifies under the other, in both
//! directions, so it is independent conformance evidence and not a self
//! round-trip.
//!
//! Provenance: `ml-dsa` 0.1.1 (RustCrypto/signatures), "Pure Rust
//! implementation of ML-DSA ... as described in FIPS-204 (final)"; added as a
//! dev-dependency for this test only.

use ml_dsa::{
    KeyExport, Keypair, MlDsa44, Seed, Signature, SignatureEncoding, Signer, Verifier, VerifyingKey,
};
use pq_solana_lab::crypto::Scheme;

const PK_LEN: usize = 1312;
const SIG_LEN: usize = 2420;

#[test]
fn fips204_signs_and_ml_dsa_verifies() {
    let kp = Scheme::MlDsa44.keygen().unwrap();
    let msg = b"interop fips204 -> ml-dsa";
    let sig = Scheme::MlDsa44.sign(&kp.secret, msg).unwrap();
    assert_eq!(sig.len(), SIG_LEN);

    let pk: [u8; PK_LEN] = kp.public.as_slice().try_into().unwrap();
    let vk = VerifyingKey::<MlDsa44>::decode(&pk.into());
    let sig_arr: [u8; SIG_LEN] = sig.as_slice().try_into().unwrap();
    let sig_obj = Signature::<MlDsa44>::decode(&sig_arr.into()).expect("decode signature");
    assert!(vk.verify(msg, &sig_obj).is_ok());
}

#[test]
fn ml_dsa_signs_and_fips204_verifies() {
    // Fixed seed for a deterministic, reproducible key.
    let seed: Seed = [0x42u8; 32].into();
    let signer = ml_dsa::SigningKey::<MlDsa44>::from_seed(&seed);
    let msg = b"interop ml-dsa -> fips204";
    let sig = signer.try_sign(msg).expect("ml-dsa sign");

    let pk = signer.verifying_key().to_bytes();
    let sig_bytes: [u8; SIG_LEN] = sig.to_bytes().as_slice().try_into().unwrap();
    assert!(Scheme::MlDsa44.verify(&pk, msg, &sig_bytes).unwrap());
}

#[test]
fn cross_implementation_rejects_tampered_message() {
    let kp = Scheme::MlDsa44.keygen().unwrap();
    let msg = b"interop tamper";
    let sig = Scheme::MlDsa44.sign(&kp.secret, msg).unwrap();

    let pk: [u8; PK_LEN] = kp.public.as_slice().try_into().unwrap();
    let vk = VerifyingKey::<MlDsa44>::decode(&pk.into());
    let sig_arr: [u8; SIG_LEN] = sig.as_slice().try_into().unwrap();
    let sig_obj = Signature::<MlDsa44>::decode(&sig_arr.into()).expect("decode signature");

    let mut tampered = msg.to_vec();
    tampered[0] ^= 0x01;
    assert!(vk.verify(&tampered, &sig_obj).is_err());
}
