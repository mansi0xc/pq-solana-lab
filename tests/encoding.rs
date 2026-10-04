//! Golden fixture and decoder-rejection tests for the canonical intent.

use pq_solana_lab::crypto::Scheme;
use pq_solana_lab::intent::{IntentError, WithdrawalIntent, ENCODING_VERSION, INTENT_LEN};

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture() -> WithdrawalIntent {
    WithdrawalIntent::new(
        Scheme::MlDsa44,
        7,
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        1_000_000,
        0,
        500,
    )
}

#[test]
fn golden_fixture() {
    const GOLDEN: &str = concat!(
        "5051534f4c2d5744010200000007",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "00000000000f4240000000000000000000000000000001f4",
    );
    assert_eq!(GOLDEN.len(), INTENT_LEN * 2, "golden hex length");
    assert_eq!(fixture().encode().to_vec(), hex(GOLDEN));
}

#[test]
fn encode_decode_roundtrip() {
    let intent = WithdrawalIntent::new(
        Scheme::Ed25519,
        12,
        [0xaa; 32],
        [0xbb; 32],
        [0xcc; 32],
        [0xdd; 32],
        42,
        9,
        u64::MAX,
    );
    let bytes = intent.encode();
    assert_eq!(WithdrawalIntent::decode(&bytes).unwrap(), intent);
}

#[test]
fn decoder_rejects_wrong_length() {
    let bytes = fixture().encode();
    for len in [0usize, 1, INTENT_LEN - 1] {
        assert_eq!(
            WithdrawalIntent::decode(&bytes[..len]),
            Err(IntentError::InvalidLength {
                expected: INTENT_LEN,
                actual: len
            })
        );
    }
    let mut padded = bytes.to_vec();
    padded.push(0);
    assert_eq!(
        WithdrawalIntent::decode(&padded),
        Err(IntentError::InvalidLength {
            expected: INTENT_LEN,
            actual: INTENT_LEN + 1
        })
    );
}

#[test]
fn decoder_rejects_unsupported_version() {
    let mut bytes = fixture().encode();
    bytes[8] = 2;
    assert_eq!(
        WithdrawalIntent::decode(&bytes),
        Err(IntentError::UnsupportedVersion(2))
    );
}

#[test]
fn decoder_rejects_unknown_scheme() {
    let mut bytes = fixture().encode();
    bytes[9] = 200;
    assert_eq!(
        WithdrawalIntent::decode(&bytes),
        Err(IntentError::UnknownScheme(200))
    );
}

#[test]
fn decoder_does_not_check_environment_fields() {
    // A wrong domain/network/program must still decode (and be rejected later
    // as policy, not as a parse error).
    let mut bytes = fixture().encode();
    bytes[0] = b'X';
    let decoded = WithdrawalIntent::decode(&bytes).unwrap();
    assert_ne!(decoded.domain, *b"PQSOL-WD");
    assert_eq!(decoded.version, ENCODING_VERSION);
}
