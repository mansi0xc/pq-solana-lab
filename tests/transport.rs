//! Transport analysis tests: the reported sizes are actually-serialized
//! transactions, and the direct-vs-registered comparison is behavior, not a
//! hard-coded table.

use pq_solana_lab::transport::{analyze, TransportRow};

fn rows() -> Vec<TransportRow> {
    analyze()
}

fn find<'a>(
    rows: &'a [TransportRow],
    scheme: &str,
    format: &str,
    placement: &str,
) -> &'a TransportRow {
    rows.iter()
        .find(|r| r.scheme == scheme && r.format == format && r.key_placement == placement)
        .unwrap_or_else(|| panic!("missing row {scheme} {format} {placement}"))
}

#[test]
fn produces_all_schemes_formats_placements() {
    let rows = rows();
    assert_eq!(rows.len(), 16, "4 schemes x 2 formats x 2 placements");
    for r in &rows {
        assert_eq!(r.evidence_type, "serialized");
        assert_eq!(r.applicable_limit, 1232);
        assert!(r.total_bytes > 0);
        assert_eq!(r.native_signature_bytes, 64);
    }
}

#[test]
fn ed25519_direct_fits_in_legacy_v0() {
    let rows = rows();
    for format in ["legacy", "v0"] {
        let r = find(&rows, "ed25519", format, "inline");
        assert!(r.total_bytes <= 1232, "ed25519 inline must fit: {r:?}");
        assert!(r.headroom > 0);
    }
}

#[test]
fn ml_dsa_44_exceeds_limit_even_when_registered() {
    // The central finding: a 2,420-byte ML-DSA-44 signature plus the 166-byte
    // intent cannot fit in a legacy/v0 packet even with the key registered.
    let rows = rows();
    for format in ["legacy", "v0"] {
        let r = find(&rows, "ml-dsa-44", format, "registered");
        assert!(
            r.total_bytes > 1232,
            "ml-dsa-44 registered exceeds limit: {r:?}"
        );
    }
}

#[test]
fn registration_reduces_transport_by_the_public_key_size() {
    let rows = rows();
    for scheme in ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"] {
        let inline = find(&rows, scheme, "legacy", "inline");
        let registered = find(&rows, scheme, "legacy", "registered");
        assert_eq!(
            inline.total_bytes - registered.total_bytes,
            inline.public_key_bytes,
            "{scheme}: registration should remove exactly the inline public key"
        );
    }
}

#[test]
fn v0_is_legacy_plus_version_prefix() {
    // A v0 transaction with no address-table lookups is the legacy layout plus
    // the version prefix and an empty address-table-lookups field (a few bytes).
    let rows = rows();
    for scheme in ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"] {
        for placement in ["inline", "registered"] {
            let legacy = find(&rows, scheme, "legacy", placement);
            let v0 = find(&rows, scheme, "v0", placement);
            assert!(v0.total_bytes >= legacy.total_bytes, "{scheme} {placement}");
            assert!(
                v0.total_bytes - legacy.total_bytes <= 4,
                "{scheme} {placement}"
            );
        }
    }
}
