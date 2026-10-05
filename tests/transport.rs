//! Transport analysis tests: direct rows are actually-serialized transactions;
//! staged rows are a modeled multi-transaction lifecycle with chunk sizes
//! derived from serialized templates.

use pq_solana_lab::transport::{analyze, staged, StagedRow, TransportRow};

fn rows() -> Vec<TransportRow> {
    analyze()
}

fn staged_rows() -> Vec<StagedRow> {
    staged()
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

fn find_staged<'a>(rows: &'a [StagedRow], scheme: &str, format: &str) -> &'a StagedRow {
    rows.iter()
        .find(|r| r.scheme == scheme && r.format == format)
        .unwrap_or_else(|| panic!("missing staged row {scheme} {format}"))
}

#[test]
fn produces_all_schemes_formats_placements() {
    let rows = rows();
    assert_eq!(rows.len(), 24, "4 schemes x 2 placements x 3 formats");
    for r in &rows {
        assert_eq!(r.evidence_type, "serialized");
        assert!(r.total_bytes > 0);
        assert_eq!(r.native_signature_bytes, 64);
        assert!((r.format == "v1") == (r.applicable_limit == 4096), "{r:?}");
    }
}

#[test]
fn ed25519_direct_fits_in_legacy_v0() {
    let rows = rows();
    for format in ["legacy", "v0"] {
        let r = find(&rows, "ed25519", format, "inline");
        assert!(r.total_bytes <= 1232, "ed25519 inline must fit: {r:?}");
    }
}

#[test]
fn ml_dsa_44_exceeds_limit_even_when_registered() {
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
fn v1_lifts_ml_dsa_44_but_not_larger_schemes() {
    let rows = rows();
    // ML-DSA-44 inline fits in v1.
    let m44 = find(&rows, "ml-dsa-44", "v1", "inline");
    assert!(m44.total_bytes <= 4096 && m44.headroom > 0, "{m44:?}");

    // ML-DSA-65 inline and SLH-DSA registered still exceed v1.
    let m65 = find(&rows, "ml-dsa-65", "v1", "inline");
    assert!(m65.total_bytes > 4096, "{m65:?}");
    let slh = find(&rows, "slh-dsa-sha2-128s", "v1", "registered");
    assert!(slh.total_bytes > 4096, "{slh:?}");
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
            "{scheme}"
        );
    }
}

#[test]
fn v0_is_legacy_plus_version_and_lookup_overhead() {
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

#[test]
fn staged_chunking_is_consistent_and_labeled_modeled() {
    let rows = staged_rows();
    assert_eq!(rows.len(), 12, "4 schemes x 3 formats");
    for r in &rows {
        assert_eq!(r.evidence_type, "modeled");
        assert_eq!(r.storage_bytes, r.signature_bytes);
        assert!(r.chunk_bytes < r.applicable_limit, "{r:?}");
        let expected_chunks = r.signature_bytes.div_ceil(r.chunk_bytes);
        assert_eq!(r.chunk_count, expected_chunks, "{r:?}");
        assert_eq!(r.total_transactions, 2 + r.chunk_count, "{r:?}");
    }
}

#[test]
fn v1_staging_needs_fewer_chunks_than_legacy() {
    let rows = staged_rows();
    for scheme in ["ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"] {
        let legacy = find_staged(&rows, scheme, "legacy");
        let v1 = find_staged(&rows, scheme, "v1");
        assert!(v1.chunk_count < legacy.chunk_count, "{scheme}");
    }
}
