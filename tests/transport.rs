//! Transport analysis tests.
//!
//! Direct rows are actually-serialized transactions. Legacy/v0 use the classic
//! bincode wire format; v1 uses the SDK's `wincode` encoder, because
//! `solana-message` 5.1.0 states the v1 format does not support bincode
//! serialization. Staged rows are a model whose component transactions are
//! serialized with full instruction framing.

use pq_solana_lab::crypto::Scheme;
use pq_solana_lab::transport::{
    analyze, build_versioned, decode_wire, encode_init, encode_wire, encode_write, signed_intent,
    staged, StagedRow, Template, TransportRow, UploadIx, KEY_ID, LEGACY_V0_LIMIT,
    SESSION_METADATA_BYTES, UPLOADER, V1_COMPUTE_UNIT_LIMIT, V1_LIMIT,
    V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT, V1_VERSION_PREFIX, WRITE_FRAME_BYTES,
};
use solana_sdk::message::{v1, VersionedMessage};
use solana_sdk::pubkey::Pubkey;

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
    template: &str,
) -> &'a TransportRow {
    rows.iter()
        .find(|r| {
            r.scheme == scheme
                && r.format == format
                && r.key_placement == placement
                && r.template == template
        })
        .unwrap_or_else(|| panic!("missing row {scheme} {format} {placement} {template}"))
}

fn find_staged<'a>(rows: &'a [StagedRow], scheme: &str, format: &str) -> &'a StagedRow {
    rows.iter()
        .find(|r| r.scheme == scheme && r.format == format)
        .unwrap_or_else(|| panic!("missing staged row {scheme} {format}"))
}

fn wire_size(
    format: &str,
    data: &[u8],
    writable: &[Pubkey],
    readonly: &[Pubkey],
    config: v1::TransactionConfig,
) -> usize {
    encode_wire(
        format,
        &build_versioned(format, data, writable, readonly, config),
    )
    .len()
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

#[test]
fn v1_wire_roundtrips_with_prefix_and_native_signature() {
    let data = signed_intent(Scheme::MlDsa44);
    let tx = build_versioned(
        "v1",
        &data,
        &[Pubkey::from([9u8; 32])],
        &[Pubkey::from([4u8; 32])],
        Template::Operational.v1_config(),
    );
    let bytes = encode_wire("v1", &tx);

    assert_eq!(bytes[0], V1_VERSION_PREFIX);
    assert_eq!(bytes[0], 0x81, "v1 version prefix is 0x80 | 1");

    let decoded = decode_wire("v1", &bytes).expect("v1 wire decodes");
    assert_eq!(decoded.message, tx.message, "message survives the wire");
    assert_eq!(decoded.signatures, tx.signatures);
    assert_eq!(decoded, tx);
    assert!(
        decoded.verify_and_hash_message().is_ok(),
        "native fee-payer signature verifies"
    );
    assert!(matches!(decoded.message, VersionedMessage::V1(_)));
}

#[test]
fn bincode_v1_buffer_is_not_a_valid_wire_transaction() {
    let tx = build_versioned("v1", &[1, 2, 3, 4], &[], &[], Template::Minimal.v1_config());
    // bincode still "serializes" the serde representation, but it is not the
    // v1 wire format and the SDK's v1 decoder rejects it.
    let bincode_bytes = bincode::serialize(&tx).expect("serde serialize");
    assert!(
        decode_wire("v1", &bincode_bytes).is_err(),
        "a bincode v1 buffer must not decode as a wire transaction"
    );
}

#[test]
fn legacy_and_v0_wire_roundtrip_with_verifiable_signatures() {
    for format in ["legacy", "v0"] {
        let tx = build_versioned(format, &[7u8; 20], &[], &[], Template::Minimal.v1_config());
        let bytes = encode_wire(format, &tx);
        let decoded = decode_wire(format, &bytes).expect("decodes");
        assert_eq!(decoded, tx, "{format} round-trips");
        assert!(
            decoded.verify_and_hash_message().is_ok(),
            "{format} native signature verifies"
        );
        // One signature: a one-byte ShortU16 length prefix precedes the message.
        assert_eq!(bytes[0], 1);
    }
}

#[test]
fn v0_message_carries_the_version_prefix_byte() {
    let tx = build_versioned("v0", &[0u8; 4], &[], &[], Template::Minimal.v1_config());
    let bytes = encode_wire("v0", &tx);
    // Legacy/v0 wire layout writes the signature array first: a one-byte
    // ShortU16 length, then 64-byte signatures, then the message. The v0
    // message therefore starts with the version prefix byte at offset 1 + 64.
    assert_eq!(bytes[0], 1, "one signature");
    assert_eq!(bytes[1 + 64], 0x80, "v0 message version prefix");
}

#[test]
fn v1_wire_size_matches_the_reviewer_probe_ladder() {
    // Independent reviewer probes of the v1 wire encoder for the ML-DSA-44
    // inline payload (166-byte intent + 2,420-byte signature + 1,312-byte key),
    // for this specific one-instruction template. Sizes do not depend on the
    // payload contents, so a same-length zero buffer reproduces them. These are
    // observations of this template, not universal constants.
    let data = vec![0u8; 166 + 2420 + 1312];
    let state = Pubkey::from([9u8; 32]);

    let two_empty = wire_size("v1", &data, &[], &[], Template::Minimal.v1_config());
    let two_configured = wire_size("v1", &data, &[], &[], Template::Operational.v1_config());
    let three_configured = wire_size(
        "v1",
        &data,
        &[state],
        &[],
        Template::Operational.v1_config(),
    );

    assert_eq!(two_empty, 4074, "2 accounts, empty config");
    assert_eq!(
        two_configured - two_empty,
        8,
        "two u32 resource-limit fields add exactly 8 bytes"
    );
    assert_eq!(two_configured, 4082);
    assert_eq!(
        three_configured - two_configured,
        33,
        "one extra state account adds a 32-byte address plus a 1-byte index"
    );
    assert_eq!(three_configured, 4115);

    // The operational 4-account template used by `analyze` (registry + state).
    let four_configured = wire_size(
        "v1",
        &data,
        &[Pubkey::from([5u8; 32])],
        &[Pubkey::from([4u8; 32])],
        Template::Operational.v1_config(),
    );
    assert_eq!(four_configured, 4115 + 33);
}

// ---------------------------------------------------------------------------
// Direct rows
// ---------------------------------------------------------------------------

#[test]
fn produces_all_schemes_templates_formats_placements() {
    let rows = rows();
    assert_eq!(
        rows.len(),
        48,
        "4 schemes x 2 placements x 2 templates x 3 formats"
    );
    for r in &rows {
        assert_eq!(r.evidence_type, "serialized");
        assert!(r.total_bytes > 0);
        assert_eq!(r.native_signature_bytes, 64);
        assert!(
            (r.format == "v1") == (r.applicable_limit == V1_LIMIT),
            "{r:?}"
        );
        if r.format == "v1" && r.template == "operational" {
            assert!(r.v1_config.contains("compute_unit_limit"), "{r:?}");
            assert!(
                r.v1_config.contains("loaded_accounts_data_size_limit"),
                "{r:?}"
            );
        } else if r.format == "v1" {
            assert_eq!(r.v1_config, "empty");
        } else {
            assert_eq!(r.v1_config, "n/a");
        }
    }
}

#[test]
fn operational_template_is_larger_than_minimal() {
    let rows = rows();
    for scheme in ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"] {
        for format in ["legacy", "v0", "v1"] {
            let min = find(&rows, scheme, format, "registered", "minimal");
            let op = find(&rows, scheme, format, "registered", "operational");
            assert!(op.total_bytes > min.total_bytes, "{scheme} {format}");
            assert_eq!(op.account_count, 4);
            assert_eq!(min.account_count, 2);
        }
    }
}

#[test]
fn ed25519_direct_fits_in_legacy_v0() {
    let rows = rows();
    for format in ["legacy", "v0"] {
        for template in ["minimal", "operational"] {
            let r = find(&rows, "ed25519", format, "inline", template);
            assert!(
                r.total_bytes <= LEGACY_V0_LIMIT,
                "ed25519 inline must fit: {r:?}"
            );
        }
    }
}

#[test]
fn ml_dsa_44_exceeds_limit_even_when_registered() {
    let rows = rows();
    for template in ["minimal", "operational"] {
        for format in ["legacy", "v0"] {
            let r = find(&rows, "ml-dsa-44", format, "registered", template);
            assert!(r.total_bytes > LEGACY_V0_LIMIT, "{r:?}");
        }
    }
}

#[test]
fn v1_lifts_ml_dsa_44_but_not_larger_schemes() {
    let rows = rows();
    // ML-DSA-44 fits v1 on the minimal template, but not on the operational one.
    let m44_min = find(&rows, "ml-dsa-44", "v1", "inline", "minimal");
    assert!(
        m44_min.total_bytes <= V1_LIMIT && m44_min.headroom > 0,
        "{m44_min:?}"
    );
    let m44_op = find(&rows, "ml-dsa-44", "v1", "inline", "operational");
    assert!(m44_op.total_bytes > V1_LIMIT, "{m44_op:?}");

    // ML-DSA-65 inline and SLH-DSA registered still exceed v1.
    let m65 = find(&rows, "ml-dsa-65", "v1", "inline", "operational");
    assert!(m65.total_bytes > V1_LIMIT, "{m65:?}");
    let slh = find(
        &rows,
        "slh-dsa-sha2-128s",
        "v1",
        "registered",
        "operational",
    );
    assert!(slh.total_bytes > V1_LIMIT, "{slh:?}");
}

#[test]
fn registration_reduces_transport_by_the_public_key_size() {
    let rows = rows();
    for scheme in ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"] {
        for template in ["minimal", "operational"] {
            let inline = find(&rows, scheme, "legacy", "inline", template);
            let registered = find(&rows, scheme, "legacy", "registered", template);
            assert_eq!(
                inline.total_bytes - registered.total_bytes,
                inline.public_key_bytes,
                "{scheme} {template}"
            );
        }
    }
}

#[test]
fn v0_is_legacy_plus_version_and_lookup_overhead() {
    let rows = rows();
    for scheme in ["ed25519", "ml-dsa-44", "ml-dsa-65", "slh-dsa-sha2-128s"] {
        for placement in ["inline", "registered"] {
            for template in ["minimal", "operational"] {
                let legacy = find(&rows, scheme, "legacy", placement, template);
                let v0 = find(&rows, scheme, "v0", placement, template);
                assert!(v0.total_bytes >= legacy.total_bytes, "{scheme} {placement}");
                assert!(
                    v0.total_bytes - legacy.total_bytes <= 4,
                    "{scheme} {placement} {template}"
                );
            }
        }
    }
}

#[test]
fn signed_intent_is_bound_to_the_configured_environment() {
    // The scheme byte and key id inside the signed intent match the row, and
    // the program id matches the program account of the transaction.
    for scheme in Scheme::ALL {
        let intent = signed_intent(scheme);
        let decoded = pq_solana_lab::intent::WithdrawalIntent::decode(&intent).unwrap();
        assert_eq!(decoded.scheme, scheme);
        assert_eq!(decoded.key_id, KEY_ID);
        assert_eq!(decoded.program_id, [2u8; 32]);
        assert_eq!(decoded.network_id, pq_solana_lab::transport::NETWORK_ID);
    }
}

// ---------------------------------------------------------------------------
// Staged upload model
// ---------------------------------------------------------------------------

#[test]
fn staged_rows_are_labeled_modeled_with_explicit_cost_scope() {
    let rows = staged_rows();
    assert_eq!(rows.len(), 12, "4 schemes x 3 formats");
    for r in &rows {
        assert_eq!(r.evidence_type, "modeled");
        assert_eq!(r.write_frame_bytes, WRITE_FRAME_BYTES);
        assert_eq!(r.session_metadata_bytes, SESSION_METADATA_BYTES);
        assert_eq!(r.storage_bytes, SESSION_METADATA_BYTES + r.signature_bytes);
        assert!(r.included_costs.contains("authorize"));
        assert!(r.excluded_costs.contains("rent"));
    }
}

#[test]
fn staged_chunking_is_consistent_and_maximal() {
    let rows = staged_rows();
    for r in &rows {
        let expected_chunks = r.signature_bytes.div_ceil(r.chunk_bytes);
        assert_eq!(r.chunk_count, expected_chunks, "{r:?}");
        assert_eq!(r.total_transactions, 3 + r.chunk_count, "{r:?}");
        assert!(
            r.total_transport_bytes
                == r.init_tx_bytes
                    + r.upload_tx_total_bytes
                    + r.seal_tx_bytes
                    + r.authorize_tx_bytes,
            "{r:?}"
        );
        assert!(r.applicable_limit == V1_LIMIT || r.applicable_limit == LEGACY_V0_LIMIT);
    }
}

#[test]
fn staged_write_transaction_fits_and_is_maximal() {
    // Re-derive the chunk boundary from the complete serialized Write
    // transaction and confirm the derived chunk is the largest that fits.
    for r in &staged_rows() {
        let session_id = [0u8; 32];
        let state = Pubkey::from([3u8; 32]);
        let registry = Pubkey::from([4u8; 32]);
        let config = Template::Operational.v1_config();

        let fit = |n: usize| {
            let data = encode_write(&session_id, 0, &vec![0u8; n]);
            wire_size(&r.format, &data, &[state], &[registry], config)
        };
        assert!(fit(r.chunk_bytes) <= r.applicable_limit, "{r:?}");
        assert!(fit(r.chunk_bytes + 1) > r.applicable_limit, "{r:?}");
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

#[test]
fn staged_init_binds_key_length_and_uploader() {
    let session_id = [0x5au8; 32];
    let data = encode_init(&session_id, KEY_ID, 2420, &UPLOADER);
    assert_eq!(data[0], UploadIx::Init.tag());
    assert_eq!(&data[1..33], &session_id);
    assert_eq!(u32::from_le_bytes(data[33..37].try_into().unwrap()), KEY_ID);
    assert_eq!(u32::from_le_bytes(data[37..41].try_into().unwrap()), 2420);
    assert_eq!(&data[41..73], &UPLOADER);
}

#[test]
fn staged_write_instruction_carries_the_protocol_framing() {
    let session_id = [0x5au8; 32];
    let chunk = [0x11u8; 100];
    let data = encode_write(&session_id, 7, &chunk);

    assert_eq!(data[0], UploadIx::Write.tag());
    assert_eq!(&data[1..33], &session_id);
    assert_eq!(u32::from_le_bytes(data[33..37].try_into().unwrap()), 7);
    assert_eq!(&data[37..], &chunk);
    assert_eq!(data.len(), WRITE_FRAME_BYTES + chunk.len());

    let tx = build_versioned(
        "v1",
        &data,
        &[Pubkey::from([3u8; 32])],
        &[Pubkey::from([4u8; 32])],
        Template::Operational.v1_config(),
    );
    let decoded = decode_wire("v1", &encode_wire("v1", &tx)).expect("decodes");
    let ix_data = &decoded.message.instructions()[0].data;
    assert_eq!(ix_data, &data, "framing survives the wire");
}

#[test]
fn v1_config_constants_are_recorded_and_sane() {
    assert_eq!(V1_COMPUTE_UNIT_LIMIT, 200_000);
    assert_eq!(V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT, 64 * 1024);
}
