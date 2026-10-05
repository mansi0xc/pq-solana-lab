//! Solana transport analysis.
//!
//! Direct rows are the sizes of *actually serialized* transactions built with
//! `solana-sdk` 5.0.0 (bincode wire format). Staged rows are a *model* of a
//! multi-transaction upload lifecycle: each transaction in the sequence is
//! serializable, but the sequence itself is not executed here. A size result
//! is a transport measurement, not an executed authorization and not a claim
//! about verification cost.

use serde::Serialize;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{v0, v1, VersionedMessage},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, VersionedTransaction},
};

use crate::crypto::Scheme;
use crate::intent::WithdrawalIntent;

/// Packet-data size limit for legacy and v0 transactions (documented).
pub const LEGACY_V0_LIMIT: usize = 1232;
/// v1 transaction size limit, from the SDK's `v1::MAX_TRANSACTION_SIZE`.
pub const V1_LIMIT: usize = v1::MAX_TRANSACTION_SIZE;
/// Stated margin subtracted when deriving the largest safe upload chunk. The
/// template already includes all accounts, signatures, and framing, so the
/// margin is zero; it exists to make the safety assumption explicit.
const STAGED_MARGIN: usize = 0;

#[derive(Debug, Clone, Serialize)]
pub struct TransportRow {
    pub scheme: String,
    pub format: String,
    pub key_placement: String,
    pub intent_bytes: usize,
    pub signature_bytes: usize,
    pub public_key_bytes: usize,
    pub instruction_data_bytes: usize,
    pub native_signature_bytes: usize,
    pub account_count: usize,
    pub total_bytes: usize,
    pub applicable_limit: usize,
    pub headroom: i64,
    pub evidence_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StagedRow {
    pub scheme: String,
    pub format: String,
    pub signature_bytes: usize,
    pub storage_bytes: usize,
    pub chunk_bytes: usize,
    pub chunk_count: usize,
    pub init_tx_bytes: usize,
    pub upload_tx_total_bytes: usize,
    pub final_tx_bytes: usize,
    pub total_transport_bytes: usize,
    pub total_transactions: usize,
    pub applicable_limit: usize,
    pub evidence_type: String,
}

/// Direct-inclusion rows for every scheme × key placement × format.
pub fn analyze() -> Vec<TransportRow> {
    let mut rows = Vec::new();
    for scheme in [
        Scheme::Ed25519,
        Scheme::MlDsa44,
        Scheme::MlDsa65,
        Scheme::SlhDsaSha2128s,
    ] {
        let (intent, sig, pk) = auth_material(scheme);
        for placement in ["inline", "registered"] {
            let data = instruction_data(&intent, &sig, &pk, placement);
            for format in ["legacy", "v0", "v1"] {
                rows.push(direct_row(
                    scheme, format, placement, &data, &intent, &sig, &pk,
                ));
            }
        }
    }
    rows
}

/// Staged-upload rows for every scheme × format.
pub fn staged() -> Vec<StagedRow> {
    let mut rows = Vec::new();
    for scheme in [
        Scheme::Ed25519,
        Scheme::MlDsa44,
        Scheme::MlDsa65,
        Scheme::SlhDsaSha2128s,
    ] {
        for format in ["legacy", "v0", "v1"] {
            rows.push(staged_row(scheme, format));
        }
    }
    rows
}

fn limit_for(format: &str) -> usize {
    match format {
        "legacy" | "v0" => LEGACY_V0_LIMIT,
        "v1" => V1_LIMIT,
        other => panic!("unknown format {other}"),
    }
}

fn direct_row(
    scheme: Scheme,
    format: &str,
    placement: &str,
    data: &[u8],
    intent: &[u8],
    sig: &[u8],
    pk: &[u8],
) -> TransportRow {
    let total = serialized_size(format, data, false);
    TransportRow {
        scheme: scheme.name().to_string(),
        format: format.to_string(),
        key_placement: placement.to_string(),
        intent_bytes: intent.len(),
        signature_bytes: sig.len(),
        public_key_bytes: if placement == "inline" { pk.len() } else { 0 },
        instruction_data_bytes: data.len(),
        native_signature_bytes: 64,
        account_count: 2,
        total_bytes: total,
        applicable_limit: limit_for(format),
        headroom: limit_for(format) as i64 - total as i64,
        evidence_type: "serialized".to_string(),
    }
}

fn staged_row(scheme: Scheme, format: &str) -> StagedRow {
    let sig_len = scheme.signature_len();
    let limit = limit_for(format);
    let chunk = max_chunk(format, limit);

    let init = serialized_size(format, &[0u8], true);
    let final_tx = serialized_size(format, &intent_bytes(), true);

    let mut upload_total = 0usize;
    let mut remaining = sig_len;
    let mut chunk_count = 0usize;
    while remaining > 0 {
        let n = remaining.min(chunk);
        upload_total += serialized_size(format, &vec![0u8; n], true);
        remaining -= n;
        chunk_count += 1;
    }

    StagedRow {
        scheme: scheme.name().to_string(),
        format: format.to_string(),
        signature_bytes: sig_len,
        storage_bytes: sig_len,
        chunk_bytes: chunk,
        chunk_count,
        init_tx_bytes: init,
        upload_tx_total_bytes: upload_total,
        final_tx_bytes: final_tx,
        total_transport_bytes: init + upload_total + final_tx,
        total_transactions: 2 + chunk_count,
        applicable_limit: limit,
        evidence_type: "modeled".to_string(),
    }
}

/// Largest instruction-data chunk that fits in an upload transaction of the
/// given format, derived by binary search over actually-serialized sizes.
fn max_chunk(format: &str, limit: usize) -> usize {
    let mut lo = 0usize;
    let mut hi = limit;
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if serialized_size(format, &vec![0u8; mid], true) <= limit - STAGED_MARGIN {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Serialized size of a single-instruction transaction carrying `data` in
/// instruction data. `with_storage` adds a writable storage account (used by
/// the staged-upload model).
fn serialized_size(format: &str, data: &[u8], with_storage: bool) -> usize {
    let payer = Keypair::new();
    let mut metas = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new_readonly(program_id(), false),
    ];
    if with_storage {
        metas.push(AccountMeta::new(storage_id(), false));
    }
    let ix = Instruction::new_with_bytes(program_id(), data, metas);
    let ixs = vec![ix];
    let bytes = match format {
        "legacy" => {
            let tx = Transaction::new_signed_with_payer(
                &ixs,
                Some(&payer.pubkey()),
                &[&payer],
                recent_blockhash(),
            );
            bincode::serialize(&tx).expect("serialize legacy")
        }
        "v0" => {
            let m = v0::Message::try_compile(&payer.pubkey(), &ixs, &[], recent_blockhash())
                .expect("compile v0");
            let vtx =
                VersionedTransaction::try_new(VersionedMessage::V0(m), &[&payer]).expect("sign v0");
            bincode::serialize(&vtx).expect("serialize v0")
        }
        "v1" => {
            let m = v1::Message::try_compile_with_config(
                &payer.pubkey(),
                &ixs,
                recent_blockhash(),
                v1::TransactionConfig::empty(),
            )
            .expect("compile v1");
            let vtx =
                VersionedTransaction::try_new(VersionedMessage::V1(m), &[&payer]).expect("sign v1");
            bincode::serialize(&vtx).expect("serialize v1")
        }
        other => panic!("unknown format {other}"),
    };
    bytes.len()
}

fn auth_material(scheme: Scheme) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let kp = scheme.keygen().expect("keygen");
    let intent = intent_bytes();
    let sig = scheme.sign(&kp.secret, &intent).expect("sign");
    (intent, sig, kp.public.clone())
}

fn intent_bytes() -> Vec<u8> {
    WithdrawalIntent::new(
        Scheme::Ed25519,
        7,
        [0xab; 32],
        [0xcd; 32],
        [0x01; 32],
        [0x02; 32],
        100,
        0,
        1000,
    )
    .encode()
    .to_vec()
}

fn instruction_data(intent: &[u8], sig: &[u8], pk: &[u8], placement: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(intent.len() + sig.len() + pk.len());
    data.extend_from_slice(intent);
    data.extend_from_slice(sig);
    if placement == "inline" {
        data.extend_from_slice(pk);
    }
    data
}

fn program_id() -> Pubkey {
    Pubkey::from([2u8; 32])
}

fn storage_id() -> Pubkey {
    Pubkey::from([3u8; 32])
}

fn recent_blockhash() -> Hash {
    Hash::new_from_array([0u8; 32])
}
