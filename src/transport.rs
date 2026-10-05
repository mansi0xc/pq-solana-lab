//! Solana transport analysis: serialize actual transactions carrying the
//! post-quantum authorization material in instruction data, and report the
//! byte budget.
//!
//! Evidence type: every `total_bytes` value here is the size of an actually
//! serialized transaction built with `solana-sdk` 5.0.0 (bincode wire format),
//! not a manual estimate. The 1,232-byte limit applies to legacy and v0 packet
//! data. A size result is a transport measurement; it is not an executed
//! authorization and not a claim about verification cost.

use serde::Serialize;
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{v0, VersionedMessage},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, VersionedTransaction},
};

use crate::crypto::Scheme;
use crate::intent::WithdrawalIntent;

/// Packet-data size limit for legacy and v0 transactions (documented).
pub const LEGACY_V0_LIMIT: usize = 1232;

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

/// Build and serialize the transactions for every scheme and key placement.
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
            rows.push(measure_legacy(
                scheme,
                placement,
                &data,
                intent.len(),
                sig.len(),
                pk.len(),
            ));
            rows.push(measure_v0(
                scheme,
                placement,
                &data,
                intent.len(),
                sig.len(),
                pk.len(),
            ));
        }
    }
    rows
}

/// One keypair, one real signed intent, and its signature per scheme.
fn auth_material(scheme: Scheme) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let kp = scheme.keygen().expect("keygen");
    let intent = WithdrawalIntent::new(
        scheme, 7, [0xab; 32], [0xcd; 32], [0x01; 32], [0x02; 32], 100, 0, 1000,
    );
    let intent = intent.encode().to_vec();
    let sig = scheme.sign(&kp.secret, &intent).expect("sign");
    (intent, sig, kp.public.clone())
}

/// Authorization instruction data: intent + signature, plus the public key
/// when it is transported inline rather than looked up from a registration.
fn instruction_data(intent: &[u8], sig: &[u8], pk: &[u8], placement: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(intent.len() + sig.len() + pk.len());
    data.extend_from_slice(intent);
    data.extend_from_slice(sig);
    if placement == "inline" {
        data.extend_from_slice(pk);
    }
    data
}

/// A fixed program id and a fixed blockhash, for reproducible sizing.
fn program_id() -> Pubkey {
    Pubkey::from([2u8; 32])
}

fn recent_blockhash() -> Hash {
    Hash::new_from_array([0u8; 32])
}

/// One application instruction (fee payer signer + program).
fn instruction(data: &[u8], payer: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        program_id(),
        data,
        vec![
            AccountMeta::new(*payer, true), // fee payer: signer, writable
            AccountMeta::new_readonly(program_id(), false), // program: readonly
        ],
    )
}

fn measure_legacy(
    scheme: Scheme,
    placement: &str,
    data: &[u8],
    intent_len: usize,
    sig_len: usize,
    pk_len: usize,
) -> TransportRow {
    let payer = Keypair::new();
    let ixs = vec![instruction(data, &payer.pubkey())];
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash(),
    );
    let bytes = bincode::serialize(&tx).expect("serialize legacy");
    finish_row(
        scheme,
        "legacy",
        placement,
        data.len(),
        intent_len,
        sig_len,
        pk_len,
        2,
        bytes.len(),
    )
}

fn measure_v0(
    scheme: Scheme,
    placement: &str,
    data: &[u8],
    intent_len: usize,
    sig_len: usize,
    pk_len: usize,
) -> TransportRow {
    let payer = Keypair::new();
    let ixs = vec![instruction(data, &payer.pubkey())];
    let message = v0::Message::try_compile(&payer.pubkey(), &ixs, &[], recent_blockhash())
        .expect("compile v0");
    let vtx =
        VersionedTransaction::try_new(VersionedMessage::V0(message), &[&payer]).expect("sign v0");
    let bytes = bincode::serialize(&vtx).expect("serialize v0");
    finish_row(
        scheme,
        "v0",
        placement,
        data.len(),
        intent_len,
        sig_len,
        pk_len,
        2,
        bytes.len(),
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_row(
    scheme: Scheme,
    format: &str,
    placement: &str,
    instruction_data_len: usize,
    intent_len: usize,
    sig_len: usize,
    pk_len: usize,
    account_count: usize,
    total: usize,
) -> TransportRow {
    TransportRow {
        scheme: scheme.name().to_string(),
        format: format.to_string(),
        key_placement: placement.to_string(),
        intent_bytes: intent_len,
        signature_bytes: sig_len,
        public_key_bytes: if placement == "inline" { pk_len } else { 0 },
        instruction_data_bytes: instruction_data_len,
        native_signature_bytes: 64,
        account_count,
        total_bytes: total,
        applicable_limit: LEGACY_V0_LIMIT,
        headroom: LEGACY_V0_LIMIT as i64 - total as i64,
        evidence_type: "serialized".to_string(),
    }
}
