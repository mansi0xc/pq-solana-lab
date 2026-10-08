//! Solana transport analysis.
//!
//! # What is measured
//!
//! *Direct* rows are the sizes of actually serialized single-instruction
//! transactions. Legacy and v0 use the classic bincode wire format; **v1 uses
//! the SDK's own wire encoder** (`wincode`). The v1 message format explicitly
//! does not support bincode binary serialization — `solana-message` 5.1.0
//! states: "This message format does not support bincode binary serialization.
//! Use the provided `serialize` and `deserialize` functions." A bincode v1
//! buffer is *not* a valid wire transaction and is rejected by the SDK's v1
//! decoder.
//!
//! Two templates are distinguished so a minimal payload measurement is never
//! confused with an operational authorization transaction:
//!
//! * [`Template::Minimal`] — fee payer + program (2 accounts). The payload and
//!   envelope floor; v1 config left empty.
//! * [`Template::Operational`] — fee payer + trusted key-registry account
//!   (read-only) + authorization-state / nonce-ledger account (writable) +
//!   program (4 accounts). v1 rows additionally set an explicit compute-unit
//!   limit and loaded-account-data size limit.
//!
//! The signed intent is bound to the configured environment: its scheme byte is
//! the row's scheme, its `program_id` equals the program account in the
//! transaction, and its `network_id` equals [`NETWORK_ID`].
//!
//! # Evidence type
//!
//! Direct rows are `serialized`. Staged rows are `modeled`: every transaction
//! in the upload protocol is serialized (with full instruction framing), but
//! the lifecycle is not executed on chain and account rent/cleanup is not
//! modeled. A size is a transport measurement, never an executed authorization
//! and never a claim about verification cost.

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

/// Explicit v1 compute-unit limit recorded in the operational template.
///
/// v1 has no compute-budget instruction; an unset field means `0`, so the
/// analysis sets it to the runtime's conventional 200,000-unit transaction cap.
pub const V1_COMPUTE_UNIT_LIMIT: u32 = 200_000;

/// Explicit v1 loaded-account-data size limit (64 KiB) for the operational
/// template; unset means `0`. It bounds the account data the runtime may load,
/// which must at least cover the stored signature plus registry/state.
pub const V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT: u32 = 64 * 1024;

/// Stated margin subtracted when deriving the largest safe upload chunk. The
/// template already includes all accounts, signatures, and framing, so the
/// margin is zero; it exists to make the safety assumption explicit.
const STAGED_MARGIN: usize = 0;

/// Registered-key identifier carried by every analyzed intent.
pub const KEY_ID: u32 = 7;
/// Network/genesis identifier of the configured environment.
pub const NETWORK_ID: [u8; 32] = [0x11; 32];
/// Asset identifier used by the analyzed withdrawal intents.
pub const ASSET_ID: [u8; 32] = [0x01; 32];
/// Recipient identifier used by the analyzed withdrawal intents.
pub const RECIPIENT_ID: [u8; 32] = [0x02; 32];

/// Session-account metadata stored on chain for the staged-upload protocol
/// (bytes): 32-byte session id + 32-byte authorized uploader + key id (u32) +
/// expected length (u32) + bytes-written counter (u32) + sealed flag (u8).
pub const SESSION_METADATA_BYTES: usize = 32 + 32 + 4 + 4 + 4 + 1;

/// Framing overhead of a `Write` instruction before the chunk payload
/// (tag + 32-byte session id + 4-byte offset).
pub const WRITE_FRAME_BYTES: usize = 1 + 32 + 4;

/// Authorized uploader bound by `Init` and stored in session metadata.
pub const UPLOADER: [u8; 32] = [0x55; 32];

/// Which account/configuration template a direct row uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Template {
    /// Fee payer + program (2 accounts); empty v1 config.
    Minimal,
    /// Fee payer + registry (ro) + authorization state (rw) + program; explicit
    /// v1 compute/loaded-data limits.
    Operational,
}

impl Template {
    pub fn name(self) -> &'static str {
        match self {
            Template::Minimal => "minimal",
            Template::Operational => "operational",
        }
    }

    /// v1 compute-config for this template. v1 has no compute-budget
    /// instruction, so the operational template states the limits explicitly.
    pub fn v1_config(self) -> v1::TransactionConfig {
        match self {
            Template::Minimal => v1::TransactionConfig::empty(),
            Template::Operational => v1::TransactionConfig::empty()
                .with_compute_unit_limit(V1_COMPUTE_UNIT_LIMIT)
                .with_loaded_accounts_data_size_limit(V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT),
        }
    }

    /// Extra accounts beyond the fee payer and the program.
    fn extra_accounts(self) -> (Vec<Pubkey>, Vec<Pubkey>) {
        match self {
            Template::Minimal => (Vec::new(), Vec::new()),
            Template::Operational => (vec![auth_state_id()], vec![registry_id()]),
        }
    }
}

/// Instruction tags for the staged signature-upload protocol (model).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UploadIx {
    /// Initialize the session: binds a registered key and an expected length.
    Init = 1,
    /// Append a chunk at a sequential offset.
    Write = 2,
    /// Seal the session once the expected total length has been written.
    Seal = 3,
    /// Authorize against the sealed signature and the signed intent.
    Authorize = 4,
}

impl UploadIx {
    pub fn tag(self) -> u8 {
        self as u8
    }
}

/// Direct-inclusion row.
#[derive(Debug, Clone, Serialize)]
pub struct TransportRow {
    pub scheme: String,
    pub template: String,
    pub format: String,
    pub key_placement: String,
    pub intent_bytes: usize,
    pub signature_bytes: usize,
    pub public_key_bytes: usize,
    pub instruction_data_bytes: usize,
    pub native_signature_bytes: usize,
    pub account_count: usize,
    pub v1_config: String,
    pub total_bytes: usize,
    pub applicable_limit: usize,
    pub headroom: i64,
    pub evidence_type: String,
}

/// Staged-upload row (model). All component transactions are serialized; the
/// lifecycle is not executed.
#[derive(Debug, Clone, Serialize)]
pub struct StagedRow {
    pub scheme: String,
    pub format: String,
    pub signature_bytes: usize,
    pub session_metadata_bytes: usize,
    pub storage_bytes: usize,
    pub chunk_bytes: usize,
    pub write_frame_bytes: usize,
    pub chunk_count: usize,
    pub init_tx_bytes: usize,
    pub upload_tx_total_bytes: usize,
    pub seal_tx_bytes: usize,
    pub authorize_tx_bytes: usize,
    pub total_transport_bytes: usize,
    pub total_transactions: usize,
    pub applicable_limit: usize,
    pub included_costs: String,
    pub excluded_costs: String,
    pub evidence_type: String,
}

/// Auth material for one scheme: signed intent, its signature, and public key.
struct AuthMaterial {
    intent: Vec<u8>,
    sig: Vec<u8>,
    pk: Vec<u8>,
}

/// Direct-inclusion rows for every scheme × placement × template × format.
pub fn analyze() -> Vec<TransportRow> {
    let mut rows = Vec::new();
    for scheme in Scheme::ALL {
        let material = auth_material(scheme);
        for placement in ["inline", "registered"] {
            let data = instruction_data(&material, placement);
            for template in [Template::Minimal, Template::Operational] {
                for format in ["legacy", "v0", "v1"] {
                    rows.push(direct_row(
                        scheme, format, placement, template, &data, &material,
                    ));
                }
            }
        }
    }
    rows
}

/// Staged-upload rows for every scheme × format.
pub fn staged() -> Vec<StagedRow> {
    let mut rows = Vec::new();
    for scheme in Scheme::ALL {
        for format in ["legacy", "v0", "v1"] {
            rows.push(staged_row(scheme, format));
        }
    }
    rows
}

// ---------------------------------------------------------------------------
// Wire encoding / decoding
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    Legacy,
    V0,
    V1,
}

impl Fmt {
    fn parse(format: &str) -> Fmt {
        match format {
            "legacy" => Fmt::Legacy,
            "v0" => Fmt::V0,
            "v1" => Fmt::V1,
            other => panic!("unknown format {other}"),
        }
    }
}

/// Build a single-instruction versioned transaction. `writable`/`readonly` are
/// extra accounts beyond the fee payer; the program account is appended.
/// `config` is only meaningful for v1.
pub fn build_versioned(
    format: &str,
    instruction_data: &[u8],
    writable: &[Pubkey],
    readonly: &[Pubkey],
    config: v1::TransactionConfig,
) -> VersionedTransaction {
    let fmt = Fmt::parse(format);
    let payer = Keypair::new();
    let mut metas = vec![AccountMeta::new(payer.pubkey(), true)];
    for key in writable {
        metas.push(AccountMeta::new(*key, false));
    }
    for key in readonly {
        metas.push(AccountMeta::new_readonly(*key, false));
    }
    metas.push(AccountMeta::new_readonly(program_id(), false));

    let ix = Instruction::new_with_bytes(program_id(), instruction_data, metas);
    let ixs = vec![ix];
    match fmt {
        Fmt::Legacy => VersionedTransaction::from(Transaction::new_signed_with_payer(
            &ixs,
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash(),
        )),
        Fmt::V0 => {
            let m = v0::Message::try_compile(&payer.pubkey(), &ixs, &[], recent_blockhash())
                .expect("compile v0");
            VersionedTransaction::try_new(VersionedMessage::V0(m), &[&payer]).expect("sign v0")
        }
        Fmt::V1 => {
            let m = v1::Message::try_compile_with_config(
                &payer.pubkey(),
                &ixs,
                recent_blockhash(),
                config,
            )
            .expect("compile v1");
            VersionedTransaction::try_new(VersionedMessage::V1(m), &[&payer]).expect("sign v1")
        }
    }
}

/// Encode a transaction in the format's actual wire encoding. Legacy/v0 use the
/// classic bincode wire format; v1 uses the SDK's `wincode` encoder, including
/// the version prefix and its fixed-length signature suffix.
pub fn encode_wire(format: &str, tx: &VersionedTransaction) -> Vec<u8> {
    match Fmt::parse(format) {
        Fmt::Legacy | Fmt::V0 => bincode::serialize(tx).expect("serialize legacy/v0"),
        Fmt::V1 => wincode::serialize(tx).expect("serialize v1 (wincode)"),
    }
}

/// Decode a wire transaction in the format's actual encoding. A bincode-encoded
/// v1 buffer is not a valid wire transaction and fails here.
pub fn decode_wire(format: &str, bytes: &[u8]) -> Result<VersionedTransaction, String> {
    match Fmt::parse(format) {
        Fmt::Legacy | Fmt::V0 => bincode::deserialize(bytes).map_err(|e| e.to_string()),
        Fmt::V1 => wincode::deserialize(bytes).map_err(|e| e.to_string()),
    }
}

/// The canonical signed withdrawal intent for a scheme, bound to the configured
/// environment (network + program identifiers).
pub fn signed_intent(scheme: Scheme) -> Vec<u8> {
    WithdrawalIntent::new(
        scheme,
        KEY_ID,
        NETWORK_ID,
        PROGRAM_BYTES,
        ASSET_ID,
        RECIPIENT_ID,
        100,
        0,
        1000,
    )
    .encode()
    .to_vec()
}

/// The version prefix byte of a v1 wire transaction (0x80 | 1).
pub const V1_VERSION_PREFIX: u8 = v1::V1_PREFIX;

// ---------------------------------------------------------------------------
// Direct rows
// ---------------------------------------------------------------------------

fn limit_for(format: &str) -> usize {
    match Fmt::parse(format) {
        Fmt::Legacy | Fmt::V0 => LEGACY_V0_LIMIT,
        Fmt::V1 => V1_LIMIT,
    }
}

fn config_label(format: &str, template: Template) -> String {
    if Fmt::parse(format) != Fmt::V1 {
        return "n/a".to_string();
    }
    match template {
        Template::Minimal => "empty".to_string(),
        Template::Operational => format!(
            "compute_unit_limit={V1_COMPUTE_UNIT_LIMIT},loaded_accounts_data_size_limit={V1_LOADED_ACCOUNTS_DATA_SIZE_LIMIT}"
        ),
    }
}

fn direct_row(
    scheme: Scheme,
    format: &str,
    placement: &str,
    template: Template,
    data: &[u8],
    material: &AuthMaterial,
) -> TransportRow {
    let (writable, readonly) = template.extra_accounts();
    let tx = build_versioned(format, data, &writable, &readonly, template.v1_config());
    let total = encode_wire(format, &tx).len();
    let limit = limit_for(format);
    TransportRow {
        scheme: scheme.name().to_string(),
        template: template.name().to_string(),
        format: format.to_string(),
        key_placement: placement.to_string(),
        intent_bytes: material.intent.len(),
        signature_bytes: material.sig.len(),
        public_key_bytes: if placement == "inline" {
            material.pk.len()
        } else {
            0
        },
        instruction_data_bytes: data.len(),
        native_signature_bytes: 64,
        account_count: 2 + writable.len() + readonly.len(),
        v1_config: config_label(format, template),
        total_bytes: total,
        applicable_limit: limit,
        headroom: limit as i64 - total as i64,
        evidence_type: "serialized".to_string(),
    }
}

fn auth_material(scheme: Scheme) -> AuthMaterial {
    let kp = scheme.keygen().expect("keygen");
    let intent = signed_intent(scheme);
    let sig = scheme.sign(&kp.secret, &intent).expect("sign");
    AuthMaterial {
        intent,
        sig,
        pk: kp.public.clone(),
    }
}

fn instruction_data(material: &AuthMaterial, placement: &str) -> Vec<u8> {
    let mut data =
        Vec::with_capacity(material.intent.len() + material.sig.len() + material.pk.len());
    data.extend_from_slice(&material.intent);
    data.extend_from_slice(&material.sig);
    if placement == "inline" {
        data.extend_from_slice(&material.pk);
    }
    data
}

// ---------------------------------------------------------------------------
// Staged upload (model)
// ---------------------------------------------------------------------------

fn staged_row(scheme: Scheme, format: &str) -> StagedRow {
    let fmt = Fmt::parse(format);
    let limit = limit_for(format);
    let config = Template::Operational.v1_config();
    let session_id = session_id_for(scheme);
    let sig_len = scheme.signature_len();
    let intent = signed_intent(scheme);

    let chunk = max_write_chunk(fmt, limit, &session_id, config);

    let init_data = encode_init(&session_id, KEY_ID, sig_len as u32, &UPLOADER);
    let init_tx_bytes = wire_len(
        fmt,
        &init_data,
        &[session_account_id()],
        &[registry_id()],
        config,
    );

    let mut upload_total = 0usize;
    let mut remaining = sig_len;
    let mut chunk_count = 0usize;
    while remaining > 0 {
        let n = remaining.min(chunk);
        let data = encode_write(&session_id, 0, &vec![0u8; n]);
        upload_total += wire_len(
            fmt,
            &data,
            &[session_account_id()],
            &[registry_id()],
            config,
        );
        remaining -= n;
        chunk_count += 1;
    }

    let seal_data = encode_seal(&session_id, sig_len as u32);
    let seal_tx_bytes = wire_len(
        fmt,
        &seal_data,
        &[session_account_id()],
        &[registry_id()],
        config,
    );

    let authorize_data = encode_authorize(&session_id, KEY_ID, &intent);
    let authorize_tx_bytes = wire_len(
        fmt,
        &authorize_data,
        &[auth_state_id()],
        &[session_account_id(), registry_id()],
        config,
    );

    let storage_bytes = SESSION_METADATA_BYTES + sig_len;
    let total_transport_bytes = init_tx_bytes + upload_total + seal_tx_bytes + authorize_tx_bytes;

    StagedRow {
        scheme: scheme.name().to_string(),
        format: format.to_string(),
        signature_bytes: sig_len,
        session_metadata_bytes: SESSION_METADATA_BYTES,
        storage_bytes,
        chunk_bytes: chunk,
        write_frame_bytes: WRITE_FRAME_BYTES,
        chunk_count,
        init_tx_bytes,
        upload_tx_total_bytes: upload_total,
        seal_tx_bytes,
        authorize_tx_bytes,
        total_transport_bytes,
        total_transactions: 3 + chunk_count,
        applicable_limit: limit,
        included_costs:
            "init+write+seal+authorize transaction wire bytes; session metadata + signature storage"
                .to_string(),
        excluded_costs: "key registration, account creation/rent, cleanup/close, compute cost"
            .to_string(),
        evidence_type: "modeled".to_string(),
    }
}

/// Instruction data for `Init`: tag, session id, registered key id, expected
/// signature length, and the authorized uploader.
pub fn encode_init(
    session_id: &[u8; 32],
    key_id: u32,
    expected_len: u32,
    uploader: &[u8; 32],
) -> Vec<u8> {
    let mut d = Vec::with_capacity(1 + 32 + 4 + 4 + 32);
    d.push(UploadIx::Init.tag());
    d.extend_from_slice(session_id);
    d.extend_from_slice(&key_id.to_le_bytes());
    d.extend_from_slice(&expected_len.to_le_bytes());
    d.extend_from_slice(uploader);
    d
}

/// Instruction data for `Write`: tag, session id, sequential offset, chunk.
pub fn encode_write(session_id: &[u8; 32], offset: u32, chunk: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(WRITE_FRAME_BYTES + chunk.len());
    d.push(UploadIx::Write.tag());
    d.extend_from_slice(session_id);
    d.extend_from_slice(&offset.to_le_bytes());
    d.extend_from_slice(chunk);
    d
}

/// Instruction data for `Seal`: tag, session id, total length.
pub fn encode_seal(session_id: &[u8; 32], total_len: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(1 + 32 + 4);
    d.push(UploadIx::Seal.tag());
    d.extend_from_slice(session_id);
    d.extend_from_slice(&total_len.to_le_bytes());
    d
}

/// Instruction data for `Authorize`: tag, session id, key id, signed intent.
pub fn encode_authorize(session_id: &[u8; 32], key_id: u32, intent: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(1 + 32 + 4 + intent.len());
    d.push(UploadIx::Authorize.tag());
    d.extend_from_slice(session_id);
    d.extend_from_slice(&key_id.to_le_bytes());
    d.extend_from_slice(intent);
    d
}

/// Largest chunk that fits a `Write` transaction of the given format, derived
/// by binary search over the complete serialized transaction (framing included).
fn max_write_chunk(
    fmt: Fmt,
    limit: usize,
    session_id: &[u8; 32],
    config: v1::TransactionConfig,
) -> usize {
    let mut lo = 0usize;
    let mut hi = limit;
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let data = encode_write(session_id, 0, &vec![0u8; mid]);
        let size = wire_len(
            fmt,
            &data,
            &[session_account_id()],
            &[registry_id()],
            config,
        );
        if size <= limit - STAGED_MARGIN {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

fn wire_len(
    fmt: Fmt,
    data: &[u8],
    writable: &[Pubkey],
    readonly: &[Pubkey],
    config: v1::TransactionConfig,
) -> usize {
    let format = match fmt {
        Fmt::Legacy => "legacy",
        Fmt::V0 => "v0",
        Fmt::V1 => "v1",
    };
    encode_wire(
        format,
        &build_versioned(format, data, writable, readonly, config),
    )
    .len()
}

fn session_id_for(scheme: Scheme) -> [u8; 32] {
    [scheme.id(); 32]
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

const PROGRAM_BYTES: [u8; 32] = [2u8; 32];

fn program_id() -> Pubkey {
    Pubkey::from(PROGRAM_BYTES)
}

/// Staged upload storage account (writable during upload, read-only afterwards).
fn session_account_id() -> Pubkey {
    Pubkey::from([3u8; 32])
}

/// Trusted key registry account (read-only).
fn registry_id() -> Pubkey {
    Pubkey::from([4u8; 32])
}

/// Authorization-state / nonce-ledger account (writable).
fn auth_state_id() -> Pubkey {
    Pubkey::from([5u8; 32])
}

fn recent_blockhash() -> Hash {
    Hash::new_from_array([0u8; 32])
}
