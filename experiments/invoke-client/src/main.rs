//! Builds a signed transaction for a local validator, so the deployed programs
//! can be executed — and so v1 submission can be probed.
//!
//! * `build-tx` — legacy transaction (bincode). Used in practice, because the
//!   Agave 3.1.x runtime has no v1 support: the `enable_tx_v1` feature
//!   ("SIMD-0385: Transaction V1") is present in `agave-feature-set` 4.2.x but
//!   absent from 3.1.x, so this runtime's RPC rejects v1 submissions.
//! * `build-v1-tx` — v1 transaction (wincode). Used to record that rejection.
//!
//! The oversized fixture is supplied through **account data** (preloaded with
//! `solana-test-validator --account`), because the RPC enforces the
//! 1,232-byte packet limit.
//!
//! Usage:
//!   invoke-client build-tx    <payer.json> <program_id> <data_file> <blockhash> [account ...]
//!   invoke-client build-v1-tx <payer.json> <program_id> <data_file> <blockhash>

use std::str::FromStr;

use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{v1, VersionedMessage},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, VersionedTransaction},
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let v1_mode = match args.get(1).map(String::as_str) {
        Some("build-tx") => false,
        Some("build-v1-tx") => true,
        _ => {
            eprintln!("usage: invoke-client build-tx|build-v1-tx <payer.json> <program_id> <data_file> <blockhash> [account ...]");
            std::process::exit(2);
        }
    };
    let payer_path = &args[2];
    let program_id = Pubkey::from_str(&args[3]).expect("program id");
    let data = std::fs::read(&args[4]).expect("data file");
    let blockhash = Hash::from_str(&args[5]).expect("blockhash");
    let accounts: Vec<Pubkey> = args[6..]
        .iter()
        .map(|a| Pubkey::from_str(a).expect("account"))
        .collect();

    let kp_bytes: Vec<u8> =
        serde_json::from_str(&std::fs::read_to_string(payer_path).expect("read payer keypair"))
            .expect("parse payer keypair");
    let payer = Keypair::try_from(kp_bytes.as_slice()).expect("keypair");

    let metas: Vec<AccountMeta> = accounts
        .iter()
        .map(|k| AccountMeta::new_readonly(*k, false))
        .collect();
    let ix = Instruction::new_with_bytes(program_id, &data, metas);

    let bytes = if v1_mode {
        let message = v1::Message::try_compile_with_config(
            &payer.pubkey(),
            &[ix],
            blockhash,
            v1::TransactionConfig::empty(),
        )
        .expect("compile v1");
        let tx = VersionedTransaction::try_new(VersionedMessage::V1(message), &[&payer])
            .expect("sign v1");
        wincode::serialize(&tx).expect("wire encode v1")
    } else {
        let tx =
            Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
        bincode::serialize(&VersionedTransaction::from(tx)).expect("bincode")
    };

    eprintln!(
        "transaction: {} bytes ({}), instruction data {} bytes, accounts {}",
        bytes.len(),
        if v1_mode {
            "v1/wincode"
        } else {
            "legacy/bincode"
        },
        data.len(),
        accounts.len()
    );
    use base64::Engine;
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    );
}
