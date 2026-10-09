//! Builds a signed legacy transaction for a local validator, so the deployed
//! ML-DSA-44 verifier program can be executed.
//!
//! The fixture is supplied through **account data** (an account preloaded by
//! `solana-test-validator --account`), because the validator's RPC enforces the
//! 1,232-byte packet limit and `pk||sig||msg` (3,783 B) cannot ride in
//! instruction data.
//!
//! Usage:
//!   invoke-client build-tx <payer.json> <program_id> <data_file> <blockhash> [account ...]

use std::str::FromStr;

use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, VersionedTransaction},
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("build-tx") {
        eprintln!("usage: invoke-client build-tx <payer.json> <program_id> <data_file> <blockhash> [account ...]");
        std::process::exit(2);
    }
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
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
    let bytes = bincode::serialize(&VersionedTransaction::from(tx)).expect("bincode");

    eprintln!(
        "transaction: {} bytes, instruction data {} bytes, accounts {}",
        bytes.len(),
        data.len(),
        accounts.len()
    );
    use base64::Engine;
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    );
}
