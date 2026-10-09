//! Host-side harness for the sBPF verifier experiment.
//!
//! Two jobs:
//!
//! * `fixture <out_dir>` — generate a genuine ML-DSA-44 fixture (public key,
//!   signature, message), verify it on the host with the same `fips204` build
//!   the on-chain program uses, and write valid / altered-message /
//!   invalid-signature variants as `pk||sig||msg` byte files.
//! * `probe <label> <elf>` — load the ELF with the Agave SBF VM
//!   (`solana-sbpf` 0.13.1, the crate Agave 3.1.x uses) using the loader's
//!   default configuration, run the loader's verifier
//!   (`RequisiteVerifier`), and report the outcome. Execution is attempted
//!   with the interpreter only if loading and verification both succeed.
//!
//! This is a *local* harness: it exercises the same VM/verifier code the
//! runtime loader uses, but it is not a validator. See
//! `../../docs/solana-feasibility.md`.

use std::sync::Arc;

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};
use solana_sbpf::{
    elf::Executable,
    program::BuiltinProgram,
    verifier::RequisiteVerifier,
    vm::{Config, ContextObject},
};

/// Minimal instruction meter context.
struct Meter {
    remaining: u64,
}

impl ContextObject for Meter {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("fixture") => {
            let out = args.get(2).expect("usage: fixture <out_dir>");
            gen_fixture(out);
        }
        Some("probe") => {
            let label = args.get(2).expect("usage: probe <label> <elf>");
            let elf = args.get(3).expect("usage: probe <label> <elf>");
            probe(label, elf);
        }
        _ => {
            eprintln!("usage: loader-harness fixture <out_dir> | probe <label> <elf>");
            std::process::exit(2);
        }
    }
}

fn gen_fixture(out_dir: &str) {
    let (pk, sk) = ml_dsa_44::try_keygen().expect("keygen");
    let pk_bytes = pk.clone().into_bytes();
    let msg = b"pq-solana-lab sBPF fixture: withdraw 100 base units".to_vec();
    let sig: [u8; ml_dsa_44::SIG_LEN] = sk.try_sign(&msg, b"").expect("sign");
    let sig_bytes = sig.to_vec();

    assert!(pk.verify(&msg, &sig, b""), "host fixture must verify");
    println!(
        "genuine fixture: pk={} sig={} msg={} (host verification: OK)",
        pk_bytes.len(),
        sig_bytes.len(),
        msg.len()
    );

    let mut altered_msg = msg.clone();
    altered_msg[0] ^= 0x01;
    assert!(
        !pk.verify(&altered_msg, &sig, b""),
        "altered message must NOT verify"
    );

    let mut invalid_sig = sig;
    invalid_sig[0] ^= 0x01;
    assert!(
        !pk.verify(&msg, &invalid_sig, b""),
        "invalid signature must NOT verify"
    );

    std::fs::create_dir_all(out_dir).expect("mkdir");
    let write = |name: &str, m: &[u8], s: &[u8]| {
        let mut buf = Vec::new();
        buf.extend_from_slice(&pk_bytes);
        buf.extend_from_slice(s);
        buf.extend_from_slice(m);
        std::fs::write(format!("{out_dir}/{name}"), &buf).expect("write fixture");
        buf.len()
    };
    let a = write("valid.bin", &msg, &sig_bytes);
    let b = write("altered_message.bin", &altered_msg, &sig_bytes);
    let c = write("invalid_signature.bin", &msg, &invalid_sig);
    println!("wrote valid.bin ({a} B), altered_message.bin ({b} B), invalid_signature.bin ({c} B)");
}

fn probe(label: &str, elf_path: &str) {
    let elf = std::fs::read(elf_path).unwrap_or_else(|e| panic!("read {elf_path}: {e}"));
    println!("== {label} ==");
    println!("elf: {elf_path} ({} bytes)", elf.len());

    let config = Config::default();
    let loader = Arc::new(BuiltinProgram::<Meter>::new_loader(config.clone()));
    let executable = match Executable::<Meter>::from_elf(&elf, loader.clone()) {
        Ok(e) => {
            println!("load:   OK (sbpf_version={:?})", e.get_sbpf_version());
            e
        }
        Err(e) => {
            println!("load:   REJECTED: {e:?}");
            return;
        }
    };

    match executable.verify::<RequisiteVerifier>() {
        Ok(()) => println!("verify: OK (RequisiteVerifier)"),
        Err(e) => {
            println!("verify: REJECTED: {e:?}");
            return;
        }
    }

    // Execution is deliberately NOT attempted here: a Solana program needs the
    // program-runtime ABI (serialized input at MM_INPUT_START plus the syscall
    // registry), which this lightweight loader harness does not implement.
    // Authentic load/execute evidence comes from the local validator
    // (see `../outcome/` and `../../docs/solana-feasibility.md`).
    println!("execute: not attempted by this harness (program-runtime ABI out of scope)");
}
