//! Minimal control program for the sBPF verifier experiment.
//!
//! It does one thing: log and return success. It exists to prove that the
//! toolchain (`cargo-build-sbf`) and the loader path work, so that the
//! ML-DSA-44 verifier's rejection can be attributed to the verifier code and
//! not to the toolchain.

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, pubkey::Pubkey,
};

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!(
        "sbpf-control: ok ({} bytes of instruction data)",
        instruction_data.len()
    );
    Ok(())
}
