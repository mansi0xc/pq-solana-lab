//! Controlled comparison: ML-DSA-44 verification via the RustCrypto `ml-dsa`
//! implementation, built for sBPF.
//!
//! Same fixture layout and same behaviour as `sbpf-verifier/src/lib.rs` (the
//! `fips204` program), so the two programs differ only in the ML-DSA library:
//! fixture `pk (1312) || sig (2420) || message`, taken from instruction data if
//! long enough, otherwise from the first account's data.

use ml_dsa::signature::Verifier;
use ml_dsa::{MlDsa44, Signature, VerifyingKey};
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

entrypoint!(process_instruction);

const PK_LEN: usize = 1312;
const SIG_LEN: usize = 2420;

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() >= PK_LEN + SIG_LEN {
        return verify_slice(instruction_data);
    }
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let data = account.try_borrow_data()?;
    verify_slice(&data)
}

fn verify_slice(data: &[u8]) -> ProgramResult {
    if data.len() < PK_LEN + SIG_LEN {
        msg!("data too short: {} bytes", data.len());
        return Err(ProgramError::InvalidInstructionData);
    }
    let pk_bytes: [u8; PK_LEN] = data[..PK_LEN]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let sig_bytes: [u8; SIG_LEN] = data[PK_LEN..PK_LEN + SIG_LEN]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let message = &data[PK_LEN + SIG_LEN..];

    let vk = VerifyingKey::<MlDsa44>::decode(&pk_bytes.into());
    let sig =
        Signature::<MlDsa44>::decode(&sig_bytes.into()).ok_or(ProgramError::InvalidArgument)?;

    match vk.verify(message, &sig) {
        Ok(()) => {
            msg!("ml-dsa (rustcrypto): signature VALID");
            Ok(())
        }
        Err(_) => {
            msg!("ml-dsa (rustcrypto): signature INVALID");
            Err(ProgramError::InvalidArgument)
        }
    }
}
