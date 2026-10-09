//! Verification-only ML-DSA-44 (FIPS 204) program for the sBPF experiment.
//!
//! Fixture layout for both paths below: `pk (1312) || sig (2420) || message`.
//!
//! * If instruction data is at least `PK_LEN + SIG_LEN` bytes, it is verified
//!   directly.
//! * Otherwise the fixture is read from the **first account's data**. This is
//!   the path used on the local validator: `pk||sig||msg` is 3,783 bytes, which
//!   exceeds the 1,232-byte transaction packet limit, so it cannot ride in
//!   instruction data.
//!
//! The program returns `Ok(())` iff the signature verifies, and
//! `Err(InvalidArgument)` otherwise, so the runtime's transaction error and
//! compute units are the experiment's execution evidence.

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Verifier};
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

entrypoint!(process_instruction);

const PK_LEN: usize = ml_dsa_44::PK_LEN;
const SIG_LEN: usize = ml_dsa_44::SIG_LEN;

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

    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes)
        .map_err(|_| ProgramError::InvalidArgument)?;

    if pk.verify(message, &sig_bytes, b"") {
        msg!("ml-dsa-44: signature VALID");
        Ok(())
    } else {
        msg!("ml-dsa-44: signature INVALID");
        Err(ProgramError::InvalidArgument)
    }
}
