use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Verifier};
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

entrypoint!(process_instruction);

const PK_LEN: usize = ml_dsa_44::PK_LEN;
const SIG_LEN: usize = ml_dsa_44::SIG_LEN;

/// Instruction data layout: [public key (1312)] [signature (2420)] [message].
fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < PK_LEN + SIG_LEN {
        msg!("instruction data too short");
        return Err(ProgramError::InvalidInstructionData);
    }
    let pk_bytes: [u8; PK_LEN] = match instruction_data[..PK_LEN].try_into() {
        Ok(b) => b,
        Err(_) => return Err(ProgramError::InvalidInstructionData),
    };
    let sig_bytes: [u8; SIG_LEN] = match instruction_data[PK_LEN..PK_LEN + SIG_LEN].try_into() {
        Ok(b) => b,
        Err(_) => return Err(ProgramError::InvalidInstructionData),
    };
    let message = &instruction_data[PK_LEN + SIG_LEN..];

    let pk = match ml_dsa_44::PublicKey::try_from_bytes(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return Err(ProgramError::InvalidArgument),
    };

    if pk.verify(message, &sig_bytes, b"") {
        Ok(())
    } else {
        Err(ProgramError::InvalidArgument)
    }
}
