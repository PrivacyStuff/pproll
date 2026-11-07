use crate::error::PayrollError;
use crate::state::{claim_at, Period, Stream, COMMITMENT_LEN, PERIOD_LEN, STREAM_LEN};
use crate::state::{Ring, Wallets};

/// Devnet permissionless pool, `ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW`.
/// `fund` and `claim` accept only this id. The account layout is unchanged.
pub const SPP_ID: [u8; 32] = [
    12, 188, 181, 120, 174, 97, 37, 129, 50, 238, 175, 106, 193, 33, 192, 164, 43, 136, 162, 232,
    79, 177, 30, 126, 45, 91, 160, 175, 209, 39, 49, 99,
];

/// Seeds of the PDA that owns one period's note. The later seeds are the stream address and the index.
/// The bump is derived at invoke time. One bump on the stream would sign every period with the wrong seed.
pub const LOCK_SEED: &[u8] = b"payroll-lock";

pub use crate::state::MAX_OPEN;

pub const CREATE_IX_LEN: usize = 58;
/// Stream, index, and the output commitment. The circuit proof sits after this.
pub const FUND_HEADER: usize = 32 + 4 + 32;
pub const CLAIM_HEADER: usize = FUND_HEADER;
/// Compressed Groth16 proof: 32-byte A, 64-byte B, 32-byte C.
pub const CIRCUIT_PROOF_LEN: usize = 128;

/// Four limbs of a 32-byte address, little-endian.
pub fn address_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let limb = |offset: usize| {
        let mut sized = [0u8; 8];
        sized.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_le_bytes(sized)
    };
    [limb(0), limb(8), limb(16), limb(24)]
}

/// Fund public inputs, read from this stream. The employer is the account, not the client proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvedFund {
    pub stream: [u64; 4],
    pub index: u64,
    pub employer: [u64; 4],
}

/// Claim public inputs. `now` is the clock. The commitment is the period account's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvedClaim {
    pub stream: [u64; 4],
    pub index: u64,
    pub now: u64,
    pub claim_at: u64,
    pub commitment: [u64; 4],
}

/// Fund public inputs taken from this stream account.
pub fn proved_fund(data: &[u8], stream: &[u8; 32], index: u32) -> Result<ProvedFund, PayrollError> {
    if data.len() != STREAM_LEN {
        return Err(PayrollError::BadAccount);
    }
    let mut employer = [0u8; 32];
    employer.copy_from_slice(&data[32..64]);
    Ok(ProvedFund {
        stream: address_limbs(stream),
        index: u64::from(index),
        employer: address_limbs(&employer),
    })
}

/// Claim public inputs. `now` is the clock. `claim_at` and the commitment come from the accounts.
pub fn proved_claim(
    stream_data: &[u8],
    stream: &[u8; 32],
    period_data: &[u8],
    index: u32,
    now: i64,
) -> Result<ProvedClaim, PayrollError> {
    if stream_data.len() != STREAM_LEN || period_data.len() != PERIOD_LEN {
        return Err(PayrollError::BadAccount);
    }
    let start_at = i64_from(&stream_data[8..16])?;
    let period_secs = i64_from(&stream_data[24..32])?;
    let due = claim_at(start_at, period_secs, index)?;
    let now = u64::try_from(now).map_err(|_| PayrollError::BadAccount)?;
    let mut commitment = [0u8; COMMITMENT_LEN];
    commitment.copy_from_slice(&period_data[40..72]);
    Ok(ProvedClaim {
        stream: address_limbs(stream),
        index: u64::from(index),
        now,
        claim_at: u64::try_from(due).map_err(|_| PayrollError::BadAccount)?,
        commitment: address_limbs(&commitment),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Instruction {
    Create = 0,
    Approve = 1,
    Decline = 2,
    Fund = 3,
    Claim = 4,
    Stop = 5,
    Close = 6,
}

pub struct CreateArgs {
    pub employer: [u8; 32],
    pub employer_is_signer: bool,
    pub employee: [u8; 32],
    pub start_at: i64,
    pub approval_deadline: i64,
    pub period_secs: i64,
    pub ring: Ring,
    pub wallets: Wallets,
}

/// Public inputs of a fund, plus the opaque shielded-pool payload.
pub struct FundMove<'a> {
    pub stream: [u8; 32],
    pub index: u32,
    pub commitment: [u8; 32],
    pub transact: &'a [u8],
}

/// One instruction. Both accounts must be ours when the instruction touches them.
#[allow(clippy::too_many_arguments)]
pub fn process(
    instruction: Instruction,
    stream_owned_by_program: bool,
    stream_data: &mut [u8],
    period_owned_by_program: bool,
    period_data: Option<&mut [u8]>,
    stream: &[u8; 32],
    ix: &[u8],
    signer: &[u8; 32],
    signer_is_signer: bool,
    now: i64,
    privacy_program: Option<&[u8; 32]>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    if !stream_owned_by_program || stream_data.len() != STREAM_LEN {
        return Err(PayrollError::BadAccount);
    }
    match instruction {
        Instruction::Create => {
            let args = parse_create(ix, signer, signer_is_signer)?;
            create(stream_data, &args)
        }
        Instruction::Approve => {
            require_signer(signer_is_signer)?;
            approve(stream_data, signer, now)
        }
        Instruction::Decline => {
            require_signer(signer_is_signer)?;
            decline(stream_data, signer, now)
        }
        Instruction::Fund => {
            require_signer(signer_is_signer)?;
            let period = owned_period(period_owned_by_program, period_data)?;
            fund(
                stream_data,
                period,
                stream,
                signer,
                privacy_program,
                parse_move(ix, FUND_HEADER)?,
                invoke,
            )
        }
        Instruction::Claim => {
            require_signer(signer_is_signer)?;
            let period = owned_period(period_owned_by_program, period_data)?;
            claim(
                stream_data,
                period,
                stream,
                signer,
                now,
                privacy_program,
                parse_move(ix, CLAIM_HEADER)?,
                invoke,
            )
        }
        Instruction::Stop => {
            require_signer(signer_is_signer)?;
            stop(stream_data, signer)
        }
        Instruction::Close => {
            require_signer(signer_is_signer)?;
            close(stream_data, signer)
        }
    }
}

/// The employer must be the signer. Writes nothing if `create` rejects the pair.
pub fn create(data: &mut [u8], args: &CreateArgs) -> Result<(), PayrollError> {
    if !args.employer_is_signer {
        return Err(PayrollError::NotAParty);
    }
    Stream::load(data)?.create(
        &args.employer,
        &args.employee,
        args.start_at,
        args.approval_deadline,
        args.period_secs,
        args.ring,
        args.wallets,
    )
}

/// Records one party's approval. No proof. Does not rewrite the schedule.
pub fn approve(data: &mut [u8], signer: &[u8; 32], now: i64) -> Result<(), PayrollError> {
    Stream::load(data)?.approve(signer, now)
}

/// Closes an unfunded proposal. No proof.
pub fn decline(data: &mut [u8], signer: &[u8; 32], now: i64) -> Result<(), PayrollError> {
    Stream::load(data)?.decline(signer, now)
}

/// Checks the privacy program id, then the fund inputs, then invokes. Writes the period after.
pub fn fund(
    stream_data: &mut [u8],
    period_data: &mut [u8],
    stream: &[u8; 32],
    signer: &[u8; 32],
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<FundMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    require_spp(privacy_program)?;
    let index = {
        let payroll = Stream::load(stream_data)?;
        payroll.fund_ready(signer)?
    };
    let Some(move_ix) = move_ix else {
        return Err(PayrollError::PrivateLockNotWired);
    };
    if &move_ix.stream != stream {
        return Err(PayrollError::ProofMismatch);
    }
    if move_ix.index != index {
        return Err(PayrollError::BadIndex);
    }
    if move_ix.commitment == [0u8; COMMITMENT_LEN] {
        return Err(PayrollError::BadAccount);
    }
    if move_ix.transact.is_empty() {
        return Err(PayrollError::PrivateLockNotWired);
    }
    if Period::load(period_data)?.tag() != 0 {
        return Err(PayrollError::AlreadyInitialized);
    }
    let _public = proved_fund(stream_data, stream, index)?;
    invoke(move_ix.transact)?;
    let mut period = Period::load(period_data)?;
    Stream::load(stream_data)?.commit_fund(&mut period, stream, index, &move_ix.commitment)
}

/// Rules run before the invoke, so a failed claim leaves the note funded.
pub fn claim(
    stream_data: &mut [u8],
    period_data: &mut [u8],
    stream: &[u8; 32],
    signer: &[u8; 32],
    now: i64,
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<FundMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    require_spp(privacy_program)?;
    let index = {
        let payroll = Stream::load(stream_data)?;
        let index = payroll.next_claim();
        let _due = payroll.claim_ready(signer, index, now)?;
        index
    };
    let Some(move_ix) = move_ix else {
        return Err(PayrollError::PrivateLockNotWired);
    };
    if &move_ix.stream != stream {
        return Err(PayrollError::ProofMismatch);
    }
    if move_ix.index != index {
        return Err(PayrollError::BadIndex);
    }
    {
        let period = Period::load(period_data)?;
        period.require_claim(stream, index, &move_ix.commitment)?;
    }
    if move_ix.transact.is_empty() {
        return Err(PayrollError::PrivateLockNotWired);
    }
    let _public = proved_claim(stream_data, stream, period_data, index, now)?;
    invoke(move_ix.transact)?;
    let mut period = Period::load(period_data)?;
    Stream::load(stream_data)?.commit_claim(&mut period, stream, index, &move_ix.commitment)
}

/// Employer blocks later funds. Does not touch a funded period.
pub fn stop(data: &mut [u8], signer: &[u8; 32]) -> Result<(), PayrollError> {
    Stream::load(data)?.stop(signer)
}

/// Marks the stream `Closed` when no funded note is still outstanding.
pub fn close(data: &mut [u8], signer: &[u8; 32]) -> Result<(), PayrollError> {
    Stream::load(data)?.close(signer)
}

fn require_spp(privacy_program: Option<&[u8; 32]>) -> Result<(), PayrollError> {
    let program = privacy_program.ok_or(PayrollError::WrongPrivacyProgram)?;
    if program != &SPP_ID {
        return Err(PayrollError::WrongPrivacyProgram);
    }
    Ok(())
}

fn owned_period<'a>(
    owned: bool,
    period_data: Option<&'a mut [u8]>,
) -> Result<&'a mut [u8], PayrollError> {
    if !owned {
        return Err(PayrollError::BadAccount);
    }
    let period = period_data.ok_or(PayrollError::BadAccount)?;
    if period.len() != PERIOD_LEN {
        return Err(PayrollError::BadAccount);
    }
    Ok(period)
}

fn require_signer(is_signer: bool) -> Result<(), PayrollError> {
    if is_signer {
        Ok(())
    } else {
        Err(PayrollError::NotAParty)
    }
}

/// 58 bytes: employee, two times, the period, ring, wallets. A short buffer fails.
fn parse_create(
    ix: &[u8],
    employer: &[u8; 32],
    employer_is_signer: bool,
) -> Result<CreateArgs, PayrollError> {
    if ix.len() != CREATE_IX_LEN {
        return Err(PayrollError::BadAccount);
    }
    let mut employee = [0u8; 32];
    employee.copy_from_slice(&ix[0..32]);
    let ring = match ix[56] {
        1 => Ring::Permissionless,
        2 => Ring::Custom,
        _ => return Err(PayrollError::BadAccount),
    };
    let wallets = match ix[57] {
        1 => Wallets::Public,
        2 => Wallets::Private,
        _ => return Err(PayrollError::BadAccount),
    };
    Ok(CreateArgs {
        employer: *employer,
        employer_is_signer,
        employee,
        start_at: i64_from(&ix[32..40])?,
        approval_deadline: i64_from(&ix[40..48])?,
        period_secs: i64_from(&ix[48..56])?,
        ring,
        wallets,
    })
}

/// Empty means no pool move. Otherwise stream, index, commitment, then opaque bytes.
fn parse_move(ix: &[u8], header: usize) -> Result<Option<FundMove<'_>>, PayrollError> {
    if ix.is_empty() {
        return Ok(None);
    }
    let transact = proof_suffix(ix, header)?;
    let mut stream = [0u8; 32];
    stream.copy_from_slice(&ix[0..32]);
    let mut index_bytes = [0u8; 4];
    index_bytes.copy_from_slice(&ix[32..36]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&ix[36..68]);
    Ok(Some(FundMove {
        stream,
        index: u32::from_le_bytes(index_bytes),
        commitment,
        transact,
    }))
}

fn proof_suffix(ix: &[u8], header: usize) -> Result<&[u8], PayrollError> {
    let end = header
        .checked_add(CIRCUIT_PROOF_LEN)
        .ok_or(PayrollError::BadAccount)?;
    ix.get(end..).ok_or(PayrollError::BadAccount)
}

fn i64_from(bytes: &[u8]) -> Result<i64, PayrollError> {
    let sized: [u8; 8] = bytes.try_into().map_err(|_| PayrollError::BadAccount)?;
    Ok(i64::from_le_bytes(sized))
}
