//! One pool per user, and one payroll note the payee redeems.
//!
//! These accounts are not the 104-byte stream or the 72-byte period. A deposit
//! spends the owner's note. A pay spends the payroll note. The program signs
//! only the PDA that is an input.

use crate::error::PayrollError;
use crate::processor::{CIRCUIT_PROOF_LEN, SPP_ID};
use crate::state::{
    claim_at, OpenPayroll, OpenVault, PayrollAccount, Vault, COMMITMENT_LEN, LIVE_NOTE,
    OWNER_HASH_LEN, PAYROLL_LEN, VAULT_LEN, VIEWING_LEN,
};

/// Seeds of the one pool PDA. The next seed is the owner's pubkey.
pub const POOL_SEED: &[u8] = b"user-pool";
/// Seeds of the payroll note PDA. The next seed is the payroll account.
pub const PAYROLL_NOTE_SEED: &[u8] = b"payroll";

/// Employee, payee hash, note hash, two times, the period, two commitments, the viewing key, ring, wallets.
pub const OPEN_PAYROLL_IX_LEN: usize = 32 + 32 + 32 + 8 + 8 + 8 + 32 + 32 + VIEWING_LEN + 1 + 1;

/// `keeps_note`, then the circuit proof. The pool payload follows.
pub const INITIATE_HEADER: usize = 1;

pub struct PoolMove<'a> {
    pub transact: &'a [u8],
}

pub struct InitiateMove<'a> {
    pub keeps_note: u8,
    pub transact: &'a [u8],
}

/// Public inputs of a deposit, a join, or a withdraw. The hash is the pool PDA's owner hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvedVault {
    pub hash: [u8; 32],
}

/// Public inputs of `initiate`. `keeps_note` is 1 when the pool still has change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvedInitiate {
    pub budget: [u8; 32],
    pub note: [u8; 32],
    pub keeps_note: u64,
}

/// Public inputs of `pay`. The payee hash is the shielded recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvedPay {
    pub index: u64,
    pub due: u64,
    pub installment: [u8; 32],
    pub payee: [u8; 32],
}

/// Public inputs of `reclaim`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvedReclaim {
    pub note: [u8; 32],
    pub pool: [u8; 32],
}

pub fn proved_vault(
    vault_data: &[u8],
    vault: &[u8; 32],
) -> Result<ProvedVault, PayrollError> {
    let mut owned = [0u8; VAULT_LEN];
    if vault_data.len() != VAULT_LEN {
        return Err(PayrollError::BadAccount);
    }
    owned.copy_from_slice(vault_data);
    let account = Vault::load(&mut owned)?;
    let _ = vault;
    Ok(ProvedVault {
        hash: account.owner_hash(),
    })
}

pub fn proved_initiate(
    payroll_data: &[u8],
    payroll: &[u8; 32],
    vault: &[u8; 32],
    keeps_note: u8,
) -> Result<ProvedInitiate, PayrollError> {
    if keeps_note > 1 {
        return Err(PayrollError::BadAccount);
    }
    let mut owned = [0u8; PAYROLL_LEN];
    if payroll_data.len() != PAYROLL_LEN {
        return Err(PayrollError::BadAccount);
    }
    owned.copy_from_slice(payroll_data);
    let account = PayrollAccount::load(&mut owned)?;
    let _ = (payroll, vault);
    Ok(ProvedInitiate {
        budget: account.budget(),
        note: account.note_hash(),
        keeps_note: u64::from(keeps_note),
    })
}

pub fn proved_pay(
    payroll_data: &[u8],
    payroll: &[u8; 32],
    now: i64,
) -> Result<ProvedPay, PayrollError> {
    let mut owned = [0u8; PAYROLL_LEN];
    if payroll_data.len() != PAYROLL_LEN {
        return Err(PayrollError::BadAccount);
    }
    owned.copy_from_slice(payroll_data);
    let account = PayrollAccount::load(&mut owned)?;
    let due = claim_at(account.start_at(), account.period_secs(), account.next_redeem())?;
    let _ = (payroll, now);
    Ok(ProvedPay {
        index: u64::from(account.next_redeem()),
        due: u64::try_from(due).map_err(|_| PayrollError::BadAccount)?,
        installment: account.installment(),
        payee: account.payee_hash(),
    })
}

pub fn proved_reclaim(
    payroll_data: &[u8],
    payroll: &[u8; 32],
    vault_data: &[u8],
    vault: &[u8; 32],
) -> Result<ProvedReclaim, PayrollError> {
    if payroll_data.len() != PAYROLL_LEN || vault_data.len() != VAULT_LEN {
        return Err(PayrollError::BadAccount);
    }
    let mut payroll_owned = [0u8; PAYROLL_LEN];
    let mut vault_owned = [0u8; VAULT_LEN];
    payroll_owned.copy_from_slice(payroll_data);
    vault_owned.copy_from_slice(vault_data);
    let payroll_account = PayrollAccount::load(&mut payroll_owned)?;
    let vault_account = Vault::load(&mut vault_owned)?;
    let _ = (payroll, vault);
    Ok(ProvedReclaim {
        note: payroll_account.note_hash(),
        pool: vault_account.owner_hash(),
    })
}

pub fn open_vault(data: &mut [u8], args: &OpenVault) -> Result<(), PayrollError> {
    Vault::load(data)?.open(args)
}

pub fn open_payroll(data: &mut [u8], args: &OpenPayroll) -> Result<(), PayrollError> {
    PayrollAccount::load(data)?.open(args)
}

pub fn approve_payroll(data: &mut [u8], signer: &[u8; 32], now: i64) -> Result<(), PayrollError> {
    PayrollAccount::load(data)?.approve(signer, now)
}

pub fn stop_payroll(data: &mut [u8], signer: &[u8; 32]) -> Result<(), PayrollError> {
    PayrollAccount::load(data)?.stop(signer)
}

/// The owner's note becomes the pool's one note.
pub fn deposit(
    vault_data: &mut [u8],
    vault: &[u8; 32],
    signer: &[u8; 32],
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<PoolMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    move_vault(
        vault_data,
        vault,
        signer,
        privacy_program,
        move_ix,
        true,
        invoke,
    )
}

/// A top-up joins the live note. The pool still has one note afterwards.
pub fn join(
    vault_data: &mut [u8],
    vault: &[u8; 32],
    signer: &[u8; 32],
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<PoolMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    move_vault(
        vault_data,
        vault,
        signer,
        privacy_program,
        move_ix,
        false,
        invoke,
    )
}

/// The owner takes the live note back. The pool is empty afterwards.
pub fn withdraw(
    vault_data: &mut [u8],
    vault: &[u8; 32],
    signer: &[u8; 32],
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<PoolMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    require_spp(privacy_program)?;
    Vault::load(vault_data)?.spend_ready(signer)?;
    let transact = transact(move_ix)?;
    let _public = proved_vault(vault_data, vault)?;
    invoke(transact)?;
    Vault::load(vault_data)?.set_live(0)
}

/// Peels the committed budget into the payroll note.
pub fn initiate(
    payroll_data: &mut [u8],
    payroll: &[u8; 32],
    vault_data: &mut [u8],
    vault: &[u8; 32],
    signer: &[u8; 32],
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<InitiateMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    require_spp(privacy_program)?;
    PayrollAccount::load(payroll_data)?.initiate_ready(signer)?;
    Vault::load(vault_data)?.spend_ready(signer)?;
    if Vault::load(vault_data)?.owner() != signer {
        return Err(PayrollError::NotAParty);
    }
    let Some(move_ix) = move_ix else {
        return Err(PayrollError::PrivateLockNotWired);
    };
    if move_ix.transact.is_empty() {
        return Err(PayrollError::PrivateLockNotWired);
    }
    let _public = proved_initiate(payroll_data, payroll, vault, move_ix.keeps_note)?;
    invoke(move_ix.transact)?;
    Vault::load(vault_data)?.set_live(move_ix.keeps_note)?;
    PayrollAccount::load(payroll_data)?.mark_funded()
}

/// The payee peels the committed installment. The employer cannot call this.
pub fn pay(
    payroll_data: &mut [u8],
    payroll: &[u8; 32],
    signer: &[u8; 32],
    now: i64,
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<PoolMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    require_spp(privacy_program)?;
    let _due = PayrollAccount::load(payroll_data)?.pay_ready(signer, now)?;
    let transact = transact(move_ix)?;
    let _public = proved_pay(payroll_data, payroll, now)?;
    invoke(transact)?;
    PayrollAccount::load(payroll_data)?.commit_pay()
}

/// After `stop`, the remainder joins the employer's pool.
pub fn reclaim(
    payroll_data: &mut [u8],
    payroll: &[u8; 32],
    vault_data: &mut [u8],
    vault: &[u8; 32],
    signer: &[u8; 32],
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<PoolMove<'_>>,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    require_spp(privacy_program)?;
    PayrollAccount::load(payroll_data)?.reclaim_ready(signer)?;
    if Vault::load(vault_data)?.owner() != signer {
        return Err(PayrollError::NotAParty);
    }
    let transact = transact(move_ix)?;
    let _public = proved_reclaim(payroll_data, payroll, vault_data, vault)?;
    invoke(transact)?;
    Vault::load(vault_data)?.set_live(LIVE_NOTE)?;
    PayrollAccount::load(payroll_data)?.mark_reclaimed()
}

/// Instruction bytes of `open_payroll`, after the tag.
pub fn parse_open_payroll(
    ix: &[u8],
    employer: &[u8; 32],
) -> Result<OpenPayroll, PayrollError> {
    if ix.len() != OPEN_PAYROLL_IX_LEN {
        return Err(PayrollError::BadAccount);
    }
    let mut payee = [0u8; 32];
    let mut payee_hash = [0u8; OWNER_HASH_LEN];
    let mut note_hash = [0u8; OWNER_HASH_LEN];
    let mut installment = [0u8; COMMITMENT_LEN];
    let mut budget = [0u8; COMMITMENT_LEN];
    let mut viewing = [0u8; VIEWING_LEN];
    payee.copy_from_slice(&ix[0..32]);
    payee_hash.copy_from_slice(&ix[32..64]);
    note_hash.copy_from_slice(&ix[64..96]);
    let start_at = i64_from(&ix[96..104])?;
    let approval_deadline = i64_from(&ix[104..112])?;
    let period_secs = i64_from(&ix[112..120])?;
    installment.copy_from_slice(&ix[120..152]);
    budget.copy_from_slice(&ix[152..184]);
    viewing.copy_from_slice(&ix[184..184 + VIEWING_LEN]);
    let ring_at = 184 + VIEWING_LEN;
    let ring = match ix[ring_at] {
        1 => crate::state::Ring::Permissionless,
        2 => crate::state::Ring::Custom,
        _ => return Err(PayrollError::BadAccount),
    };
    let wallets = match ix[ring_at + 1] {
        1 => crate::state::Wallets::Public,
        2 => crate::state::Wallets::Private,
        _ => return Err(PayrollError::BadAccount),
    };
    Ok(OpenPayroll {
        employer: *employer,
        payee,
        payee_hash,
        note_hash,
        installment,
        budget,
        viewing,
        start_at,
        approval_deadline,
        period_secs,
        ring,
        wallets,
    })
}

pub fn parse_open_vault(ix: &[u8], owner: &[u8; 32]) -> Result<OpenVault, PayrollError> {
    if ix.len() != OWNER_HASH_LEN + VIEWING_LEN {
        return Err(PayrollError::BadAccount);
    }
    let mut owner_hash = [0u8; OWNER_HASH_LEN];
    let mut viewing = [0u8; VIEWING_LEN];
    owner_hash.copy_from_slice(&ix[0..OWNER_HASH_LEN]);
    viewing.copy_from_slice(&ix[OWNER_HASH_LEN..]);
    Ok(OpenVault {
        owner: *owner,
        owner_hash,
        viewing,
    })
}

pub fn parse_pool_move(ix: &[u8]) -> Result<Option<PoolMove<'_>>, PayrollError> {
    if ix.is_empty() {
        return Ok(None);
    }
    let transact = ix.get(CIRCUIT_PROOF_LEN..).ok_or(PayrollError::BadAccount)?;
    Ok(Some(PoolMove { transact }))
}

pub fn parse_initiate(ix: &[u8]) -> Result<Option<InitiateMove<'_>>, PayrollError> {
    if ix.is_empty() {
        return Ok(None);
    }
    let keeps_note = *ix.first().ok_or(PayrollError::BadAccount)?;
    let transact = ix
        .get(INITIATE_HEADER + CIRCUIT_PROOF_LEN..)
        .ok_or(PayrollError::BadAccount)?;
    Ok(Some(InitiateMove {
        keeps_note,
        transact,
    }))
}

fn move_vault(
    vault_data: &mut [u8],
    vault: &[u8; 32],
    signer: &[u8; 32],
    privacy_program: Option<&[u8; 32]>,
    move_ix: Option<PoolMove<'_>>,
    opening: bool,
    invoke: &mut dyn FnMut(&[u8]) -> Result<(), PayrollError>,
) -> Result<(), PayrollError> {
    require_spp(privacy_program)?;
    if opening {
        Vault::load(vault_data)?.deposit_ready(signer)?;
    } else {
        Vault::load(vault_data)?.spend_ready(signer)?;
    }
    let transact = transact(move_ix)?;
    let _public = proved_vault(vault_data, vault)?;
    invoke(transact)?;
    Vault::load(vault_data)?.set_live(LIVE_NOTE)
}

fn transact(move_ix: Option<PoolMove<'_>>) -> Result<&[u8], PayrollError> {
    let Some(move_ix) = move_ix else {
        return Err(PayrollError::PrivateLockNotWired);
    };
    if move_ix.transact.is_empty() {
        return Err(PayrollError::PrivateLockNotWired);
    }
    Ok(move_ix.transact)
}

fn require_spp(privacy_program: Option<&[u8; 32]>) -> Result<(), PayrollError> {
    let program = privacy_program.ok_or(PayrollError::WrongPrivacyProgram)?;
    if program != &SPP_ID {
        return Err(PayrollError::WrongPrivacyProgram);
    }
    Ok(())
}

fn i64_from(bytes: &[u8]) -> Result<i64, PayrollError> {
    let sized: [u8; 8] = bytes.try_into().map_err(|_| PayrollError::BadAccount)?;
    Ok(i64::from_le_bytes(sized))
}
