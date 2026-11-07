use pinocchio::cpi::Signer;
use pinocchio::error::ProgramError;
use pinocchio::{
    default_allocator, default_panic_handler, program_entrypoint, AccountView, Address,
    ProgramResult,
};
use spr_interface::instruction::TransactIxDataRef;
use spr_program::cpi::SppTransactAccounts;
use spr_program::CompressedProof;

use crate::error::PayrollError;
use crate::pool::{
    approve_payroll, deposit, initiate, join, open_payroll, open_vault, parse_initiate,
    parse_open_payroll, parse_open_vault, parse_pool_move, pay, proved_initiate, proved_pay,
    proved_reclaim, proved_vault, reclaim, stop_payroll, withdraw, INITIATE_HEADER, PAYROLL_NOTE_SEED,
    POOL_SEED,
};
use crate::processor::{
    process, proved_claim, proved_fund, Instruction, CIRCUIT_PROOF_LEN, CLAIM_HEADER, FUND_HEADER,
    LOCK_SEED, SPP_ID,
};
use crate::state::{Stream, LIVE_NOTE, PAYROLL_LEN, PERIOD_LEN, STREAM_LEN, VAULT_LEN};
use crate::verifier::{claim, deposit as deposit_vk, fund, initiate as initiate_vk, join as join_vk, pay as pay_vk, reclaim as reclaim_vk, withdraw as withdraw_vk};

program_entrypoint!(process_instruction);
default_allocator!();
default_panic_handler!();

/// Create, approve, decline, and stop never move a note. Fund and claim do.
fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (tag, rest) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let instruction = match tag {
        0 => Instruction::Create,
        1 => Instruction::Approve,
        2 => Instruction::Decline,
        3 => Instruction::Fund,
        4 => Instruction::Claim,
        5 => Instruction::Stop,
        6 => return close_stream(program_id, accounts),
        7 => return deposit_note(program_id, accounts, rest),
        8 => return join_note(program_id, accounts, rest),
        9 => return withdraw_note(program_id, accounts, rest),
        10 => return open_vault_account(program_id, accounts, rest),
        11 => return open_payroll_account(program_id, accounts, rest),
        12 => return approve_payroll_account(program_id, accounts, rest),
        13 => return initiate_note(program_id, accounts, rest),
        14 => return pay_note(program_id, accounts, rest),
        15 => return stop_payroll_account(program_id, accounts),
        16 => return reclaim_note(program_id, accounts, rest),
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    if matches!(instruction, Instruction::Fund | Instruction::Claim) {
        return move_note(program_id, accounts, instruction, rest);
    }

    let stream = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !stream.is_writable() || !stream.owned_by(program_id) || stream.data_len() != STREAM_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let party = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let signer_bytes = *party.address().as_array();
    let signer_is_signer = party.is_signer();
    let account = *stream.address().as_array();
    let now = if instruction == Instruction::Create {
        0
    } else {
        read_clock(accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?)?
    };
    let mut scratch = [0u8; STREAM_LEN];
    scratch.copy_from_slice(&stream.try_borrow()?);
    process(
        instruction,
        true,
        &mut scratch,
        false,
        None,
        &account,
        rest,
        &signer_bytes,
        signer_is_signer,
        now,
        None,
        &mut |_| Err(PayrollError::PrivateLockNotWired),
    )
    .map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&scratch);
    Ok(())
}

/// Stream, period, signer, clock, then the pool accounts. On a claim the employer
/// rent account sits between the clock and the pool. Index 2 of the pool tail must be SPP.
fn move_note(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: Instruction,
    rest: &[u8],
) -> ProgramResult {
    let head_len = if instruction == Instruction::Claim {
        5
    } else {
        4
    };
    if accounts.len() < head_len + 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, spp_accounts) = accounts.split_at_mut(head_len);
    let stream_view = &head[0];
    let period_view = &head[1];
    if !stream_view.is_writable()
        || !stream_view.owned_by(program_id)
        || stream_view.data_len() != STREAM_LEN
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if !period_view.is_writable()
        || !period_view.owned_by(program_id)
        || period_view.data_len() != PERIOD_LEN
    {
        return Err(ProgramError::InvalidAccountData);
    }
    if stream_view.address() == period_view.address() {
        return Err(map_error(PayrollError::BadAccount));
    }
    let party = &head[2];
    let signer_bytes = *party.address().as_array();
    let signer_is_signer = party.is_signer();
    let stream_addr = *stream_view.address().as_array();
    let now = read_clock(&head[3])?;
    let privacy = *spp_accounts
        .get(2)
        .ok_or(ProgramError::IncorrectProgramId)?
        .address()
        .as_array();
    if privacy != SPP_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut stream_scratch = [0u8; STREAM_LEN];
    stream_scratch.copy_from_slice(&stream_view.try_borrow()?);
    let mut period_scratch = [0u8; PERIOD_LEN];
    period_scratch.copy_from_slice(&period_view.try_borrow()?);
    let stream_before = stream_scratch;
    let period_before = period_scratch;
    if instruction == Instruction::Claim {
        let employer = &head[4];
        let stored = &stream_before[32..64];
        if !employer.is_writable() || employer.address().as_array() != stored {
            return Err(map_error(PayrollError::NotAParty));
        }
    }
    let index = match instruction {
        Instruction::Fund => u32_at(&stream_before, 96)?,
        Instruction::Claim => u32_at(&stream_before, 100)?,
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    process(
        instruction,
        true,
        &mut stream_scratch,
        true,
        Some(&mut period_scratch),
        &stream_addr,
        rest,
        &signer_bytes,
        signer_is_signer,
        now,
        Some(&privacy),
        &mut |transact| {
            verify_then_stop(
                instruction,
                &stream_before,
                &period_before,
                &stream_addr,
                index,
                now,
                rest,
                transact,
            )?;
            invoke_pool(
                program_id,
                &stream_addr,
                index,
                spp_accounts,
                transact,
                instruction == Instruction::Claim,
            )
        },
    )
    .map_err(map_error)?;
    // A rejected proof returns before this copy. The accounts change only after `invoke_pool`.
    head[0].try_borrow_mut()?.copy_from_slice(&stream_scratch);
    head[1].try_borrow_mut()?.copy_from_slice(&period_scratch);
    if instruction == Instruction::Claim {
        let (period, after_period) = head[1..]
            .split_first_mut()
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        // signer, clock, employer. The employer was checked writable above.
        let employer = after_period
            .get_mut(2)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        release_rent(period, employer)?;
    }
    Ok(())
}

/// Builds the public inputs from the accounts and checks the Groth16 proof. A rejected proof does not invoke.
fn verify_then_stop(
    instruction: Instruction,
    stream_data: &[u8],
    period_data: &[u8],
    stream: &[u8; 32],
    index: u32,
    now: i64,
    rest: &[u8],
    transact: &[u8],
) -> Result<(), PayrollError> {
    let header = match instruction {
        Instruction::Fund => FUND_HEADER,
        Instruction::Claim => CLAIM_HEADER,
        _ => return Err(PayrollError::BadAccount),
    };
    let proof_at = header
        .checked_add(CIRCUIT_PROOF_LEN)
        .ok_or(PayrollError::BadAccount)?;
    let proof_bytes = rest
        .get(header..proof_at)
        .ok_or(PayrollError::BadAccount)?;
    if rest.get(proof_at..) != Some(transact) {
        return Err(PayrollError::ProofMismatch);
    }
    let tx = TransactIxDataRef::from_bytes(transact).map_err(|_| PayrollError::BadAccount)?;
    if !tx.interface_transfers.is_empty() {
        return Err(PayrollError::ProofMismatch);
    }
    let proof = compressed_proof(proof_bytes)?;
    match instruction {
        Instruction::Fund => {
            let public = proved_fund(stream_data, stream, index)?;
            fund::Verifier {
                proof: &proof,
                public_inputs: fund::PublicInputs {
                    stream_0: public.stream[0],
                    stream_1: public.stream[1],
                    stream_2: public.stream[2],
                    stream_3: public.stream[3],
                    index: public.index,
                    employer_0: public.employer[0],
                    employer_1: public.employer[1],
                    employer_2: public.employer[2],
                    employer_3: public.employer[3],
                },
                private_tx_hash: tx.private_tx_hash,
                transfers: &[],
            }
            .verify()
            .map_err(|_| PayrollError::ProofRejected)
        }
        Instruction::Claim => {
            let public = proved_claim(stream_data, stream, period_data, index, now)?;
            claim::Verifier {
                proof: &proof,
                public_inputs: claim::PublicInputs {
                    stream_0: public.stream[0],
                    stream_1: public.stream[1],
                    stream_2: public.stream[2],
                    stream_3: public.stream[3],
                    index: public.index,
                    now: public.now,
                    claim_at: public.claim_at,
                    commitment_0: public.commitment[0],
                    commitment_1: public.commitment[1],
                    commitment_2: public.commitment[2],
                    commitment_3: public.commitment[3],
                },
                private_tx_hash: tx.private_tx_hash,
                transfers: &[],
            }
            .verify()
            .map_err(|_| PayrollError::ProofRejected)
        }
        _ => Err(PayrollError::BadAccount),
    }
}

fn compressed_proof(bytes: &[u8]) -> Result<CompressedProof, PayrollError> {
    if bytes.len() != CIRCUIT_PROOF_LEN {
        return Err(PayrollError::BadAccount);
    }
    let mut a = [0u8; 32];
    let mut b = [0u8; 64];
    let mut c = [0u8; 32];
    a.copy_from_slice(&bytes[0..32]);
    b.copy_from_slice(&bytes[32..96]);
    c.copy_from_slice(&bytes[96..128]);
    Ok(CompressedProof { a, b, c })
}

/// Invokes SPP. A claim signs the period PDA, because that PDA spends the note.
/// A fund does not. The pool hashes every signer into the transact proof, and
/// the funded note's owner is an output, not a signer.
fn invoke_pool(
    program_id: &Address,
    stream: &[u8; 32],
    index: u32,
    spp_accounts: &[AccountView],
    transact: &[u8],
    sign_pda: bool,
) -> Result<(), PayrollError> {
    let index_bytes = index.to_le_bytes();
    let (pda, bump) = Address::find_program_address(&[LOCK_SEED, stream, &index_bytes], program_id);
    let bump_byte = [bump];
    let seeds = [
        pinocchio::cpi::Seed::from(LOCK_SEED),
        pinocchio::cpi::Seed::from(stream),
        pinocchio::cpi::Seed::from(&index_bytes),
        pinocchio::cpi::Seed::from(&bump_byte),
    ];
    let signer = Signer::from(&seeds);
    let pdas: &[&Address] = if sign_pda { &[&pda] } else { &[] };
    let accounts = SppTransactAccounts::new(spp_accounts, pdas)
        .map_err(|_| PayrollError::WrongPrivacyProgram)?;
    if sign_pda {
        accounts
            .invoke::<16>(transact, &[signer])
            .map_err(|_| PayrollError::InvokeFailed)
    } else {
        accounts
            .invoke::<16>(transact, &[])
            .map_err(|_| PayrollError::InvokeFailed)
    }
}

fn open_vault_account(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    let (vault, owner) = writable_pair(program_id, accounts, VAULT_LEN)?;
    if !owner.is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let args = parse_open_vault(rest, owner.address().as_array()).map_err(map_error)?;
    let mut scratch = [0u8; VAULT_LEN];
    scratch.copy_from_slice(&vault.try_borrow()?);
    open_vault(&mut scratch, &args).map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&scratch);
    Ok(())
}

fn open_payroll_account(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    let (payroll, employer) = writable_pair(program_id, accounts, PAYROLL_LEN)?;
    if !employer.is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let args = parse_open_payroll(rest, employer.address().as_array()).map_err(map_error)?;
    let mut scratch = [0u8; PAYROLL_LEN];
    scratch.copy_from_slice(&payroll.try_borrow()?);
    open_payroll(&mut scratch, &args).map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&scratch);
    Ok(())
}

fn approve_payroll_account(program_id: &Address, accounts: &mut [AccountView], _rest: &[u8]) -> ProgramResult {
    let now = read_clock(accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?)?;
    let (payroll, party) = writable_pair(program_id, accounts, PAYROLL_LEN)?;
    if !party.is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let mut scratch = [0u8; PAYROLL_LEN];
    scratch.copy_from_slice(&payroll.try_borrow()?);
    approve_payroll(&mut scratch, party.address().as_array(), now).map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&scratch);
    Ok(())
}

fn stop_payroll_account(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let (payroll, employer) = writable_pair(program_id, accounts, PAYROLL_LEN)?;
    if !employer.is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let mut scratch = [0u8; PAYROLL_LEN];
    scratch.copy_from_slice(&payroll.try_borrow()?);
    stop_payroll(&mut scratch, employer.address().as_array()).map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&scratch);
    Ok(())
}

fn deposit_note(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    move_vault(program_id, accounts, rest, VaultStep::Deposit)
}

fn join_note(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    move_vault(program_id, accounts, rest, VaultStep::Join)
}

fn withdraw_note(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    move_vault(program_id, accounts, rest, VaultStep::Withdraw)
}

enum VaultStep {
    Deposit,
    Join,
    Withdraw,
}

/// Deposit does not sign the pool PDA. Join and withdraw do, because that PDA spends.
fn move_vault(
    program_id: &Address,
    accounts: &mut [AccountView],
    rest: &[u8],
    step: VaultStep,
) -> ProgramResult {
    let (head, spp) = split_tail(program_id, accounts, 2, VAULT_LEN)?;
    require_spp(spp)?;
    let owner = *head[1].address().as_array();
    if !head[1].is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let vault_addr = *head[0].address().as_array();
    let (proof, transact, tx_hash) = split_proof(rest, 0)?;
    let mut scratch = [0u8; VAULT_LEN];
    scratch.copy_from_slice(&head[0].try_borrow()?);
    let public = proved_vault(&scratch, &vault_addr).map_err(map_error)?;
    let rejected = map_error(PayrollError::ProofRejected);
    match step {
        VaultStep::Deposit => deposit_vk::Verifier {
            proof: &proof,
            public_inputs: deposit_vk::PublicInputs { hash: public.hash },
            private_tx_hash: tx_hash,
            transfers: &[],
        }
        .verify()
        .map_err(|_| rejected)?,
        VaultStep::Join => join_vk::Verifier {
            proof: &proof,
            public_inputs: join_vk::PublicInputs { hash: public.hash },
            private_tx_hash: tx_hash,
            transfers: &[],
        }
        .verify()
        .map_err(|_| rejected)?,
        VaultStep::Withdraw => withdraw_vk::Verifier {
            proof: &proof,
            public_inputs: withdraw_vk::PublicInputs { hash: public.hash },
            private_tx_hash: tx_hash,
            transfers: &[],
        }
        .verify()
        .map_err(|_| rejected)?,
    }
    let move_ix = parse_pool_move(rest).map_err(map_error)?;
    match step {
        VaultStep::Deposit => {
            crate::state::Vault::load(&mut scratch).map_err(map_error)?.deposit_ready(&owner).map_err(map_error)?;
        }
        VaultStep::Join | VaultStep::Withdraw => {
            crate::state::Vault::load(&mut scratch).map_err(map_error)?.spend_ready(&owner).map_err(map_error)?;
        }
    }
    if matches!(step, VaultStep::Deposit) {
        invoke_none(spp, transact)?;
    } else {
        let (pda, bump) = Address::find_program_address(&[POOL_SEED, &owner], program_id);
        let bump_byte = [bump];
        let seeds = [
            pinocchio::cpi::Seed::from(POOL_SEED),
            pinocchio::cpi::Seed::from(&owner),
            pinocchio::cpi::Seed::from(&bump_byte),
        ];
        invoke_one(spp, transact, &pda, &seeds)?;
    }
    match step {
        VaultStep::Deposit => deposit(&mut scratch, &vault_addr, &owner, Some(&SPP_ID), move_ix, &mut |_| Ok(())),
        VaultStep::Join => join(&mut scratch, &vault_addr, &owner, Some(&SPP_ID), move_ix, &mut |_| Ok(())),
        VaultStep::Withdraw => withdraw(&mut scratch, &vault_addr, &owner, Some(&SPP_ID), move_ix, &mut |_| Ok(())),
    }
    .map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&scratch);
    Ok(())
}

fn initiate_note(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    let (head, spp) = split_tail(program_id, accounts, 3, PAYROLL_LEN)?;
    require_spp(spp)?;
    if head[1].data_len() != VAULT_LEN || !head[1].owned_by(program_id) {
        return Err(ProgramError::InvalidAccountData);
    }
    let employer = *head[2].address().as_array();
    if !head[2].is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let payroll_addr = *head[0].address().as_array();
    let vault_addr = *head[1].address().as_array();
    let (proof, transact, tx_hash) = split_proof(rest, INITIATE_HEADER)?;
    let mut payroll_scratch = [0u8; PAYROLL_LEN];
    let mut vault_scratch = [0u8; VAULT_LEN];
    payroll_scratch.copy_from_slice(&head[0].try_borrow()?);
    vault_scratch.copy_from_slice(&head[1].try_borrow()?);
    let parsed = parse_initiate(rest).map_err(map_error)?;
    let keeps = parsed.as_ref().map(|item| item.keeps_note).unwrap_or(0);
    let public = proved_initiate(&payroll_scratch, &payroll_addr, &vault_addr, keeps).map_err(map_error)?;
    initiate_vk::Verifier {
        proof: &proof,
        public_inputs: initiate_vk::PublicInputs {
            budget: public.budget,
            note: public.note,
            keeps_note: public.keeps_note,
        },
        private_tx_hash: tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(|_| map_error(PayrollError::ProofRejected))?;
    let (pda, bump) = Address::find_program_address(&[POOL_SEED, &employer], program_id);
    let bump_byte = [bump];
    let seeds = [
        pinocchio::cpi::Seed::from(POOL_SEED),
        pinocchio::cpi::Seed::from(&employer),
        pinocchio::cpi::Seed::from(&bump_byte),
    ];
    invoke_one(spp, transact, &pda, &seeds)?;
    initiate(
        &mut payroll_scratch,
        &payroll_addr,
        &mut vault_scratch,
        &vault_addr,
        &employer,
        Some(&SPP_ID),
        parsed,
        &mut |_| Ok(()),
    )
    .map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&payroll_scratch);
    accounts[1].try_borrow_mut()?.copy_from_slice(&vault_scratch);
    Ok(())
}

fn pay_note(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    let (head, spp) = split_tail(program_id, accounts, 3, PAYROLL_LEN)?;
    require_spp(spp)?;
    let payee = *head[1].address().as_array();
    if !head[1].is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let now = read_clock(&head[2])?;
    let payroll_addr = *head[0].address().as_array();
    let (proof, transact, tx_hash) = split_proof(rest, 0)?;
    let mut scratch = [0u8; PAYROLL_LEN];
    scratch.copy_from_slice(&head[0].try_borrow()?);
    let public = proved_pay(&scratch, &payroll_addr, now).map_err(map_error)?;
    pay_vk::Verifier {
        proof: &proof,
        public_inputs: pay_vk::PublicInputs {
            index: public.index,
            due: public.due,
            installment: public.installment,
            payee: public.payee,
        },
        private_tx_hash: tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(|_| map_error(PayrollError::ProofRejected))?;
    let (pda, bump) = Address::find_program_address(&[PAYROLL_NOTE_SEED, &payroll_addr], program_id);
    let bump_byte = [bump];
    let seeds = [
        pinocchio::cpi::Seed::from(PAYROLL_NOTE_SEED),
        pinocchio::cpi::Seed::from(&payroll_addr),
        pinocchio::cpi::Seed::from(&bump_byte),
    ];
    invoke_one(spp, transact, &pda, &seeds)?;
    let move_ix = parse_pool_move(rest).map_err(map_error)?;
    pay(
        &mut scratch,
        &payroll_addr,
        &payee,
        now,
        Some(&SPP_ID),
        move_ix,
        &mut |_| Ok(()),
    )
    .map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&scratch);
    Ok(())
}

fn reclaim_note(program_id: &Address, accounts: &mut [AccountView], rest: &[u8]) -> ProgramResult {
    let (head, spp) = split_tail(program_id, accounts, 3, PAYROLL_LEN)?;
    require_spp(spp)?;
    if head[1].data_len() != VAULT_LEN || !head[1].owned_by(program_id) {
        return Err(ProgramError::InvalidAccountData);
    }
    let employer = *head[2].address().as_array();
    if !head[2].is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let payroll_addr = *head[0].address().as_array();
    let vault_addr = *head[1].address().as_array();
    let (proof, transact, tx_hash) = split_proof(rest, 0)?;
    let mut payroll_scratch = [0u8; PAYROLL_LEN];
    let mut vault_scratch = [0u8; VAULT_LEN];
    payroll_scratch.copy_from_slice(&head[0].try_borrow()?);
    vault_scratch.copy_from_slice(&head[1].try_borrow()?);
    let public = proved_reclaim(&payroll_scratch, &payroll_addr, &vault_scratch, &vault_addr).map_err(map_error)?;
    reclaim_vk::Verifier {
        proof: &proof,
        public_inputs: reclaim_vk::PublicInputs {
            note: public.note,
            pool: public.pool,
        },
        private_tx_hash: tx_hash,
        transfers: &[],
    }
    .verify()
    .map_err(|_| map_error(PayrollError::ProofRejected))?;
    let pool_live = vault_scratch[1] == LIVE_NOTE;
    let (payroll_pda, payroll_bump) = Address::find_program_address(&[PAYROLL_NOTE_SEED, &payroll_addr], program_id);
    let (pool_pda, pool_bump) = Address::find_program_address(&[POOL_SEED, &employer], program_id);
    let payroll_bump_byte = [payroll_bump];
    let pool_bump_byte = [pool_bump];
    let payroll_seeds = [
        pinocchio::cpi::Seed::from(PAYROLL_NOTE_SEED),
        pinocchio::cpi::Seed::from(&payroll_addr),
        pinocchio::cpi::Seed::from(&payroll_bump_byte),
    ];
    let pool_seeds = [
        pinocchio::cpi::Seed::from(POOL_SEED),
        pinocchio::cpi::Seed::from(&employer),
        pinocchio::cpi::Seed::from(&pool_bump_byte),
    ];
    if pool_live {
        invoke_two(spp, transact, &payroll_pda, &payroll_seeds, &pool_pda, &pool_seeds)?;
    } else {
        invoke_one(spp, transact, &payroll_pda, &payroll_seeds)?;
    }
    let move_ix = parse_pool_move(rest).map_err(map_error)?;
    reclaim(
        &mut payroll_scratch,
        &payroll_addr,
        &mut vault_scratch,
        &vault_addr,
        &employer,
        Some(&SPP_ID),
        move_ix,
        &mut |_| Ok(()),
    )
    .map_err(map_error)?;
    accounts[0].try_borrow_mut()?.copy_from_slice(&payroll_scratch);
    accounts[1].try_borrow_mut()?.copy_from_slice(&vault_scratch);
    Ok(())
}

fn writable_pair<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    len: usize,
) -> Result<(&'a AccountView, &'a AccountView), ProgramError> {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let party = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !account.is_writable() || !account.owned_by(program_id) || account.data_len() != len {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok((account, party))
}

fn split_tail<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    head_len: usize,
    len: usize,
) -> Result<(&'a mut [AccountView], &'a mut [AccountView]), ProgramError> {
    if accounts.len() < head_len + 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, spp) = accounts.split_at_mut(head_len);
    if !head[0].is_writable() || !head[0].owned_by(program_id) || head[0].data_len() != len {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok((head, spp))
}

fn require_spp(spp: &[AccountView]) -> Result<(), ProgramError> {
    let privacy = *spp.get(2).ok_or(ProgramError::IncorrectProgramId)?.address().as_array();
    if privacy != SPP_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

fn split_proof<'a>(rest: &'a [u8], header: usize) -> Result<(CompressedProof, &'a [u8], &'a [u8; 32]), ProgramError> {
    let end = header.checked_add(CIRCUIT_PROOF_LEN).ok_or(ProgramError::InvalidInstructionData)?;
    let proof_bytes = rest.get(header..end).ok_or(ProgramError::InvalidInstructionData)?;
    let transact = rest.get(end..).ok_or(ProgramError::InvalidInstructionData)?;
    if transact.is_empty() {
        return Err(map_error(PayrollError::PrivateLockNotWired));
    }
    let tx = TransactIxDataRef::from_bytes(transact).map_err(|_| map_error(PayrollError::BadAccount))?;
    if !tx.interface_transfers.is_empty() {
        return Err(map_error(PayrollError::ProofMismatch));
    }
    let proof = compressed_proof(proof_bytes).map_err(map_error)?;
    Ok((proof, transact, tx.private_tx_hash))
}

fn invoke_none(spp: &[AccountView], transact: &[u8]) -> Result<(), ProgramError> {
    SppTransactAccounts::new(spp, &[])
        .map_err(|_| map_error(PayrollError::WrongPrivacyProgram))?
        .invoke::<16>(transact, &[])
        .map_err(|_| map_error(PayrollError::InvokeFailed))
}

fn invoke_one(spp: &[AccountView], transact: &[u8], pda: &Address, seeds: &[pinocchio::cpi::Seed]) -> Result<(), ProgramError> {
    let signer = Signer::from(seeds);
    SppTransactAccounts::new(spp, &[pda])
        .map_err(|_| map_error(PayrollError::WrongPrivacyProgram))?
        .invoke::<16>(transact, &[signer])
        .map_err(|_| map_error(PayrollError::InvokeFailed))
}

fn invoke_two(
    spp: &[AccountView],
    transact: &[u8],
    first: &Address,
    first_seeds: &[pinocchio::cpi::Seed],
    second: &Address,
    second_seeds: &[pinocchio::cpi::Seed],
) -> Result<(), ProgramError> {
    let first_signer = Signer::from(first_seeds);
    let second_signer = Signer::from(second_seeds);
    SppTransactAccounts::new(spp, &[first, second])
        .map_err(|_| map_error(PayrollError::WrongPrivacyProgram))?
        .invoke::<16>(transact, &[first_signer, second_signer])
        .map_err(|_| map_error(PayrollError::InvokeFailed))
}

/// Stream, then the party who closes. The employer receives the rent.
fn close_stream(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let stream = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !stream.is_writable() || !stream.owned_by(program_id) || stream.data_len() != STREAM_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let party = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !party.is_signer() {
        return Err(map_error(PayrollError::NotAParty));
    }
    let signer = *party.address().as_array();
    let mut data = [0u8; STREAM_LEN];
    data.copy_from_slice(&stream.try_borrow()?);
    let employer = {
        let mut payroll = Stream::load(&mut data).map_err(map_error)?;
        payroll.close(&signer).map_err(map_error)?;
        *payroll.employer()
    };
    let recipient_index = if accounts[1].address().as_array() == &employer {
        1
    } else {
        let recipient = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
        if recipient.address().as_array() != &employer || !recipient.is_writable() {
            return Err(map_error(PayrollError::NotAParty));
        }
        2
    };
    if !accounts[recipient_index].is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if accounts[recipient_index].address() == accounts[0].address() {
        return Err(map_error(PayrollError::BadAccount));
    }
    accounts[0].try_borrow_mut()?.copy_from_slice(&data);
    let (stream, tail) = accounts
        .split_first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let recipient = if recipient_index == 1 {
        &mut tail[0]
    } else {
        tail.get_mut(1).ok_or(ProgramError::NotEnoughAccountKeys)?
    };
    release_rent(stream, recipient)
}

/// Moves every lamport to `recipient`, zeroes the data, and assigns the system program.
fn release_rent(source: &mut AccountView, recipient: &mut AccountView) -> ProgramResult {
    if source.address() == recipient.address() {
        return Err(map_error(PayrollError::BadAccount));
    }
    let rent = source.lamports();
    let credited = recipient
        .lamports()
        .checked_add(rent)
        .ok_or(ProgramError::InvalidAccountData)?;
    recipient.set_lamports(credited);
    source.set_lamports(0);
    source.try_borrow_mut()?.fill(0);
    // SAFETY: this account is writable and owned by this program. Its lamports are already 0
    // and its data is zero, so assigning the system program id only releases the empty account.
    unsafe {
        source.assign(&Address::new_from_array([0u8; 32]));
    }
    Ok(())
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, ProgramError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(ProgramError::InvalidAccountData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Clock `unix_timestamp` at byte 32. A short sysvar is rejected.
fn read_clock(clock: &AccountView) -> Result<i64, ProgramError> {
    let data = clock.try_borrow()?;
    if data.len() < 40 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&data[32..40]);
    Ok(i64::from_le_bytes(ts))
}

fn map_error(error: PayrollError) -> ProgramError {
    ProgramError::Custom(error.code())
}
