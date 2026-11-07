use pproll::{
    approve_payroll, deposit, initiate, join, open_payroll, open_vault, pay, reclaim, stop_payroll,
    withdraw, InitiateMove, OpenPayroll, OpenVault, PayrollAccount, PoolMove, Ring, Stream, Vault,
    Wallets, LIVE_EMPTY, LIVE_NOTE, PAYROLL_LEN, PAYROLL_TAG, PERIOD_LEN, STREAM_LEN, STREAM_TAG,
    VAULT_LEN, VAULT_TAG, SPP_ID,
};

fn wallet(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn viewing() -> [u8; VIEWING] {
    let mut key = [9u8; VIEWING];
    key[0] = 4;
    key
}

const VIEWING: usize = 33;

fn vault_args() -> OpenVault {
    OpenVault {
        owner: wallet(1),
        owner_hash: hash(3),
        viewing: viewing(),
    }
}

fn payroll_args() -> OpenPayroll {
    OpenPayroll {
        employer: wallet(1),
        payee: wallet(2),
        payee_hash: hash(4),
        note_hash: hash(5),
        installment: hash(6),
        budget: hash(7),
        viewing: viewing(),
        start_at: 1_000,
        approval_deadline: 900,
        period_secs: 100,
        ring: Ring::Permissionless,
        wallets: Wallets::Public,
    }
}

fn fresh_vault() -> Vec<u8> {
    vec![0u8; VAULT_LEN]
}

fn fresh_payroll() -> Vec<u8> {
    vec![0u8; PAYROLL_LEN]
}

fn move_ix() -> PoolMove<'static> {
    PoolMove { transact: &[1u8] }
}

fn funded_payroll(payroll: &mut [u8], vault: &mut [u8]) {
    open_payroll(payroll, &payroll_args()).unwrap();
    approve_payroll(payroll, &wallet(2), 100).unwrap();
    open_vault(vault, &vault_args()).unwrap();
    deposit(vault, &wallet(8), &wallet(1), Some(&SPP_ID), Some(move_ix()), &mut |_| Ok(())).unwrap();
    initiate(
        payroll,
        &wallet(9),
        vault,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(InitiateMove {
            keeps_note: 1,
            transact: &[1u8],
        }),
        &mut |_| Ok(()),
    )
    .unwrap();
}

/// The old stream and period layouts stay the sizes the funded notes already use.
#[test]
fn old_accounts_keep_their_lengths() {
    assert_eq!(STREAM_LEN, 104);
    assert_eq!(PERIOD_LEN, 72);
    assert_eq!(STREAM_TAG, 2);
    assert_ne!(VAULT_TAG, STREAM_TAG);
    assert_ne!(PAYROLL_TAG, STREAM_TAG);
    let mut stream = vec![0u8; STREAM_LEN];
    Stream::load(&mut stream).unwrap();
}

/// A second open fails and the first pool stays empty.
#[test]
fn a_vault_opens_once() {
    let mut data = fresh_vault();
    open_vault(&mut data, &vault_args()).unwrap();
    assert_eq!(data[0], VAULT_TAG);
    assert_eq!(Vault::load(&mut data).unwrap().live(), LIVE_EMPTY);
    let err = open_vault(&mut data, &vault_args()).unwrap_err();
    assert_eq!(err, pproll::PayrollError::AlreadyInitialized);
}

/// Deposit, join, and withdraw follow the one-note flag.
#[test]
fn the_pool_holds_one_note() {
    let mut data = fresh_vault();
    open_vault(&mut data, &vault_args()).unwrap();
    let err = join(
        &mut data,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(err, pproll::PayrollError::PoolEmpty);
    deposit(
        &mut data,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(Vault::load(&mut data).unwrap().live(), LIVE_NOTE);
    let err = deposit(
        &mut data,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(err, pproll::PayrollError::PoolOccupied);
    join(
        &mut data,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap();
    withdraw(
        &mut data,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(Vault::load(&mut data).unwrap().live(), LIVE_EMPTY);
}

/// Opening signs the employer on. Only the payee still has to accept.
#[test]
fn opening_counts_as_the_employer_approval() {
    let mut payroll = fresh_payroll();
    open_payroll(&mut payroll, &payroll_args()).unwrap();
    assert_eq!(payroll[2], 1);
    assert_eq!(payroll[3], 0);
    assert_eq!(payroll[4], 0);
    approve_payroll(&mut payroll, &wallet(2), 100).unwrap();
    assert_eq!(payroll[3], 1);
    assert_eq!(payroll[4], 1);
}

/// The employer cannot redeem. The payee waits for the milestone.
#[test]
fn only_the_payee_can_pay_and_only_at_the_milestone() {
    let mut payroll = fresh_payroll();
    let mut vault = fresh_vault();
    funded_payroll(&mut payroll, &mut vault);
    let employer = pay(
        &mut payroll,
        &wallet(9),
        &wallet(1),
        1_100,
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(employer, pproll::PayrollError::NotAParty);
    let early = pay(
        &mut payroll,
        &wallet(9),
        &wallet(2),
        1_099,
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(early, pproll::PayrollError::TooEarly);
    pay(
        &mut payroll,
        &wallet(9),
        &wallet(2),
        1_100,
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(PayrollAccount::load(&mut payroll).unwrap().next_redeem(), 1);
}

/// Stop blocks a later pay. Reclaim waits for that stop.
#[test]
fn reclaim_waits_until_stop() {
    let mut payroll = fresh_payroll();
    let mut vault = fresh_vault();
    funded_payroll(&mut payroll, &mut vault);
    let early = reclaim(
        &mut payroll,
        &wallet(9),
        &mut vault,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(early, pproll::PayrollError::StillActive);
    stop_payroll(&mut payroll, &wallet(1)).unwrap();
    let blocked = pay(
        &mut payroll,
        &wallet(9),
        &wallet(2),
        1_100,
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(blocked, pproll::PayrollError::Stopped);
    reclaim(
        &mut payroll,
        &wallet(9),
        &mut vault,
        &wallet(8),
        &wallet(1),
        Some(&SPP_ID),
        Some(move_ix()),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(PayrollAccount::load(&mut payroll).unwrap().status_byte(), 4);
    assert_eq!(Vault::load(&mut vault).unwrap().live(), LIVE_NOTE);
}
