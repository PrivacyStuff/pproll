use pproll::{
    approve, claim, claim_at, close, create, decline, fund, process, stop,
    CreateArgs, FundMove, Instruction, PayrollError, Period, Ring, Status, Stream, Wallets,
    CIRCUIT_PROOF_LEN, CREATE_IX_LEN, FUND_HEADER, MAX_OPEN, PERIOD_LEN, PERIOD_TAG, SPP_ID,
    STREAM_LEN, STREAM_TAG,
};

fn wallet(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn fresh_stream() -> Vec<u8> {
    vec![0u8; STREAM_LEN]
}

fn fresh_period() -> Vec<u8> {
    vec![0u8; PERIOD_LEN]
}

fn opened(data: &mut [u8]) {
    create(
        data,
        &CreateArgs {
            employer: wallet(1),
            employer_is_signer: true,
            employee: wallet(2),
            start_at: 1_000,
            approval_deadline: 900,
            period_secs: 100,
            ring: Ring::Permissionless,
            wallets: Wallets::Public,
        },
    )
    .unwrap();
}

fn frozen(data: &mut [u8]) {
    opened(data);
    approve(data, &wallet(1), 100).unwrap();
    approve(data, &wallet(2), 100).unwrap();
}

fn move_ix(stream: [u8; 32], index: u32, commitment: [u8; 32]) -> Vec<u8> {
    let mut ix = Vec::with_capacity(FUND_HEADER + CIRCUIT_PROOF_LEN + 1);
    ix.extend_from_slice(&stream);
    ix.extend_from_slice(&index.to_le_bytes());
    ix.extend_from_slice(&commitment);
    ix.extend(std::iter::repeat(0).take(CIRCUIT_PROOF_LEN + 1));
    ix
}

fn commitment(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Approval deadline after `start_at` is rejected and the account stays empty.
#[test]
fn rejects_a_deadline_after_the_start() {
    let err = create(
        &mut fresh_stream(),
        &CreateArgs {
            employer: wallet(1),
            employer_is_signer: true,
            employee: wallet(2),
            start_at: 100,
            approval_deadline: 101,
            period_secs: 50,
            ring: Ring::Permissionless,
            wallets: Wallets::Public,
        },
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::DeadlineAfterStart);
}

/// A zero or negative period is not a cadence.
#[test]
fn rejects_a_non_positive_period() {
    for period_secs in [0, -1] {
        let mut data = fresh_stream();
        let err = create(
            &mut data,
            &CreateArgs {
                employer: wallet(1),
                employer_is_signer: true,
                employee: wallet(2),
                start_at: 1_000,
                approval_deadline: 900,
                period_secs,
                ring: Ring::Permissionless,
                wallets: Wallets::Public,
            },
        )
        .unwrap_err();
        assert_eq!(err, PayrollError::BadPeriodSecs);
        assert_eq!(data[0], 0);
    }
}

/// A foreign owner never reaches create.
#[test]
fn rejects_an_account_this_program_does_not_own() {
    let err = process(
        Instruction::Create,
        false,
        &mut fresh_stream(),
        false,
        None,
        &wallet(9),
        &[0u8; CREATE_IX_LEN],
        &wallet(1),
        true,
        0,
        None,
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::BadAccount);
}

/// The same wallet cannot be both sides.
#[test]
fn the_employer_and_the_employee_cannot_be_the_same_wallet() {
    let err = create(
        &mut fresh_stream(),
        &CreateArgs {
            employer: wallet(1),
            employer_is_signer: true,
            employee: wallet(1),
            start_at: 1_000,
            approval_deadline: 900,
            period_secs: 100,
            ring: Ring::Permissionless,
            wallets: Wallets::Public,
        },
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::SameParty);
}

/// The other three create choices return an error and leave the account empty.
#[test]
fn wallet_privacy_is_an_option_on_both_rings_and_the_open_ones_do_not_initialize() {
    let mut permissionless_private = fresh_stream();
    let err = create(
        &mut permissionless_private,
        &CreateArgs {
            employer: wallet(1),
            employer_is_signer: true,
            employee: wallet(2),
            start_at: 1_000,
            approval_deadline: 900,
            period_secs: 100,
            ring: Ring::Permissionless,
            wallets: Wallets::Private,
        },
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::PermissionlessPublishesWallets);
    assert_eq!(permissionless_private[0], 0);

    for wallets in [Wallets::Public, Wallets::Private] {
        let mut custom = fresh_stream();
        let err = create(
            &mut custom,
            &CreateArgs {
                employer: wallet(1),
                employer_is_signer: true,
                employee: wallet(2),
                start_at: 1_000,
                approval_deadline: 900,
                period_secs: 100,
                ring: Ring::Custom,
                wallets,
            },
        )
        .unwrap_err();
        assert_eq!(err, PayrollError::CustomRingUnset);
        assert_eq!(custom[0], 0);
    }
}

/// A wallet that is neither party cannot approve.
#[test]
fn rejects_a_third_party_approval() {
    let mut data = fresh_stream();
    opened(&mut data);
    let err = approve(&mut data, &wallet(9), 100).unwrap_err();
    assert_eq!(err, PayrollError::NotAParty);
}

/// Approval at the deadline, or at `start_at`, is too late.
#[test]
fn rejects_approval_at_the_deadline_and_at_the_start() {
    let mut data = fresh_stream();
    opened(&mut data);
    assert_eq!(
        approve(&mut data, &wallet(1), 900).unwrap_err(),
        PayrollError::TooLate
    );
    assert_eq!(
        approve(&mut data, &wallet(1), 1_000).unwrap_err(),
        PayrollError::TooLate
    );
    assert_eq!(
        Stream::load(&mut data).unwrap().status().unwrap(),
        Status::Proposed
    );
}

/// The second approval freezes the schedule. A later approval does not rewrite it.
#[test]
fn the_second_approval_freezes_the_schedule() {
    let mut data = fresh_stream();
    opened(&mut data);
    let schedule = Stream::load(&mut data).unwrap().schedule_bytes();
    approve(&mut data, &wallet(1), 100).unwrap();
    assert!(!Stream::load(&mut data).unwrap().terms_frozen());
    approve(&mut data, &wallet(2), 100).unwrap();
    let stream = Stream::load(&mut data).unwrap();
    assert!(stream.terms_frozen());
    assert_eq!(stream.schedule_bytes(), schedule);
    assert_eq!(stream.tag(), STREAM_TAG);
    let again = create(
        &mut data,
        &CreateArgs {
            employer: wallet(1),
            employer_is_signer: true,
            employee: wallet(3),
            start_at: 5_000,
            approval_deadline: 4_000,
            period_secs: 10,
            ring: Ring::Permissionless,
            wallets: Wallets::Public,
        },
    )
    .unwrap_err();
    assert_eq!(again, PayrollError::AlreadyInitialized);
    assert_eq!(Stream::load(&mut data).unwrap().schedule_bytes(), schedule);
}

/// Decline closes an unfunded proposal and fails once a period is funded.
#[test]
fn decline_closes_the_proposal_and_a_funded_stream_cannot_be_declined() {
    let mut data = fresh_stream();
    opened(&mut data);
    decline(&mut data, &wallet(2), 100).unwrap();
    assert_eq!(
        Stream::load(&mut data).unwrap().status().unwrap(),
        Status::Closed
    );

    let mut funded = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut funded);
    fund(
        &mut funded,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(0, 3)),
        &mut |_| Ok(()),
    )
    .unwrap();
    let err = decline(&mut funded, &wallet(2), 100).unwrap_err();
    assert_eq!(err, PayrollError::AlreadyFinished);
    assert_eq!(Period::load(&mut period).unwrap().tag(), PERIOD_TAG);
}

/// An unfunded proposal can be closed. An active stream cannot, until it is stopped and caught up.
#[test]
fn close_recovers_an_unfunded_proposal_and_refuses_an_active_stream() {
    let mut proposed = fresh_stream();
    opened(&mut proposed);
    close(&mut proposed, &wallet(2)).unwrap();
    assert_eq!(
        Stream::load(&mut proposed).unwrap().status().unwrap(),
        Status::Closed
    );

    let mut active = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut active);
    fund_ok(&mut active, &mut period, 0, 4);
    let err = close(&mut active, &wallet(1)).unwrap_err();
    assert_eq!(err, PayrollError::Frozen);
    claim_ok(&mut active, &mut period, 0, 4, 1_100);
    let still_active = close(&mut active, &wallet(1)).unwrap_err();
    assert_eq!(still_active, PayrollError::StillActive);
    stop(&mut active, &wallet(1)).unwrap();
    close(&mut active, &wallet(2)).unwrap();
    assert_eq!(
        Stream::load(&mut active).unwrap().status().unwrap(),
        Status::Closed
    );
}

/// Any program id other than the privacy program fails and does not fund.
#[test]
fn fund_rejects_any_program_other_than_the_privacy_program_and_does_not_write() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    let wrong = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&[9u8; 32]),
        None,
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(wrong, PayrollError::WrongPrivacyProgram);
    assert_eq!(period[0], 0);
    assert_eq!(Stream::load(&mut data).unwrap().next_fund(), 0);
    assert_eq!(
        Stream::load(&mut data).unwrap().status().unwrap(),
        Status::Proposed
    );
}

/// The employee cannot fund. A missing payload does not write the period.
#[test]
fn fund_requires_the_employer_and_a_pool_payload() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    let employee = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(2),
        Some(&SPP_ID),
        None,
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(employee, PayrollError::NotAParty);

    let unwired = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        None,
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(unwired, PayrollError::PrivateLockNotWired);
    assert_eq!(period[0], 0);
}

/// One approval is not enough to fund.
#[test]
fn fund_waits_for_both_approvals() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    opened(&mut data);
    approve(&mut data, &wallet(1), 100).unwrap();
    let err = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(0, 3)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::NotBothApproved);
    assert_eq!(period[0], 0);
}

/// A failed invoke leaves the stream proposed and the period empty.
#[test]
fn a_failed_fund_invoke_does_not_write_the_commitment() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    let err = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(0, 3)),
        &mut |_| Err(PayrollError::InvokeFailed),
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::InvokeFailed);
    assert_eq!(period[0], 0);
    assert_eq!(Stream::load(&mut data).unwrap().next_fund(), 0);
    assert_eq!(
        Stream::load(&mut data).unwrap().status().unwrap(),
        Status::Proposed
    );
}

/// The first successful fund stores the commitment and opens the stream.
#[test]
fn fund_writes_the_commitment_only_after_the_invoke() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    let mut invoked = false;
    fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(0, 3)),
        &mut |_| {
            invoked = true;
            Ok(())
        },
    )
    .unwrap();
    assert!(invoked);
    let stream = Stream::load(&mut data).unwrap();
    assert_eq!(stream.status().unwrap(), Status::Active);
    assert_eq!(stream.next_fund(), 1);
    assert_eq!(stream.next_claim(), 0);
    let note = Period::load(&mut period).unwrap();
    assert_eq!(note.tag(), PERIOD_TAG);
    assert_eq!(note.index(), 0);
    assert_eq!(note.commitment(), commitment(3));
    assert_eq!(note.stream(), &wallet(7));
}

/// Index 1 cannot be funded while index 0 is the next fund. One past `MAX_OPEN` is refused.
#[test]
fn funds_are_sequential_and_stop_at_the_open_limit() {
    let mut data = fresh_stream();
    frozen(&mut data);
    let skipped = fund(
        &mut data,
        &mut fresh_period(),
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(1, 3)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(skipped, PayrollError::BadIndex);

    let mut periods = Vec::new();
    for index in 0..MAX_OPEN {
        let mut period = fresh_period();
        fund_ok(&mut data, &mut period, index, 10 + index as u8);
        periods.push(period);
    }
    let fifth = fund(
        &mut data,
        &mut fresh_period(),
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(MAX_OPEN, 9)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(fifth, PayrollError::TooManyOpen);
    assert_eq!(Stream::load(&mut data).unwrap().next_fund(), MAX_OPEN);
    assert_eq!(
        Period::load(&mut periods[0]).unwrap().commitment(),
        commitment(10)
    );
}

/// A claim before the period end does not spend the note. The employer cannot claim.
#[test]
fn claim_waits_for_the_period_end_and_the_employee() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    fund_ok(&mut data, &mut period, 0, 5);
    let early = claim(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(2),
        1_099,
        Some(&SPP_ID),
        Some(funded_move(0, 5)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(early, PayrollError::TooEarly);
    assert_eq!(claim_at(1_000, 100, 0).unwrap(), 1_100);

    let employer = claim(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        1_100,
        Some(&SPP_ID),
        Some(funded_move(0, 5)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(employer, PayrollError::NotAParty);
    assert_eq!(Stream::load(&mut data).unwrap().next_claim(), 0);
    assert_eq!(Period::load(&mut period).unwrap().status_byte(), 1);
}

/// A failed claim invoke leaves the note funded.
#[test]
fn a_failed_claim_invoke_leaves_the_note_funded() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    fund_ok(&mut data, &mut period, 0, 5);
    let err = claim(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(2),
        1_100,
        Some(&SPP_ID),
        Some(funded_move(0, 5)),
        &mut |_| Err(PayrollError::InvokeFailed),
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::InvokeFailed);
    assert_eq!(Stream::load(&mut data).unwrap().next_claim(), 0);
    assert_eq!(
        Period::load(&mut period).unwrap().commitment(),
        commitment(5)
    );
}

/// The employee claims the oldest note at the period end, and not the newer one first.
#[test]
fn claim_takes_the_oldest_funded_period_after_it_ends() {
    let mut data = fresh_stream();
    let mut first = fresh_period();
    let mut second = fresh_period();
    frozen(&mut data);
    fund_ok(&mut data, &mut first, 0, 5);
    fund_ok(&mut data, &mut second, 1, 6);
    let newer = claim(
        &mut data,
        &mut second,
        &wallet(7),
        &wallet(2),
        1_200,
        Some(&SPP_ID),
        Some(funded_move(1, 6)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(newer, PayrollError::BadIndex);

    claim_ok(&mut data, &mut first, 0, 5, 1_100);
    assert_eq!(Stream::load(&mut data).unwrap().next_claim(), 1);
    assert_eq!(Period::load(&mut first).unwrap().status_byte(), 2);
    assert_eq!(Period::load(&mut second).unwrap().status_byte(), 1);
    let still_early = claim(
        &mut data,
        &mut second,
        &wallet(7),
        &wallet(2),
        1_199,
        Some(&SPP_ID),
        Some(funded_move(1, 6)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(still_early, PayrollError::TooEarly);
}

/// Stop blocks the next fund and leaves the funded note claimable.
#[test]
fn stop_blocks_a_later_fund_and_does_not_touch_the_funded_note() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    fund_ok(&mut data, &mut period, 0, 8);
    let employee = stop(&mut data, &wallet(2)).unwrap_err();
    assert_eq!(employee, PayrollError::NotAParty);
    stop(&mut data, &wallet(1)).unwrap();
    let commitment_before = Period::load(&mut period).unwrap().commitment();
    let blocked = fund(
        &mut data,
        &mut fresh_period(),
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(1, 9)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(blocked, PayrollError::Stopped);
    assert_eq!(
        Period::load(&mut period).unwrap().commitment(),
        commitment_before
    );
    claim_ok(&mut data, &mut period, 0, 8, 1_100);
    assert_eq!(
        Stream::load(&mut data).unwrap().status().unwrap(),
        Status::Stopped
    );
    assert_eq!(Stream::load(&mut data).unwrap().next_claim(), 1);
}

/// A zero commitment is rejected. A proof for another stream is rejected.
#[test]
fn fund_rejects_a_zero_commitment_and_a_swapped_stream() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    let zero = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(0, 0)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(zero, PayrollError::BadAccount);

    let swapped = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move_for(wallet(8), 0, 4)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(swapped, PayrollError::ProofMismatch);
    assert_eq!(period[0], 0);
}

/// The period end has to fit. A huge cadence cannot be claimed.
#[test]
fn a_period_end_that_does_not_fit_is_rejected() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    create(
        &mut data,
        &CreateArgs {
            employer: wallet(1),
            employer_is_signer: true,
            employee: wallet(2),
            start_at: 1,
            approval_deadline: 0,
            period_secs: i64::MAX,
            ring: Ring::Permissionless,
            wallets: Wallets::Public,
        },
    )
    .unwrap();
    approve(&mut data, &wallet(1), -1).unwrap();
    approve(&mut data, &wallet(2), -1).unwrap();
    fund_ok(&mut data, &mut period, 0, 5);
    let err = claim(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(2),
        i64::MAX,
        Some(&SPP_ID),
        Some(funded_move(0, 5)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::Overflow);
    assert_eq!(Stream::load(&mut data).unwrap().next_claim(), 0);
}

/// A period that is already written is rejected before the pool is asked.
#[test]
fn fund_rejects_a_period_that_is_already_used() {
    let mut data = fresh_stream();
    let mut period = fresh_period();
    frozen(&mut data);
    fund_ok(&mut data, &mut period, 0, 3);
    let err = fund(
        &mut data,
        &mut period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(1, 4)),
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::AlreadyInitialized);
    assert_eq!(Stream::load(&mut data).unwrap().next_fund(), 1);
    assert_eq!(Period::load(&mut period).unwrap().index(), 0);
}
#[test]
fn fund_public_inputs_come_from_the_stream() {
    let short = pproll::proved_fund(&[0u8; 8], &wallet(7), 0).unwrap_err();
    assert_eq!(short, PayrollError::BadAccount);
    let mut data = fresh_stream();
    frozen(&mut data);
    let public = pproll::proved_fund(&data, &wallet(7), 0).unwrap();
    assert_eq!(public.employer, pproll::address_limbs(&wallet(1)));
    assert_eq!(public.stream, pproll::address_limbs(&wallet(7)));
    assert_eq!(public.index, 0);
}

/// A signer flag that is false is not a party, even when the address matches.
#[test]
fn a_matching_address_that_did_not_sign_is_rejected() {
    let mut data = fresh_stream();
    opened(&mut data);
    let err = process(
        Instruction::Approve,
        true,
        &mut data,
        false,
        None,
        &wallet(7),
        &[],
        &wallet(1),
        false,
        100,
        None,
        &mut |_| unreachable!(),
    )
    .unwrap_err();
    assert_eq!(err, PayrollError::NotAParty);
}

fn funded_move(index: u32, byte: u8) -> FundMove<'static> {
    funded_move_for(wallet(7), index, byte)
}

fn funded_move_for(stream: [u8; 32], index: u32, byte: u8) -> FundMove<'static> {
    let ix = Box::leak(move_ix(stream, index, commitment(byte)).into_boxed_slice());
    parse_leaked(ix)
}

fn parse_leaked(ix: &'static [u8]) -> FundMove<'static> {
    let mut stream = [0u8; 32];
    stream.copy_from_slice(&ix[0..32]);
    let mut index_bytes = [0u8; 4];
    index_bytes.copy_from_slice(&ix[32..36]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&ix[36..68]);
    FundMove {
        stream,
        index: u32::from_le_bytes(index_bytes),
        commitment,
        transact: &ix[FUND_HEADER + CIRCUIT_PROOF_LEN..],
    }
}

fn fund_ok(stream: &mut [u8], period: &mut [u8], index: u32, byte: u8) {
    fund(
        stream,
        period,
        &wallet(7),
        &wallet(1),
        Some(&SPP_ID),
        Some(funded_move(index, byte)),
        &mut |_| Ok(()),
    )
    .unwrap();
}

fn claim_ok(stream: &mut [u8], period: &mut [u8], index: u32, byte: u8, now: i64) {
    claim(
        stream,
        period,
        &wallet(7),
        &wallet(2),
        now,
        Some(&SPP_ID),
        Some(funded_move(index, byte)),
        &mut |_| Ok(()),
    )
    .unwrap();
}
