use crate::error::PayrollError;

/// Distinguishes a payroll stream from an empty account. Escrow uses tag 1 in its own program.
pub const STREAM_TAG: u8 = 2;
/// Distinguishes a period account from an empty buffer and from a stream.
pub const PERIOD_TAG: u8 = 3;

/// 0 tag, 1 status, 2 employer_approved, 3 employee_approved, 4 terms_frozen,
/// 5 ring, 6 wallets, 7 reserved (always 0 — a lock bump is per period, not stored here),
/// 8 start, 16 deadline, 24 period_secs, 32 employer, 64 employee, 96 next_fund, 100 next_claim.
pub const STREAM_LEN: usize = 104;
pub const PERIOD_LEN: usize = 72;
pub const COMMITMENT_LEN: usize = 32;

const OFF_TAG: usize = 0;
const OFF_STATUS: usize = 1;
const OFF_EMPLOYER_APPROVED: usize = 2;
const OFF_EMPLOYEE_APPROVED: usize = 3;
const OFF_TERMS_FROZEN: usize = 4;
const OFF_RING: usize = 5;
const OFF_WALLETS: usize = 6;
const OFF_START: usize = 8;
const OFF_DEADLINE: usize = 16;
const OFF_PERIOD: usize = 24;
const OFF_EMPLOYER: usize = 32;
const OFF_EMPLOYEE: usize = 64;
const OFF_NEXT_FUND: usize = 96;
const OFF_NEXT_CLAIM: usize = 100;

const PERIOD_OFF_TAG: usize = 0;
const PERIOD_OFF_STATUS: usize = 1;
const PERIOD_OFF_INDEX: usize = 4;
const PERIOD_OFF_STREAM: usize = 8;
const PERIOD_OFF_COMMIT: usize = 40;

/// Funded periods that may wait on a claim. Ten 0.01 notes fit, with room for the spare note.
/// A funded note cannot be cancelled, so this is not unbounded.
pub const MAX_OPEN: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Proposed = 1,
    Active = 2,
    Stopped = 3,
    Closed = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PeriodStatus {
    Funded = 1,
    Claimed = 2,
}

/// Which pool the notes use. Independent of whether the wallets are public.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ring {
    Permissionless = 1,
    Custom = 2,
}

/// Public stores the two wallets. Private stores commitments of the same size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Wallets {
    Public = 1,
    Private = 2,
}

pub struct Stream<'a> {
    data: &'a mut [u8],
}

impl<'a> Stream<'a> {
    /// Rejects any buffer that is not the 104-byte stream.
    pub fn load(data: &'a mut [u8]) -> Result<Self, PayrollError> {
        if data.len() != STREAM_LEN {
            return Err(PayrollError::BadAccount);
        }
        Ok(Self { data })
    }

    /// Opens permissionless plus public wallets only. A second create fails.
    /// The reserved byte stays 0. The lock PDA bump depends on the period index, so it is not stored.
    pub fn create(
        &mut self,
        employer: &[u8; 32],
        employee: &[u8; 32],
        start_at: i64,
        approval_deadline: i64,
        period_secs: i64,
        ring: Ring,
        wallets: Wallets,
    ) -> Result<(), PayrollError> {
        if self.data[OFF_TAG] != 0 {
            return Err(PayrollError::AlreadyInitialized);
        }
        if approval_deadline > start_at {
            return Err(PayrollError::DeadlineAfterStart);
        }
        if period_secs <= 0 {
            return Err(PayrollError::BadPeriodSecs);
        }
        if employer == employee {
            return Err(PayrollError::SameParty);
        }
        match (ring, wallets) {
            (Ring::Permissionless, Wallets::Private) => {
                return Err(PayrollError::PermissionlessPublishesWallets);
            }
            (Ring::Custom, Wallets::Public | Wallets::Private) => {
                return Err(PayrollError::CustomRingUnset);
            }
            (Ring::Permissionless, Wallets::Public) => {}
        }
        self.data[OFF_TAG] = STREAM_TAG;
        self.data[OFF_STATUS] = Status::Proposed as u8;
        self.data[OFF_RING] = ring as u8;
        self.data[OFF_WALLETS] = wallets as u8;
        write_i64(self.data, OFF_START, start_at);
        write_i64(self.data, OFF_DEADLINE, approval_deadline);
        write_i64(self.data, OFF_PERIOD, period_secs);
        self.data[OFF_EMPLOYER..OFF_EMPLOYER + 32].copy_from_slice(employer);
        self.data[OFF_EMPLOYEE..OFF_EMPLOYEE + 32].copy_from_slice(employee);
        Ok(())
    }

    /// One party signs, once, strictly before the approval deadline and `start_at`.
    /// Does not write the schedule. The second approval freezes the terms.
    pub fn approve(&mut self, signer: &[u8; 32], now: i64) -> Result<(), PayrollError> {
        self.require_proposed_window(now)?;
        match self.side(signer)? {
            Side::Employer => self.data[OFF_EMPLOYER_APPROVED] = 1,
            Side::Employee => self.data[OFF_EMPLOYEE_APPROVED] = 1,
        }
        if self.both_approved() {
            self.data[OFF_TERMS_FROZEN] = 1;
        }
        Ok(())
    }

    /// Voids a proposal that has not been funded. Rent is recovered by `close`.
    pub fn decline(&mut self, signer: &[u8; 32], now: i64) -> Result<(), PayrollError> {
        self.require_proposed_window(now)?;
        if self.next_fund() != 0 {
            return Err(PayrollError::Frozen);
        }
        let _ = self.side(signer)?;
        self.data[OFF_STATUS] = Status::Closed as u8;
        Ok(())
    }

    /// Employer, employee, frozen terms, and room under `MAX_OPEN`. Writes nothing.
    pub fn fund_ready(&self, signer: &[u8; 32]) -> Result<u32, PayrollError> {
        self.require_tag()?;
        if signer != self.employer() {
            return Err(PayrollError::NotAParty);
        }
        if !self.terms_frozen() {
            return Err(PayrollError::NotBothApproved);
        }
        match self.status_known()? {
            Status::Proposed | Status::Active => {}
            Status::Stopped => return Err(PayrollError::Stopped),
            Status::Closed => return Err(PayrollError::AlreadyFinished),
        }
        let open = self
            .next_fund()
            .checked_sub(self.next_claim())
            .ok_or(PayrollError::BadAccount)?;
        if open >= MAX_OPEN {
            return Err(PayrollError::TooManyOpen);
        }
        Ok(self.next_fund())
    }

    /// Writes the period, then advances `next_fund`. Call only after the pool invoke returns.
    pub fn commit_fund(
        &mut self,
        period: &mut Period<'_>,
        stream: &[u8; 32],
        index: u32,
        commitment: &[u8; COMMITMENT_LEN],
    ) -> Result<(), PayrollError> {
        let employer = *self.employer();
        if self.fund_ready(&employer)? != index {
            return Err(PayrollError::BadIndex);
        }
        let next = index.checked_add(1).ok_or(PayrollError::Overflow)?;
        period.init(stream, index, commitment)?;
        write_u32(self.data, OFF_NEXT_FUND, next);
        if self.data[OFF_STATUS] == Status::Proposed as u8 {
            self.data[OFF_STATUS] = Status::Active as u8;
        }
        Ok(())
    }

    /// Employee, this index, and the clock at or after the period end. Writes nothing.
    pub fn claim_ready(
        &self,
        signer: &[u8; 32],
        index: u32,
        now: i64,
    ) -> Result<i64, PayrollError> {
        self.require_tag()?;
        if signer != self.employee() {
            return Err(PayrollError::NotAParty);
        }
        match self.status_known()? {
            Status::Active | Status::Stopped => {}
            Status::Proposed => return Err(PayrollError::NotFunded),
            Status::Closed => return Err(PayrollError::AlreadyFinished),
        }
        if index != self.next_claim() {
            return Err(PayrollError::BadIndex);
        }
        if self.next_claim() >= self.next_fund() {
            return Err(PayrollError::NotFunded);
        }
        let due = claim_at(self.start_at(), self.period_secs(), index)?;
        if now < due {
            return Err(PayrollError::TooEarly);
        }
        Ok(due)
    }

    /// Marks the period claimed and advances `next_claim`. Call only after the pool invoke returns.
    pub fn commit_claim(
        &mut self,
        period: &mut Period<'_>,
        stream: &[u8; 32],
        index: u32,
        commitment: &[u8; COMMITMENT_LEN],
    ) -> Result<(), PayrollError> {
        period.require_claim(stream, index, commitment)?;
        let next = index.checked_add(1).ok_or(PayrollError::Overflow)?;
        if next
            != self
                .next_claim()
                .checked_add(1)
                .ok_or(PayrollError::Overflow)?
        {
            return Err(PayrollError::BadIndex);
        }
        period.mark_claimed()?;
        write_u32(self.data, OFF_NEXT_CLAIM, next);
        Ok(())
    }

    /// Employer ends future funds. Funded notes stay claimable.
    pub fn stop(&mut self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_tag()?;
        if signer != self.employer() {
            return Err(PayrollError::NotAParty);
        }
        if self.data[OFF_STATUS] != Status::Active as u8 {
            return Err(PayrollError::NotActive);
        }
        self.data[OFF_STATUS] = Status::Stopped as u8;
        Ok(())
    }

    /// Sets `Closed` when nothing is unclaimed and the stream is not still `Active`.
    /// `Closed` is accepted again so a wiped close can be retried after decline.
    pub fn close(&mut self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.close_ready(signer)?;
        self.data[OFF_STATUS] = Status::Closed as u8;
        Ok(())
    }

    /// Either party. `Active` must `stop` first. A funded note blocks the close.
    pub fn close_ready(&self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_tag()?;
        let _ = self.side(signer)?;
        if self.next_fund() != self.next_claim() {
            return Err(PayrollError::Frozen);
        }
        match self.status_known()? {
            Status::Proposed | Status::Stopped | Status::Closed => Ok(()),
            Status::Active => Err(PayrollError::StillActive),
        }
    }

    /// Wallet that pays. Public on this path.
    pub fn employer(&self) -> &[u8; 32] {
        self.party(OFF_EMPLOYER)
    }

    /// Wallet that claims. Public on this path.
    pub fn employee(&self) -> &[u8; 32] {
        self.party(OFF_EMPLOYEE)
    }

    /// `STREAM_TAG` once `create` has written the account.
    pub fn tag(&self) -> u8 {
        self.data[OFF_TAG]
    }

    /// `Proposed`, `Active`, `Stopped`, or `Closed`. A corrupt byte is `BadAccount`.
    pub fn status(&self) -> Result<Status, PayrollError> {
        self.status_known()
    }

    fn status_known(&self) -> Result<Status, PayrollError> {
        match self.data[OFF_STATUS] {
            1 => Ok(Status::Proposed),
            2 => Ok(Status::Active),
            3 => Ok(Status::Stopped),
            4 => Ok(Status::Closed),
            _ => Err(PayrollError::BadAccount),
        }
    }

    /// Raw status byte, including a corrupt value the typed getter would hide.
    pub fn status_byte(&self) -> u8 {
        self.data[OFF_STATUS]
    }

    /// Unix time of period 0. Public.
    pub fn start_at(&self) -> i64 {
        i64_at(self.data, OFF_START)
    }

    /// Length of every period. Public. Frozen at create.
    pub fn period_secs(&self) -> i64 {
        i64_at(self.data, OFF_PERIOD)
    }

    /// Both approval bytes are 1 and `terms_frozen` is set.
    pub fn terms_frozen(&self) -> bool {
        self.data[OFF_TERMS_FROZEN] == 1 && self.both_approved()
    }

    /// Next index `fund` must use.
    pub fn next_fund(&self) -> u32 {
        u32_at(self.data, OFF_NEXT_FUND)
    }

    /// Next index `claim` must use.
    pub fn next_claim(&self) -> u32 {
        u32_at(self.data, OFF_NEXT_CLAIM)
    }

    /// The eight schedule bytes `approve` must not rewrite.
    pub fn schedule_bytes(&self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes.copy_from_slice(&self.data[OFF_START..OFF_EMPLOYER]);
        bytes
    }

    fn require_tag(&self) -> Result<(), PayrollError> {
        if self.data[OFF_TAG] != STREAM_TAG {
            return Err(PayrollError::NotInitialized);
        }
        Ok(())
    }

    fn require_proposed_window(&mut self, now: i64) -> Result<(), PayrollError> {
        self.require_tag()?;
        if self.data[OFF_STATUS] != Status::Proposed as u8 {
            return Err(PayrollError::AlreadyFinished);
        }
        if now >= self.approval_deadline() || now >= self.start_at() {
            return Err(PayrollError::TooLate);
        }
        Ok(())
    }

    fn both_approved(&self) -> bool {
        self.data[OFF_EMPLOYER_APPROVED] == 1 && self.data[OFF_EMPLOYEE_APPROVED] == 1
    }

    fn side(&self, signer: &[u8; 32]) -> Result<Side, PayrollError> {
        if signer == self.party(OFF_EMPLOYER) {
            Ok(Side::Employer)
        } else if signer == self.party(OFF_EMPLOYEE) {
            Ok(Side::Employee)
        } else {
            Err(PayrollError::NotAParty)
        }
    }

    fn party(&self, offset: usize) -> &[u8; 32] {
        self.data[offset..offset + 32]
            .try_into()
            .expect("party field is 32 bytes")
    }

    fn approval_deadline(&self) -> i64 {
        i64_at(self.data, OFF_DEADLINE)
    }
}

pub struct Period<'a> {
    data: &'a mut [u8],
}

impl<'a> Period<'a> {
    /// Rejects any buffer that is not the 72-byte period.
    pub fn load(data: &'a mut [u8]) -> Result<Self, PayrollError> {
        if data.len() != PERIOD_LEN {
            return Err(PayrollError::BadAccount);
        }
        Ok(Self { data })
    }

    /// First write of a funded note. A zero commitment is rejected.
    pub fn init(
        &mut self,
        stream: &[u8; 32],
        index: u32,
        commitment: &[u8; COMMITMENT_LEN],
    ) -> Result<(), PayrollError> {
        if self.data[PERIOD_OFF_TAG] != 0 {
            return Err(PayrollError::AlreadyInitialized);
        }
        if commitment == &[0u8; COMMITMENT_LEN] {
            return Err(PayrollError::BadAccount);
        }
        self.data[PERIOD_OFF_TAG] = PERIOD_TAG;
        self.data[PERIOD_OFF_STATUS] = PeriodStatus::Funded as u8;
        write_u32(self.data, PERIOD_OFF_INDEX, index);
        self.data[PERIOD_OFF_STREAM..PERIOD_OFF_STREAM + 32].copy_from_slice(stream);
        self.data[PERIOD_OFF_COMMIT..PERIOD_OFF_COMMIT + COMMITMENT_LEN]
            .copy_from_slice(commitment);
        Ok(())
    }

    /// This stream, this index, funded, and the stored commitment.
    pub fn require_claim(
        &self,
        stream: &[u8; 32],
        index: u32,
        commitment: &[u8; COMMITMENT_LEN],
    ) -> Result<(), PayrollError> {
        if self.data[PERIOD_OFF_TAG] != PERIOD_TAG {
            return Err(PayrollError::NotInitialized);
        }
        if self.data[PERIOD_OFF_STATUS] != PeriodStatus::Funded as u8 {
            return Err(PayrollError::BadPeriod);
        }
        if self.stream() != stream || self.index() != index {
            return Err(PayrollError::ProofMismatch);
        }
        if self.commitment() == [0u8; COMMITMENT_LEN] {
            return Err(PayrollError::MissingCommitment);
        }
        if self.commitment() != *commitment {
            return Err(PayrollError::ProofMismatch);
        }
        Ok(())
    }

    /// Sets the claimed byte. Does not return the rent. The entrypoint does that.
    pub fn mark_claimed(&mut self) -> Result<(), PayrollError> {
        if self.data[PERIOD_OFF_TAG] != PERIOD_TAG {
            return Err(PayrollError::NotInitialized);
        }
        if self.data[PERIOD_OFF_STATUS] != PeriodStatus::Funded as u8 {
            return Err(PayrollError::BadPeriod);
        }
        self.data[PERIOD_OFF_STATUS] = PeriodStatus::Claimed as u8;
        Ok(())
    }

    /// `PERIOD_TAG` once `init` has written the account.
    pub fn tag(&self) -> u8 {
        self.data[PERIOD_OFF_TAG]
    }

    /// `Funded` or `Claimed`.
    pub fn status_byte(&self) -> u8 {
        self.data[PERIOD_OFF_STATUS]
    }

    /// Period index written at fund.
    pub fn index(&self) -> u32 {
        u32_at(self.data, PERIOD_OFF_INDEX)
    }

    /// Stream this note belongs to.
    pub fn stream(&self) -> &[u8; 32] {
        self.data[PERIOD_OFF_STREAM..PERIOD_OFF_STREAM + 32]
            .try_into()
            .expect("stream field is 32 bytes")
    }

    /// Output note from the fund. Zero until that invoke succeeds.
    pub fn commitment(&self) -> [u8; COMMITMENT_LEN] {
        let mut commitment = [0u8; COMMITMENT_LEN];
        commitment
            .copy_from_slice(&self.data[PERIOD_OFF_COMMIT..PERIOD_OFF_COMMIT + COMMITMENT_LEN]);
        commitment
    }
}

/// One shielded pool per user. Not a stream and not a period.
pub const VAULT_TAG: u8 = 4;
/// One employment. The note PDA is separate from this account.
pub const PAYROLL_TAG: u8 = 5;
/// X25519 viewing public key, tag byte plus the 32-byte coordinate.
pub const VIEWING_LEN: usize = 33;
/// Poseidon owner hash. It fits in the field, unlike a raw pubkey.
pub const OWNER_HASH_LEN: usize = 32;

/// 0 tag, 1 live note (0 empty, 1 one note), 8 owner, 40 owner hash, 72 viewing key.
pub const VAULT_LEN: usize = 112;
/// Schedule, parties, both commitments, the note owner hash, the payee owner hash, the viewing key, `next_redeem`.
pub const PAYROLL_LEN: usize = 264;

const VAULT_OFF_LIVE: usize = 1;
const VAULT_OFF_OWNER: usize = 8;
const VAULT_OFF_HASH: usize = 40;
const VAULT_OFF_VIEW: usize = 72;

const PAY_OFF_STATUS: usize = 1;
const PAY_OFF_EMPLOYER_APPROVED: usize = 2;
const PAY_OFF_PAYEE_APPROVED: usize = 3;
const PAY_OFF_FROZEN: usize = 4;
const PAY_OFF_RING: usize = 5;
const PAY_OFF_WALLETS: usize = 6;
const PAY_OFF_START: usize = 8;
const PAY_OFF_DEADLINE: usize = 16;
const PAY_OFF_PERIOD: usize = 24;
const PAY_OFF_EMPLOYER: usize = 32;
const PAY_OFF_PAYEE: usize = 64;
const PAY_OFF_PAYEE_HASH: usize = 96;
const PAY_OFF_NOTE_HASH: usize = 128;
const PAY_OFF_INSTALLMENT: usize = 160;
const PAY_OFF_BUDGET: usize = 192;
const PAY_OFF_VIEW: usize = 224;
const PAY_OFF_NEXT: usize = 260;

/// The vault has no note, or it already has one.
pub const LIVE_EMPTY: u8 = 0;
pub const LIVE_NOTE: u8 = 1;

pub struct Vault<'a> {
    data: &'a mut [u8],
}

pub struct OpenVault {
    pub owner: [u8; 32],
    pub owner_hash: [u8; OWNER_HASH_LEN],
    pub viewing: [u8; VIEWING_LEN],
}

pub struct PayrollAccount<'a> {
    data: &'a mut [u8],
}

pub struct OpenPayroll {
    pub employer: [u8; 32],
    pub payee: [u8; 32],
    pub payee_hash: [u8; OWNER_HASH_LEN],
    pub note_hash: [u8; OWNER_HASH_LEN],
    pub installment: [u8; COMMITMENT_LEN],
    pub budget: [u8; COMMITMENT_LEN],
    pub viewing: [u8; VIEWING_LEN],
    pub start_at: i64,
    pub approval_deadline: i64,
    pub period_secs: i64,
    pub ring: Ring,
    pub wallets: Wallets,
}

impl<'a> Vault<'a> {
    /// Rejects any buffer that is not the vault length.
    pub fn load(data: &'a mut [u8]) -> Result<Self, PayrollError> {
        if data.len() != VAULT_LEN {
            return Err(PayrollError::BadAccount);
        }
        Ok(Self { data })
    }

    /// The owner opens an empty pool. A second open fails.
    pub fn open(&mut self, args: &OpenVault) -> Result<(), PayrollError> {
        if self.data[OFF_TAG] != 0 {
            return Err(PayrollError::AlreadyInitialized);
        }
        if args.owner_hash == [0u8; OWNER_HASH_LEN] || args.viewing[0] != 4 {
            return Err(PayrollError::BadAccount);
        }
        self.data[OFF_TAG] = VAULT_TAG;
        self.data[VAULT_OFF_LIVE] = LIVE_EMPTY;
        self.data[VAULT_OFF_OWNER..VAULT_OFF_OWNER + 32].copy_from_slice(&args.owner);
        self.data[VAULT_OFF_HASH..VAULT_OFF_HASH + OWNER_HASH_LEN].copy_from_slice(&args.owner_hash);
        self.data[VAULT_OFF_VIEW..VAULT_OFF_VIEW + VIEWING_LEN].copy_from_slice(&args.viewing);
        Ok(())
    }

    /// `deposit` only. The pool already has a note.
    pub fn deposit_ready(&self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_owner(signer)?;
        if self.live() != LIVE_EMPTY {
            return Err(PayrollError::PoolOccupied);
        }
        Ok(())
    }

    /// `join`, `withdraw`, and `initiate` only. The pool has one note.
    pub fn spend_ready(&self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_owner(signer)?;
        if self.live() != LIVE_NOTE {
            return Err(PayrollError::PoolEmpty);
        }
        Ok(())
    }

    /// Writes the live-note byte after the pool invoke returns.
    pub fn set_live(&mut self, live: u8) -> Result<(), PayrollError> {
        self.require_tag()?;
        if live != LIVE_EMPTY && live != LIVE_NOTE {
            return Err(PayrollError::BadAccount);
        }
        self.data[VAULT_OFF_LIVE] = live;
        Ok(())
    }

    /// Solana wallet that owns the pool.
    pub fn owner(&self) -> &[u8; 32] {
        self.field32(VAULT_OFF_OWNER)
    }

    /// Shielded owner hash of this pool's PDA.
    pub fn owner_hash(&self) -> [u8; OWNER_HASH_LEN] {
        self.bytes32(VAULT_OFF_HASH)
    }

    /// `0` empty, `1` one live note.
    pub fn live(&self) -> u8 {
        self.data[VAULT_OFF_LIVE]
    }

    fn require_owner(&self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_tag()?;
        if signer != self.owner() {
            return Err(PayrollError::NotAParty);
        }
        Ok(())
    }

    fn require_tag(&self) -> Result<(), PayrollError> {
        if self.data[OFF_TAG] != VAULT_TAG {
            return Err(PayrollError::NotInitialized);
        }
        Ok(())
    }

    fn field32(&self, offset: usize) -> &[u8; 32] {
        self.data[offset..offset + 32]
            .try_into()
            .expect("32-byte field")
    }

    fn bytes32(&self, offset: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[offset..offset + 32]);
        out
    }
}

impl<'a> PayrollAccount<'a> {
    /// Rejects any buffer that is not the payroll length.
    pub fn load(data: &'a mut [u8]) -> Result<Self, PayrollError> {
        if data.len() != PAYROLL_LEN {
            return Err(PayrollError::BadAccount);
        }
        Ok(Self { data })
    }

    /// The employer writes the terms. Signing this open is the employer's approval.
    pub fn open(&mut self, args: &OpenPayroll) -> Result<(), PayrollError> {
        if self.data[OFF_TAG] != 0 {
            return Err(PayrollError::AlreadyInitialized);
        }
        if args.approval_deadline > args.start_at {
            return Err(PayrollError::DeadlineAfterStart);
        }
        if args.period_secs <= 0 {
            return Err(PayrollError::BadPeriodSecs);
        }
        if args.employer == args.payee {
            return Err(PayrollError::SameParty);
        }
        if args.installment == [0u8; COMMITMENT_LEN]
            || args.budget == [0u8; COMMITMENT_LEN]
            || args.payee_hash == [0u8; OWNER_HASH_LEN]
            || args.note_hash == [0u8; OWNER_HASH_LEN]
            || args.viewing[0] != 4
        {
            return Err(PayrollError::BadAccount);
        }
        match (args.ring, args.wallets) {
            (Ring::Permissionless, Wallets::Private) => {
                return Err(PayrollError::PermissionlessPublishesWallets);
            }
            (Ring::Custom, _) => return Err(PayrollError::CustomRingUnset),
            (Ring::Permissionless, Wallets::Public) => {}
        }
        self.data[OFF_TAG] = PAYROLL_TAG;
        self.data[PAY_OFF_STATUS] = Status::Proposed as u8;
        self.data[PAY_OFF_EMPLOYER_APPROVED] = 1;
        self.data[PAY_OFF_RING] = args.ring as u8;
        self.data[PAY_OFF_WALLETS] = args.wallets as u8;
        write_i64(self.data, PAY_OFF_START, args.start_at);
        write_i64(self.data, PAY_OFF_DEADLINE, args.approval_deadline);
        write_i64(self.data, PAY_OFF_PERIOD, args.period_secs);
        self.data[PAY_OFF_EMPLOYER..PAY_OFF_EMPLOYER + 32].copy_from_slice(&args.employer);
        self.data[PAY_OFF_PAYEE..PAY_OFF_PAYEE + 32].copy_from_slice(&args.payee);
        self.data[PAY_OFF_PAYEE_HASH..PAY_OFF_PAYEE_HASH + 32].copy_from_slice(&args.payee_hash);
        self.data[PAY_OFF_NOTE_HASH..PAY_OFF_NOTE_HASH + 32].copy_from_slice(&args.note_hash);
        self.data[PAY_OFF_INSTALLMENT..PAY_OFF_INSTALLMENT + 32].copy_from_slice(&args.installment);
        self.data[PAY_OFF_BUDGET..PAY_OFF_BUDGET + 32].copy_from_slice(&args.budget);
        self.data[PAY_OFF_VIEW..PAY_OFF_VIEW + VIEWING_LEN].copy_from_slice(&args.viewing);
        Ok(())
    }

    /// One party, once, strictly before the deadline and `start_at`.
    pub fn approve(&mut self, signer: &[u8; 32], now: i64) -> Result<(), PayrollError> {
        self.require_tag()?;
        if self.data[PAY_OFF_STATUS] != Status::Proposed as u8 {
            return Err(PayrollError::AlreadyFinished);
        }
        if now >= self.deadline() || now >= self.start_at() {
            return Err(PayrollError::TooLate);
        }
        match self.side(signer)? {
            Side::Employer => self.data[PAY_OFF_EMPLOYER_APPROVED] = 1,
            Side::Employee => self.data[PAY_OFF_PAYEE_APPROVED] = 1,
        }
        if self.data[PAY_OFF_EMPLOYER_APPROVED] == 1 && self.data[PAY_OFF_PAYEE_APPROVED] == 1 {
            self.data[PAY_OFF_FROZEN] = 1;
        }
        Ok(())
    }

    /// Frozen terms, still `Proposed`. The employer has not locked the budget yet.
    pub fn initiate_ready(&self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_tag()?;
        if signer != self.employer() {
            return Err(PayrollError::NotAParty);
        }
        if self.data[PAY_OFF_FROZEN] != 1 {
            return Err(PayrollError::NotBothApproved);
        }
        if self.data[PAY_OFF_STATUS] != Status::Proposed as u8 {
            return Err(PayrollError::AlreadyInitialized);
        }
        Ok(())
    }

    /// The budget note exists. Call only after the pool invoke returns.
    pub fn mark_funded(&mut self) -> Result<(), PayrollError> {
        let employer = *self.employer();
        self.initiate_ready(&employer)?;
        self.data[PAY_OFF_STATUS] = Status::Active as u8;
        Ok(())
    }

    /// The payee, this index, and the clock at or after the milestone.
    pub fn pay_ready(&self, signer: &[u8; 32], now: i64) -> Result<i64, PayrollError> {
        self.require_tag()?;
        if signer != self.payee() {
            return Err(PayrollError::NotAParty);
        }
        if self.data[PAY_OFF_STATUS] == Status::Stopped as u8 {
            return Err(PayrollError::Stopped);
        }
        if self.data[PAY_OFF_STATUS] != Status::Active as u8 {
            return Err(PayrollError::NotFunded);
        }
        let due = claim_at(self.start_at(), self.period_secs(), self.next_redeem())?;
        if now < due {
            return Err(PayrollError::TooEarly);
        }
        Ok(due)
    }

    /// Advances `next_redeem` after the pool pays the installment.
    pub fn commit_pay(&mut self) -> Result<(), PayrollError> {
        let next = self.next_redeem().checked_add(1).ok_or(PayrollError::Overflow)?;
        write_u32(self.data, PAY_OFF_NEXT, next);
        Ok(())
    }

    /// The employer blocks later pays. The budget note stays until `reclaim`.
    pub fn stop(&mut self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_tag()?;
        if signer != self.employer() {
            return Err(PayrollError::NotAParty);
        }
        if self.data[PAY_OFF_STATUS] != Status::Active as u8 {
            return Err(PayrollError::NotActive);
        }
        self.data[PAY_OFF_STATUS] = Status::Stopped as u8;
        Ok(())
    }

    /// `Stopped` only. The remainder goes back to the employer's pool.
    pub fn reclaim_ready(&self, signer: &[u8; 32]) -> Result<(), PayrollError> {
        self.require_tag()?;
        if signer != self.employer() {
            return Err(PayrollError::NotAParty);
        }
        if self.data[PAY_OFF_STATUS] != Status::Stopped as u8 {
            return Err(PayrollError::StillActive);
        }
        Ok(())
    }

    /// Marks the payroll closed after the remainder has moved.
    pub fn mark_reclaimed(&mut self) -> Result<(), PayrollError> {
        let employer = *self.employer();
        self.reclaim_ready(&employer)?;
        self.data[PAY_OFF_STATUS] = Status::Closed as u8;
        Ok(())
    }

    pub fn employer(&self) -> &[u8; 32] {
        self.field32(PAY_OFF_EMPLOYER)
    }

    pub fn payee(&self) -> &[u8; 32] {
        self.field32(PAY_OFF_PAYEE)
    }

    pub fn payee_hash(&self) -> [u8; OWNER_HASH_LEN] {
        self.bytes32(PAY_OFF_PAYEE_HASH)
    }

    pub fn note_hash(&self) -> [u8; OWNER_HASH_LEN] {
        self.bytes32(PAY_OFF_NOTE_HASH)
    }

    pub fn installment(&self) -> [u8; COMMITMENT_LEN] {
        self.bytes32(PAY_OFF_INSTALLMENT)
    }

    pub fn budget(&self) -> [u8; COMMITMENT_LEN] {
        self.bytes32(PAY_OFF_BUDGET)
    }

    pub fn start_at(&self) -> i64 {
        i64_at(self.data, PAY_OFF_START)
    }

    pub fn period_secs(&self) -> i64 {
        i64_at(self.data, PAY_OFF_PERIOD)
    }

    pub fn next_redeem(&self) -> u32 {
        u32_at(self.data, PAY_OFF_NEXT)
    }

    pub fn status_byte(&self) -> u8 {
        self.data[PAY_OFF_STATUS]
    }

    fn deadline(&self) -> i64 {
        i64_at(self.data, PAY_OFF_DEADLINE)
    }

    fn require_tag(&self) -> Result<(), PayrollError> {
        if self.data[OFF_TAG] != PAYROLL_TAG {
            return Err(PayrollError::NotInitialized);
        }
        Ok(())
    }

    fn side(&self, signer: &[u8; 32]) -> Result<Side, PayrollError> {
        if signer == self.employer() {
            Ok(Side::Employer)
        } else if signer == self.payee() {
            Ok(Side::Employee)
        } else {
            Err(PayrollError::NotAParty)
        }
    }

    fn field32(&self, offset: usize) -> &[u8; 32] {
        self.data[offset..offset + 32]
            .try_into()
            .expect("32-byte field")
    }

    fn bytes32(&self, offset: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[offset..offset + 32]);
        out
    }
}

/// Period `index` becomes claimable at `start_at + (index + 1) * period_secs`.
pub fn claim_at(start_at: i64, period_secs: i64, index: u32) -> Result<i64, PayrollError> {
    let step = i64::from(index)
        .checked_add(1)
        .ok_or(PayrollError::Overflow)?;
    let span = step
        .checked_mul(period_secs)
        .ok_or(PayrollError::Overflow)?;
    start_at.checked_add(span).ok_or(PayrollError::Overflow)
}

#[derive(Clone, Copy)]
enum Side {
    Employer,
    Employee,
}

fn write_i64(data: &mut [u8], offset: usize, value: i64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn i64_at(data: &[u8], offset: usize) -> i64 {
    let bytes: [u8; 8] = data[offset..offset + 8]
        .try_into()
        .expect("i64 field is 8 bytes");
    i64::from_le_bytes(bytes)
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    let bytes: [u8; 4] = data[offset..offset + 4]
        .try_into()
        .expect("u32 field is 4 bytes");
    u32::from_le_bytes(bytes)
}
