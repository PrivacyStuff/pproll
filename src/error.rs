/// Failures a caller can hit. Custom codes start at 100 so they do not collide
/// with the runtime's `ProgramError` discriminants when mapped at the entrypoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayrollError {
    /// `approval_deadline` is after `start_at`.
    DeadlineAfterStart = 100,
    /// Employer and employee are the same wallet.
    SameParty = 101,
    /// The signer is not the employer or the employee, or the account did not sign.
    NotAParty = 102,
    /// The account was already created, or the period was already funded.
    AlreadyInitialized = 103,
    /// The tag byte is still zero.
    NotInitialized = 104,
    /// Approval or decline is at or after the deadline or `start_at`.
    TooLate = 105,
    /// `fund` ran before both parties had approved.
    NotBothApproved = 106,
    /// `claim` ran before `start_at + (index + 1) * period_secs`.
    TooEarly = 107,
    /// The stream is `Closed`.
    AlreadyFinished = 108,
    /// The CPI program id is not the Solana Privacy Program.
    WrongPrivacyProgram = 109,
    /// The instruction carried no pool payload.
    PrivateLockNotWired = 110,
    /// The account length, owner, or an instruction byte is wrong.
    BadAccount = 111,
    /// The permissionless ring prints both wallets. Private wallets there would be a false hide.
    PermissionlessPublishesWallets = 112,
    /// A custom ring is a real option. Create waits until that ring's program id is set.
    CustomRingUnset = 113,
    /// The proof's public inputs are not this stream, this period, or this commitment.
    ProofMismatch = 114,
    /// No verifying key has been built for this circuit. The invoke does not run.
    ProofKeyMissing = 115,
    /// The shielded-pool invoke failed. The period was not written.
    InvokeFailed = 116,
    /// A funded period has no output commitment to spend.
    MissingCommitment = 117,
    /// The circuit proof does not match this account.
    ProofRejected = 118,
    /// The period account is not this stream's funded note.
    BadPeriod = 119,
    /// The index is not `next_fund` on fund, or not `next_claim` on claim.
    BadIndex = 120,
    /// `fund` after `stop`.
    Stopped = 121,
    /// Four funded periods are already unclaimed.
    TooManyOpen = 122,
    /// `close` on an `Active` stream. `stop` first.
    StillActive = 123,
    /// `period_secs` is not a positive length.
    BadPeriodSecs = 124,
    /// A period end does not fit in `i64`, or a counter does not fit in `u32`.
    Overflow = 125,
    /// `claim` or `stop` before any period is funded.
    NotFunded = 126,
    /// `stop` when the stream is not `Active`.
    NotActive = 127,
    /// Decline after a note is funded.
    Frozen = 128,
    /// `deposit` while the pool already has a note.
    PoolOccupied = 129,
    /// `join`, `withdraw`, or `initiate` while the pool has no note.
    PoolEmpty = 130,
}

impl PayrollError {
    /// Stable numeric code returned to the runtime. Do not renumber a shipped code.
    pub const fn code(self) -> u32 {
        self as u32
    }
}
