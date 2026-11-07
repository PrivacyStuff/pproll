#![cfg_attr(feature = "bpf-entrypoint", no_std)]

//! One-way private payroll. The employer funds a period note. The employee claims it after the period ends.
//!
//! This is not the escrow swap. A fund and a claim each have their own circuit.
//! A claim signs the period PDA. A fund does not, because the pool hashes every
//! signer into the transact proof. The period commitment is
//! written only after that invoke. `zolana build-zk-program` writes the verifying
//! keys. A public test setup does not compile into the program.

#[cfg(feature = "circuits")]
mod circuits;
mod error;
mod pool;
mod processor;
mod state;

#[cfg(feature = "circuits")]
pub use circuits::{
    Claim, ClaimPrivate, ClaimPublic, Deposit, DepositPrivate, DepositPublic, Fund, FundPrivate,
    FundPublic, Initiate, InitiatePrivate, InitiatePublic, Join, JoinPrivate, JoinPublic, Pay,
    PayPrivate, PayPublic, Reclaim, ReclaimPrivate, ReclaimPublic, Withdraw, WithdrawPrivate,
    WithdrawPublic,
};

pub use error::PayrollError;
pub use pool::{
    approve_payroll, deposit, initiate, join, open_payroll, open_vault, pay, reclaim, stop_payroll,
    withdraw, InitiateMove, PoolMove, ProvedInitiate, ProvedPay, ProvedReclaim, ProvedVault,
    INITIATE_HEADER, OPEN_PAYROLL_IX_LEN, PAYROLL_NOTE_SEED, POOL_SEED,
};
pub use processor::address_limbs;
pub use processor::{
    approve, claim, close, create, decline, fund, process, proved_claim, proved_fund, stop,
    CreateArgs, FundMove, Instruction, ProvedClaim, CIRCUIT_PROOF_LEN,
    CLAIM_HEADER, CREATE_IX_LEN, FUND_HEADER, LOCK_SEED, MAX_OPEN, SPP_ID,
};
pub use state::{
    claim_at, OpenPayroll, OpenVault, PayrollAccount, Period, Ring, Status, Stream, Vault, Wallets,
    LIVE_EMPTY, LIVE_NOTE, OWNER_HASH_LEN, PAYROLL_LEN, PAYROLL_TAG, PERIOD_LEN, PERIOD_TAG,
    STREAM_LEN, STREAM_TAG, VAULT_LEN, VAULT_TAG, VIEWING_LEN,
};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "r1cs-export")))]
mod verifier;

#[cfg(feature = "bpf-entrypoint")]
mod entrypoint;
