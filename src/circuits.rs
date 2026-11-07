//! Fund and claim, in the shape `zolana build-zk-program` discovers.
//!
//! These are not the escrow lock, swap, or give-back circuits. The asset and
//! the amount stay in the note. The stream, the period index, and the employer
//! are public on a fund. A claim also publishes the clock and the stored
//! commitment, so a proof built for another period does not verify here.

use spr_macros::PublicInputs;
use spr_program::circuit::{
    poseidon, Assert, CheckedTransaction, Circuit, CircuitVar, ConfidentialTransaction,
    TokenUtxos, UtxoTrait, U64,
};
use spr_program::conversion::ProofInput;
use spr_keypair::ShieldedAddress;
use spr_program::{CircuitError, TxContext, UtxoOwner, ZkProgramCircuit};
use spr_transaction::WalletUtxo;

#[derive(Clone, ProofInput)]
pub struct FundPrivate {
    pub tx_context: TxContext,
    pub note: [WalletUtxo; 1],
    pub pda: UtxoOwner,
}

#[derive(Clone, PublicInputs)]
pub struct FundPublic {
    pub stream_0: u64,
    pub stream_1: u64,
    pub stream_2: u64,
    pub stream_3: u64,
    pub index: u64,
    pub employer_0: u64,
    pub employer_1: u64,
    pub employer_2: u64,
    pub employer_3: u64,
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Fund {
    pub private: FundPrivate,
    pub public: FundPublic,
}

impl Circuit for <Fund as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// The employer's note becomes the period PDA's note. Public inputs bind the stream.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut source = TokenUtxos::new_mut(&self.private.note)?;
        let mut locked = TokenUtxos::new_init(&self.private.pda, &source.asset());
        source.transfer_all(&mut locked)?;
        // A zero change stays in the output list ahead of the PDA note, and the
        // builder can name only one owner. Closing the source drops that output.
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(source.close())
            .with(locked)
            .check()
    }
}

#[derive(Clone, ProofInput)]
pub struct ClaimPrivate {
    pub tx_context: TxContext,
    pub note: [WalletUtxo; 1],
    pub employee: UtxoOwner,
}

#[derive(Clone, PublicInputs)]
pub struct ClaimPublic {
    pub stream_0: u64,
    pub stream_1: u64,
    pub stream_2: u64,
    pub stream_3: u64,
    pub index: u64,
    pub now: u64,
    pub claim_at: u64,
    pub commitment_0: u64,
    pub commitment_1: u64,
    pub commitment_2: u64,
    pub commitment_3: u64,
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Claim {
    pub private: ClaimPrivate,
    pub public: ClaimPublic,
}

impl Circuit for <Claim as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// `now >= claim_at`. The PDA note is paid to the employee. The clock is a public input.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        self.public
            .claim_at
            .assert_less_or_equal(&self.public.now, "the period has not ended")?;
        let mut locked = TokenUtxos::new_mut(&self.private.note)?;
        let mut paid = TokenUtxos::new_init(&self.private.employee, &locked.asset());
        locked.transfer_all(&mut paid)?;
        // Closing the spent PDA note drops its zero change, so the employee is the named owner.
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(locked.close())
            .with(paid)
            .check()
    }
}

#[derive(Clone, ProofInput)]
pub struct DepositPrivate {
    pub tx_context: TxContext,
    pub note: [WalletUtxo; 1],
    pub pool: UtxoOwner,
}

#[derive(Clone, PublicInputs)]
pub struct DepositPublic {
    pub hash: [u8; 32],
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Deposit {
    pub private: DepositPrivate,
    pub public: DepositPublic,
}

impl Circuit for <Deposit as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// The owner's whole note becomes the pool's note.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut source = TokenUtxos::new_mut(&self.private.note)?;
        let mut locked = TokenUtxos::new_init(&self.private.pool, &source.asset());
        source.transfer_all(&mut locked)?;
        bind_owner(&locked.owner(), &self.public.hash)?;
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(source.close())
            .with(locked)
            .check()
    }
}

#[derive(Clone, ProofInput)]
pub struct JoinPrivate {
    pub tx_context: TxContext,
    pub incoming: [WalletUtxo; 1],
    pub pool_note: [WalletUtxo; 1],
    pub pool: UtxoOwner,
}

#[derive(Clone, PublicInputs)]
pub struct JoinPublic {
    pub hash: [u8; 32],
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Join {
    pub private: JoinPrivate,
    pub public: JoinPublic,
}

impl Circuit for <Join as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// The owner's top-up joins the pool's one note.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut incoming = TokenUtxos::new_mut(&self.private.incoming)?;
        let mut pool = TokenUtxos::new_mut(&self.private.pool_note)?;
        pool.owner().assert_equal(&self.private.pool, "the pool note")?;
        incoming.transfer_all(&mut pool)?;
        bind_owner(&pool.owner(), &self.public.hash)?;
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(incoming.close())
            .with(pool)
            .check()
    }
}

#[derive(Clone, ProofInput)]
pub struct WithdrawPrivate {
    pub tx_context: TxContext,
    pub note: [WalletUtxo; 1],
    pub owner: UtxoOwner,
}

#[derive(Clone, PublicInputs)]
pub struct WithdrawPublic {
    pub hash: [u8; 32],
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Withdraw {
    pub private: WithdrawPrivate,
    pub public: WithdrawPublic,
}

impl Circuit for <Withdraw as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// The pool note returns to the owner's shielded wallet.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut source = TokenUtxos::new_mut(&self.private.note)?;
        let mut owned = TokenUtxos::new_init(&self.private.owner, &source.asset());
        source.transfer_all(&mut owned)?;
        bind_owner(&source.owner(), &self.public.hash)?;
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(source.close())
            .with(owned)
            .check()
    }
}

#[derive(Clone, ProofInput)]
pub struct InitiatePrivate {
    pub tx_context: TxContext,
    pub note: [WalletUtxo; 1],
    pub amount: u64,
    pub blind_0: u64,
    pub blind_1: u64,
    pub blind_2: u64,
    pub blind_3: u64,
    pub payroll: UtxoOwner,
    /// Records the pool address so the change output is allowed.
    pub pool_address: ShieldedAddress,
}

#[derive(Clone, PublicInputs)]
pub struct InitiatePublic {
    pub budget: [u8; 32],
    pub note: [u8; 32],
    pub keeps_note: u64,
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Initiate {
    pub private: InitiatePrivate,
    pub public: InitiatePublic,
}

impl Circuit for <Initiate as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// Peels the committed budget into the payroll note. Change stays in the pool.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut source = TokenUtxos::new_mut(&self.private.note)?;
        let mut locked = TokenUtxos::new_init(&self.private.payroll, &source.asset());
        source.transfer(&mut locked, &self.private.amount)?;
        source
            .owner()
            .assert_equal(self.private.pool_address.owner(), "the pool keeps its change")?;
        source.amount()?.assert_not_zero("the pool keeps a live note")?;
        self.public
            .keeps_note
            .assert_equal(&U64::constant(1)?, "the pool keeps a live note")?;
        bind_commitment(
            &self.private.amount.var(),
            &pack(&[
                self.private.blind_0.clone(),
                self.private.blind_1.clone(),
                self.private.blind_2.clone(),
                self.private.blind_3.clone(),
            ]),
            &self.public.budget,
        )?;
        bind_owner(&locked.owner(), &self.public.note)?;
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(source)
            .with(locked)
            .check()
    }
}

#[derive(Clone, ProofInput)]
pub struct PayPrivate {
    pub tx_context: TxContext,
    pub note: [WalletUtxo; 1],
    pub amount: u64,
    pub blind_0: u64,
    pub blind_1: u64,
    pub blind_2: u64,
    pub blind_3: u64,
    pub payee: UtxoOwner,
    /// Records the payroll address so the remainder stays on the same note.
    pub payroll_address: ShieldedAddress,
}

#[derive(Clone, PublicInputs)]
pub struct PayPublic {
    pub index: u64,
    pub due: u64,
    pub installment: [u8; 32],
    pub payee: [u8; 32],
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Pay {
    pub private: PayPrivate,
    pub public: PayPublic,
}

impl Circuit for <Pay as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// The milestone has arrived. The installment goes to the payee. Change stays on the payroll note.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut source = TokenUtxos::new_mut(&self.private.note)?;
        let mut paid = TokenUtxos::new_init(&self.private.payee, &source.asset());
        source.transfer(&mut paid, &self.private.amount)?;
        source.owner().assert_equal(
            self.private.payroll_address.owner(),
            "the payroll keeps its change",
        )?;
        bind_commitment(
            &self.private.amount.var(),
            &pack(&[
                self.private.blind_0.clone(),
                self.private.blind_1.clone(),
                self.private.blind_2.clone(),
                self.private.blind_3.clone(),
            ]),
            &self.public.installment,
        )?;
        bind_owner(&paid.owner(), &self.public.payee)?;
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(source)
            .with(paid)
            .check()
    }
}

#[derive(Clone, ProofInput)]
pub struct ReclaimPrivate {
    pub tx_context: TxContext,
    pub payroll_note: [WalletUtxo; 1],
    pub pool_note: [WalletUtxo; 1],
    pub pool: UtxoOwner,
}

#[derive(Clone, PublicInputs)]
pub struct ReclaimPublic {
    pub note: [u8; 32],
    pub pool: [u8; 32],
}

#[derive(Clone, ZkProgramCircuit)]
pub struct Reclaim {
    pub private: ReclaimPrivate,
    pub public: ReclaimPublic,
}

impl Circuit for <Reclaim as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    /// The payroll remainder joins the employer's pool, which may already hold a note.
    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let mut locked = TokenUtxos::new_mut(&self.private.payroll_note)?;
        let asset = locked.asset();
        let mut pool = TokenUtxos::new_mut(&self.private.pool_note)?.with_optional(&self.private.pool, &asset);
        locked.transfer_all(&mut pool)?;
        bind_owner(&locked.owner(), &self.public.note)?;
        bind_owner(&pool.owner(), &self.public.pool)?;
        ConfidentialTransaction::new(&self.private.tx_context, &self.public)
            .with(locked.close())
            .with(pool)
            .check()
    }
}

fn bind_owner(owner: &spr_program::circuit::UtxoOwner, hash: &CircuitVar) -> Result<(), CircuitError> {
    let got = owner.hash()?;
    got.assert_equal(hash, "the note owner")?;
    Ok(())
}

fn bind_commitment(amount: &CircuitVar, blinding: &CircuitVar, commitment: &CircuitVar) -> Result<(), CircuitError> {
    let got = poseidon(&[amount.clone(), blinding.clone()])?;
    got.assert_equal(commitment, "the amount commitment")?;
    Ok(())
}

fn pack(limbs: &[U64; 4]) -> CircuitVar {
    let mut acc = limbs[3].var();
    for limb in [limbs[2].var(), limbs[1].var(), limbs[0].var()] {
        acc = shift64(acc).plus(&limb);
    }
    acc
}

fn shift64(value: CircuitVar) -> CircuitVar {
    let mut acc = value;
    for _ in 0..64 {
        acc = acc.plus(&acc);
    }
    acc
}
