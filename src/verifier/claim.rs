use spr_program::{
    transaction_hash,
    verifier::{groth16_solana, public_hash, verify_groth16, Field, VerifyError},
    CompressedProof, PublicTransfer,
};

include!("claim.vk.rs");

pub struct PublicInputs {
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

impl PublicInputs {
    pub fn hash(&self, transaction_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
        public_hash(
            &[
                Field::Integer(u128::from(self.stream_0)),
                Field::Integer(u128::from(self.stream_1)),
                Field::Integer(u128::from(self.stream_2)),
                Field::Integer(u128::from(self.stream_3)),
                Field::Integer(u128::from(self.index)),
                Field::Integer(u128::from(self.now)),
                Field::Integer(u128::from(self.claim_at)),
                Field::Integer(u128::from(self.commitment_0)),
                Field::Integer(u128::from(self.commitment_1)),
                Field::Integer(u128::from(self.commitment_2)),
                Field::Integer(u128::from(self.commitment_3)),
            ],
            transaction_hash,
        )
    }
}

pub struct Verifier<'a> {
    pub proof: &'a CompressedProof,
    pub public_inputs: PublicInputs,
    pub private_tx_hash: &'a [u8; 32],
    pub transfers: &'a [PublicTransfer],
}

impl Verifier<'_> {
    pub fn verify(&self) -> Result<(), VerifyError> {
        let transaction_hash = transaction_hash(self.private_tx_hash, self.transfers)
            .map_err(|_| VerifyError::PublicInputs)?;
        verify_groth16(
            self.proof,
            self.public_inputs.hash(&transaction_hash)?,
            &VERIFYINGKEY,
        )
    }
}
