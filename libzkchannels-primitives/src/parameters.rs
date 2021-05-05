use crate::states::*;
use crate::types::*;
use pedersen_commitments::*;
use ps_keys::*;

#[allow(unused)]
pub struct CustomerParameters {
    /// Merchant public key for transaction validation
    merchant_signing_pk: PublicKey,
    /// Parameters for forming general commitments
    commitment_params: PedersenParameters<G1Projective>,
}

#[allow(unused)]
pub struct MerchantParameters {
    /// Keypair suitable for signing transactions
    signing_keys: KeyPair,
    /// Parameters for forming general commitments
    commitment_params: PedersenParameters<G1Projective>,
}

impl MerchantParameters {
    pub fn sign_state_commitment(&self, _com: CloseStateCommitment) -> CloseState {
        todo!();
    }
}
