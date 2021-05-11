//! Keys and other parameters used by participants in the zkChannels protocol.
use crate::types::*;
use pedersen_commitments::*;
use ps_keys::*;

#[allow(unused)]
#[derive(Debug)]
/// Keys and parameters used by the customer throughout the lifetime of a zkChannel.
pub struct CustomerParameters {
    /// Merchant public key for transaction validation
    merchant_signing_pk: PublicKey,
    /// Parameters for forming general commitments
    commitment_params: PedersenParameters<G1Projective>,
}

#[allow(unused)]
#[derive(Debug)]
/// Keys and parameters used by the merchant throughout its lifetime (and across all its channels).
pub struct MerchantParameters {
    /// Keypair suitable for signing transactions
    signing_keys: KeyPair,
    /// Parameters for forming general commitments
    commitment_params: PedersenParameters<G1Projective>,
}
