//! Keys and other parameters used by participants in the zkChannels protocol.
use crate::Rng;

#[allow(unused)]
#[derive(Debug)]
/// Keys and parameters used by the customer throughout the lifetime of a zkChannel.
pub struct CustomerParameters {
    /*
/// Merchant public key for signature validation.
pub merchant_signing_pk: PublicKey,
/// Parameters for forming general commitments.
pub commitment_params: PedersenParameters<G1Projective>,
*/}

#[allow(unused)]
#[derive(Debug)]
/// Keys and parameters used by the merchant throughout its lifetime (and across all its channels).
pub struct MerchantParameters {
    /*
/// Keypair suitable for signing transactions.
pub signing_keys: KeyPair,
/// Parameters for forming general commitments.
pub commitment_params: PedersenParameters<G1Projective>,
*/}

impl MerchantParameters {
    /// Generates new merchant parameters.
    pub fn new(rng: &mut impl Rng) -> Self {
        MerchantParameters {
            //signing_keys: KeyPair::new(0, rng),
            //commitment_params: PedersenParameters::new(0, rng),
        }
    }

    /// Extracts public keys from the merchant parameters to produce [`CustomerParameters`]
    pub fn extract_customer_parameters(&self) -> CustomerParameters {
        CustomerParameters {
            //merchant_signing_pk: self.signing_keys.pk.clone(),
            //// commitment_params: self.commitment_params.clone(),
        }
    }
}
