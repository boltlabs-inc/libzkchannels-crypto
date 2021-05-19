//! Keys and other parameters used by participants in the zkChannels protocol.
use crate::Rng;

/// Keys and parameters used by the customer throughout the lifetime of a zkChannel.
#[allow(unused)]
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct ZkAbacusCustomerChannelParameters {}

/// Keys and parameters used by the merchant throughout its lifetime (and across all its channels).
#[allow(unused)]
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct ZkAbacusMerchantChannelParameters {}

impl ZkAbacusMerchantChannelParameters {
    /// Generates new merchant parameters.
    pub fn new(_rng: &mut impl Rng) -> Self {
        ZkAbacusMerchantChannelParameters {}
    }

    /// Extracts public keys from the merchant parameters to produce [`CustomerParameters`]
    pub fn extract_customer_parameters(&self) -> ZkAbacusCustomerChannelParameters {
        ZkAbacusCustomerChannelParameters {}
    }
}
