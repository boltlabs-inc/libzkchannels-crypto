use crate::customer::pay::Ready;
use crate::states::*;
use crate::{customer::Config, proofs::EstablishProof};

/// Public parameters for a requested channel (i.e. that has not been accepted by the merchant).
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct Request {
    config: Config,
    channel_id: ChannelId,
    merchant_balance: MerchantBalance,
    customer_balance: CustomerBalance,
    state: State,
    close_state_blinding_factor: CloseStateBlindingFactor,
    pay_token_blinding_factor: PayTokenBlindingFactor,
}

/// Message sent to the merchant to request a new channel.
#[derive(Debug)]
pub struct RequestMessage {
    close_state_commitment: CloseStateCommitment,
    state_commitment: StateCommitment,
    proof: EstablishProof,
}

impl Request {
    /// Generate a new channel request from public parameters.
    ///
    /// @Kenny: It may be better to pass config as the set of its parts. not sure yet.
    pub fn new(
        _config: Config,
        _channel_id: ChannelId,
        _merchant_balance: MerchantBalance,
        _customer_balance: CustomerBalance,
    ) -> (Self, RequestMessage) {
        todo!();
    }

    /// Complete a payment request: validate approval received from the merchant.
    ///
    /// @Kenny: Is it better to return a string describing the error or define an new error type?
    /// There is only one failure case and it should abort the establish.
    pub fn complete(
        self,
        _blinded_signature: CloseStateBlindedSignature,
    ) -> Result<Inactive, String> {
        todo!();
    }
}

/// A channel that has been requested but not yet activated.
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct Inactive {
    config: Config,
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Inactive {
    /// Activate the channel with the fresh pay token from the merchant.
    ///
    /// @Kenny: ditto as above. Only one failure case that aborts.
    pub fn activate(self, _pay_token: BlindedPayToken) -> Result<Ready, String> {
        todo!();
    }
}
