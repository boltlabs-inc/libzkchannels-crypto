use crate::customer::Config;
use crate::nonce::Nonce;
use crate::proofs::*;
use crate::revlock::*;
use crate::states::*;
use crate::PaymentAmount;

/// A channel that is ready to start a new payment.
#[derive(Debug)]
pub struct Ready {
    config: Config,
    state: State,
    pay_token: PayToken,
    close_state_signature: CloseStateSignature,
}

/// Message sent to the merchant after starting a payment.
#[derive(Debug)]
pub struct StartMessage {
    /// The current customer state's random nonce.
    pub nonce: Nonce,
    /// The zero-knowledge proof of the validity of the payment.
    pub pay_proof: PayProof,
    /// The commitment to the (not yet revealed) revocation lock.
    pub revocation_lock_commitment: RevocationLockCommitment,
    /// The commitment to the close state message.
    pub close_state_commitment: CloseStateCommitment,
    /// The commitment to the state.
    pub state_commitment: StateCommitment,
}

impl Ready {
    /// Start a payment of the given [`PaymentAmount`].
    pub fn start(self, _amount: PaymentAmount) -> (Started, StartMessage) {
        todo!()
    }

    /// Extract data used to close the channel.
    pub fn close(self) -> Closing {
        todo!()
    }
}

/// A channel that has started a new payment.
#[derive(Debug)]
pub struct Started {
    config: Config,
    new_state: State,
    old_state: State,
    blinding_factors: BlindingFactors,
    close_state_signature: CloseStateSignature,
    old_close_state_signature: CloseStateSignature,
}

/// Message sent to the merchant to revoke the old balance and lock the channel.
#[derive(Debug)]
pub struct LockMessage {
    /// Revocation lock
    pub revocation_lock: RevocationLock,
    /// Revocation secret
    pub revocation_secret: RevocationSecret,
    /// Blinding factor for commitment to revocation lock
    pub revocation_lock_blinding_factor: RevocationLockBlindingFactor,
}

/// The information necessary to perform an on-chain close for a state.
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct Closing {}

impl Started {
    /// Revoke the ability to close the channel on the outdated balances.
    pub fn lock(
        self,
        _blinded_close_signature: CloseStateBlindedSignature,
    ) -> Result<(Locked, LockMessage), Started> {
        todo!();
    }

    /// Extract data used to close the channel.
    pub fn close(self) -> Closing {
        todo!()
    }

    /// Extract data used to close the channel on the old balances, prior to the
    /// currently-in-progress payment.
    pub fn close_old(self) -> Closing {
        todo!()
    }
}

/// A channel that has made a payment but not yet been given permission by the merchant to make
/// another payment.
#[derive(Debug)]
pub struct Locked {
    config: Config,
    state: State,
    blinding_factor: PayTokenBlindingFactor,
    close_state_signature: CloseStateSignature,
}

impl Locked {
    /// Unlock the channel by validating the merchant's approval message.
    pub fn unlock(self, _blinded_pay_token: BlindedPayToken) -> Result<Ready, Locked> {
        todo!()
    }

    /// Extract data used to close the channel.
    pub fn close(self) -> Closing {
        todo!()
    }
}
