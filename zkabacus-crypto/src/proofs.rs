/*!
This describes the zero-knowledge proofs used in the Establish and Pay subprotocols of
zkChannels.

These proofs are formed by the customer and demonstrate that they know the current state of the
channel and have modified it appropriately. The merchant verifies the proofs, confirming that
the customer is behaving correctly without learning any additional information about the channel state.
*/
use serde::*;

use crate::{
    customer, merchant, revlock::*, states::*, types::*, Nonce, Rng, Verification, CLOSE_SCALAR,
};
use zkchannels_crypto::{
    challenge::ChallengeBuilder,
    commitment_proof::{CommitmentProof, CommitmentProofBuilder},
    pedersen_commitments::Commitment,
    range_proof::{RangeProof, RangeProofBuilder},
    signature_proof::{SignatureProof, SignatureProofBuilder},
    SerializeElement,
};

/**
An establish proof demonstrates that a customer is trying to initialize a channel correctly.

This is a zero-knowledge proof that makes the following guarantees:

- The new balances match the previously-agreed-upon values.
- The [`StateCommitment`] and [`CloseStateCommitment`] open to objects that are correctly formed
  relative to each other.
- The close state is well-formed (e.g. with a close tag and corresponding to the state).
*/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstablishProof {
    state_proof: CommitmentProof<G1Projective>,
    close_state_proof: CommitmentProof<G1Projective>,

    #[serde(with = "SerializeElement")]
    channel_id_cs: Scalar,
    #[serde(with = "SerializeElement")]
    close_tag_cs: Scalar,
    #[serde(with = "SerializeElement")]
    customer_balance_cs: Scalar,
    #[serde(with = "SerializeElement")]
    merchant_balance_cs: Scalar,
}

#[allow(unused)]
impl EstablishProof {
    /**
    Form a new zero-knowledge [`EstablishProof`] object.

    It takes the [`State`] and two current blinding factors. These should correspond to
    commitments made from the given [`State`] and its associated [`CloseState`].

    This function is typically called by the customer.
    */
    pub(crate) fn new(
        rng: &mut impl Rng,
        params: &customer::Config,
        state: &State,
        close_state_blinding_factor: CloseStateBlindingFactor,
        pay_token_blinding_factor: PayTokenBlindingFactor,
        state_commitment: &StateCommitment,
        close_state_commitment: &CloseStateCommitment,
    ) -> Self {
        let pedersen_parameters = params.merchant_public_key.to_g1_pedersen_parameters();
        let state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[None; 5],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        let cs = state_proof_builder.conjunction_commitment_scalars();
        let close_state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[Some(cs[0]), None, Some(cs[2]), Some(cs[3]), Some(cs[4])],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        let challenge = ChallengeBuilder::new()
            .with_public_key(&params.merchant_public_key)
            .with_scalar(state.channel_id().to_scalar())
            .with_scalar(CLOSE_SCALAR)
            .with_scalar(state.customer_balance().to_scalar())
            .with_scalar(state.merchant_balance().to_scalar())
            .with_blinded_message(state_commitment.0)
            .with_blinded_message(close_state_commitment.0)
            .with_commitment(state_proof_builder.scalar_commitment)
            .with_commitment(close_state_proof_builder.scalar_commitment)
            .finish();

        // We take the commitment scalars from the close state proof because we need the close tag
        // from the close state proof and then the channel ID, customer balance, and merchant
        // balance commitment scalars should match by construction.
        let commitment_scalars = close_state_proof_builder.conjunction_commitment_scalars();
        Self {
            channel_id_cs: commitment_scalars[0],
            close_tag_cs: commitment_scalars[1],
            customer_balance_cs: commitment_scalars[3],
            merchant_balance_cs: commitment_scalars[4],

            state_proof: state_proof_builder
                .generate_proof_response(
                    &state.to_message(),
                    pay_token_blinding_factor.0,
                    challenge,
                )
                .expect("mismatched length"),

            close_state_proof: close_state_proof_builder
                .generate_proof_response(
                    &state.close_state().to_message(),
                    close_state_blinding_factor.0,
                    challenge,
                )
                .expect("mismatched length"),
        }
    }

    /// Verify the [`EstablishProof`] against the provided verification objects.
    ///
    /// This function is typically called by the merchant.
    pub fn verify(
        &self,
        params: &merchant::Config,
        verification_objects: &EstablishProofVerification,
    ) -> Verification {
        let challenge = ChallengeBuilder::new()
            .with_public_key(params.signing_keypair.public_key())
            .with_scalar(verification_objects.channel_id.to_scalar())
            .with_scalar(CLOSE_SCALAR)
            .with_scalar(verification_objects.customer_balance.to_scalar())
            .with_scalar(verification_objects.merchant_balance.to_scalar())
            .with_blinded_message(verification_objects.state_commitment.0)
            .with_blinded_message(verification_objects.close_state_commitment.0)
            .with_commitment(self.state_proof.scalar_commitment)
            .with_commitment(self.close_state_proof.scalar_commitment)
            .finish();

        let pedersen_parameters = params
            .signing_keypair
            .public_key()
            .to_g1_pedersen_parameters();

        let state_proof_verifies = self
            .state_proof
            .verify_knowledge_of_opening_of_commitment(
                &pedersen_parameters,
                verification_objects.state_commitment.0.as_commitment(),
                challenge,
            )
            .expect("length mismatch");

        let close_state_proof_verifies = self
            .close_state_proof
            .verify_knowledge_of_opening_of_commitment(
                &pedersen_parameters,
                verification_objects
                    .close_state_commitment
                    .0
                    .as_commitment(),
                challenge,
            )
            .expect("length mismatch");

        let state_proof_rs = self.state_proof.conjunction_response_scalars();
        let close_state_proof_rs = self.close_state_proof.conjunction_response_scalars();

        // check channel identifiers match expected.
        let expected_channel_id =
            challenge.0 * verification_objects.channel_id.to_scalar() + self.channel_id_cs;
        let channel_ids_match = state_proof_rs[0] == expected_channel_id
            && close_state_proof_rs[0] == expected_channel_id;

        // check close state contains close tag.
        let expected_close_tag = challenge.0 * CLOSE_SCALAR + self.close_tag_cs;
        let close_tags_match = close_state_proof_rs[1] == expected_close_tag;

        // check revocation locks match each other
        let revlocks_match = state_proof_rs[2] == close_state_proof_rs[2];

        // check customer balances match expected
        let expected_customer_balance = challenge.0
            * verification_objects.customer_balance.to_scalar()
            + self.customer_balance_cs;
        let customer_balances_match = state_proof_rs[3] == expected_customer_balance
            && close_state_proof_rs[3] == expected_customer_balance;

        // check merchant balances match expected
        let expected_merchant_balance = challenge.0
            * verification_objects.merchant_balance.to_scalar()
            + self.merchant_balance_cs;
        let merchant_balances_match = state_proof_rs[4] == expected_merchant_balance
            && close_state_proof_rs[4] == expected_merchant_balance;

        Verification::from(
            state_proof_verifies
                && close_state_proof_verifies
                && channel_ids_match
                && close_tags_match
                && revlocks_match
                && customer_balances_match
                && merchant_balances_match,
        )
    }
}

/// Collects the information a merchant needs to verify a [`EstablishProof`].
#[derive(Debug)]
pub struct EstablishProofVerification<'a> {
    /// Commitment to a [`State`].
    pub state_commitment: &'a StateCommitment,
    /// Commitment to a `CloseState`.
    pub close_state_commitment: CloseStateCommitment,
    /// Expected channel ID.
    pub channel_id: ChannelId,
    /// Expected merchant balance.
    pub merchant_balance: MerchantBalance,
    /// Expected customer balance.
    pub customer_balance: CustomerBalance,
}

/**
A payment proof demonstrates that a customer is trying to make a valid payment on a channel.

This is a zero-knowledge proof that makes the following guarantees:

- The customer holds a valid `PayToken` and knows the state it corresponds to.
- The customer knows the opening of the [`RevocationLockCommitment`], the [`StateCommitment`], and
  the [`CloseStateCommitment`].
- The new state from the commitment is correctly updated from the previous state
  (that is, the balances are updated by an agreed-upon amount).
- The close state is well-formed (e.g. with a close tag and corresponding to the new state).
- The committed [`RevocationLock`] and revealed [`Nonce`] are contained in the previous `State`.
- The new balances are non-negative.

*/
#[derive(Debug, Serialize, Deserialize)]
pub struct PayProof {
    #[serde(with = "SerializeElement")]
    nonce_cs: Scalar,
    #[serde(with = "SerializeElement")]
    close_tag_cs: Scalar,
    pay_token_proof: SignatureProof,
    revocation_lock_proof: CommitmentProof<G1Projective>,
    state_proof: CommitmentProof<G1Projective>,
    close_state_proof: CommitmentProof<G1Projective>,
    customer_balance_proof: RangeProof,
    merchant_balance_proof: RangeProof,
}

/// Blinding factors for commitments associated with a particular payment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlindingFactors {
    /// The blinding factor for a [`RevocationLockCommitment`] (associated with the previous [`State`])
    pub for_revocation_lock: RevocationLockBlindingFactor,
    /// The blinding factor for a [`StateCommitment`] (associated with the current [`State`]).
    pub for_pay_token: PayTokenBlindingFactor,
    /// The blinding factor for a [`CloseStateCommitment`] (associated with the current [`CloseState`]).
    pub for_close_state: CloseStateBlindingFactor,
}

#[allow(unused)]
impl PayProof {
    /**
    Form a new zero-knowledge [`PayProof`] object.

    It takes the previous [`State`] and corresponding [`PayToken`], and the new [`State`]. It also
    requires the blinding factors corresponding to commitments made on the previous [`State`]'s
    revocation lock, the [`PayToken`], and the [`CloseState`] derived from the given [`State`].

    Internally, it also prepares the signature proof on the given [`PayToken`]:

    - blinds and randomizes the [`PayToken`] to produce a [`PayTokenCommitment`] and
      corresponding [`PayTokenBlindingFactor`], and
    - forms a commitment to the old [`State`] underlying the [`PayToken`]

    This blinding factor is not used again during the protocol, so it doesn't leave this
    function.

    This function is typically called by the customer.
    */
    pub(crate) fn new(
        rng: &mut impl Rng,
        params: &customer::Config,
        pay_token: PayToken,
        old_state: &State,
        state: &State,
        revocation_lock_commitment: &RevocationLockCommitment,
        state_commitment: &StateCommitment,
        close_state_commitment: &CloseStateCommitment,
        blinding_factors: BlindingFactors,
    ) -> Self {
        let pedersen_parameters = params.merchant_public_key.to_g1_pedersen_parameters();

        let customer_range_proof_builder = RangeProofBuilder::generate_proof_commitments(
            state.customer_balance().into_inner() as i64,
            &params.range_proof_parameters,
            rng,
        )
        .unwrap();

        let merchant_range_proof_builder = RangeProofBuilder::generate_proof_commitments(
            state.merchant_balance().into_inner() as i64,
            &params.range_proof_parameters,
            rng,
        )
        .unwrap();

        let customer_rs = customer_range_proof_builder.commitment_scalar;
        let merchant_rs = merchant_range_proof_builder.commitment_scalar;

        let revocation_lock_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[None],
            &params.revocation_commitment_parameters,
        )
        .expect("mismatched lengths");
        let revlock_cs = revocation_lock_proof_builder.conjunction_commitment_scalars()[0];

        let pay_token_proof_builder = SignatureProofBuilder::generate_proof_commitments(
            rng,
            old_state.to_message(),
            pay_token.0,
            &[
                None,
                None,
                Some(revlock_cs),
                Some(customer_rs),
                Some(merchant_rs),
            ],
            &params.merchant_public_key,
        )
        .expect("mismatched lengths");
        let channel_id_cs = pay_token_proof_builder.conjunction_commitment_scalars()[0];

        let state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[
                Some(channel_id_cs),
                None,
                Some(revlock_cs),
                Some(customer_rs),
                Some(merchant_rs),
            ],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        let cs = state_proof_builder.conjunction_commitment_scalars();
        let close_state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[
                Some(channel_id_cs),
                None,
                Some(revlock_cs),
                Some(customer_rs),
                Some(merchant_rs),
            ],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        let challenge = ChallengeBuilder::new()
            // integrate keys and constants
            .with_public_key(&params.merchant_public_key)
            .with_public_key(params.range_proof_parameters.public_key())
            .with_scalar(state.nonce().to_scalar())
            .with_scalar(CLOSE_SCALAR)
            // integrate commitments from commitment proofs
            .with_commitment(revocation_lock_commitment.0)
            .with_blinded_message(state_commitment.0)
            .with_blinded_message(close_state_commitment.0)
            // integrate commitment scalars from commitment proofs
            .with_commitment(revocation_lock_proof_builder.scalar_commitment)
            .with_commitment(state_proof_builder.scalar_commitment)
            .with_commitment(close_state_proof_builder.scalar_commitment)
            // integrate signature and range proofs
            .with_signature_proof_builder(&pay_token_proof_builder)
            .with_range_proof_builder(&customer_range_proof_builder)
            .with_range_proof_builder(&merchant_range_proof_builder)
            // TODO: incorporate context here.
            .finish();

        Self {
            nonce_cs: pay_token_proof_builder.conjunction_commitment_scalars()[1],
            close_tag_cs: close_state_proof_builder.conjunction_commitment_scalars()[1],
            pay_token_proof: pay_token_proof_builder
                .generate_proof_response(challenge)
                .unwrap(),
            revocation_lock_proof: revocation_lock_proof_builder
                .generate_proof_response(todo!(), blinding_factors.for_revocation_lock.0, challenge)
                .unwrap(),
            state_proof: state_proof_builder
                .generate_proof_response(
                    &state.to_message(),
                    blinding_factors.for_pay_token.0,
                    challenge,
                )
                .unwrap(),
            close_state_proof: close_state_proof_builder
                .generate_proof_response(
                    &state.close_state().to_message(),
                    blinding_factors.for_close_state.0,
                    challenge,
                )
                .unwrap(),
            customer_balance_proof: customer_range_proof_builder
                .generate_proof_response(challenge)
                .unwrap(),
            merchant_balance_proof: merchant_range_proof_builder
                .generate_proof_response(challenge)
                .unwrap(),
        }
    }

    /**
    Verify a PayProof against the given verification objects.

    This function is typically called by the merchant.
    */
    pub fn verify(
        &self,
        _params: &merchant::Config,
        _verification_objects: &PayProofVerification,
    ) -> Verification {
        todo!();
    }
}

/**
Commitment to the [`State`] underlying a [`PayToken`] for use in a [`PayProof`]

Note: this is a commitment to the [`State`] for use in the proof of knowledge of the opening
of a _signature_. This makes it different from a [`StateCommitment`], which is used in the
proof of knowledge of the opening of a _commitment_.

*/
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayTokenCommitment(Commitment<G2Projective>);

/// Collects the information a merchant needs to verify a [`PayProof`].
#[derive(Debug)]
pub struct PayProofVerification<'a> {
    /// Commitment to the revocation lock in the previous [`State`].
    pub revocation_lock_commitment: &'a RevocationLockCommitment,
    /// Commitment to the new channel [`State`].
    pub state_commitment: &'a StateCommitment,
    /// Commitment to the new [`CloseState`].
    pub close_state_commitment: &'a CloseStateCommitment,
    /// Expected nonce revealed at the beginning of Pay.
    pub nonce: Nonce,
    /// Expected payment amount.
    pub amount: crate::PaymentAmount,
}

#[cfg(test)]
mod tests {
    use crate::{
        merchant,
        proofs::*,
        states::{ChannelId, CustomerBalance, MerchantBalance, State},
    };
    use rand::SeedableRng;

    #[test]
    fn establish_proof_verifies() {
        let seed: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let merchant_params = merchant::Config::new(&mut rng);
        let params = merchant_params.to_customer_config();
        let channel_id = ChannelId::new(&mut rng);
        let state = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(0).unwrap(),
            CustomerBalance::try_new(100).unwrap(),
        );
        let close_state = state.close_state();

        let (state_commitment, pt_bf) = state.commit(&mut rng, &params);
        let (close_state_commitment, cs_bf) = close_state.commit(&mut rng, &params);
        let proof = EstablishProof::new(
            &mut rng,
            &params,
            &state,
            cs_bf,
            pt_bf,
            &state_commitment,
            &close_state_commitment,
        );

        let vos = EstablishProofVerification {
            state_commitment: &state_commitment,
            close_state_commitment,
            channel_id: *state.channel_id(),
            merchant_balance: *state.merchant_balance(),
            customer_balance: *state.customer_balance(),
        };
        assert!(matches!(
            proof.verify(&merchant_params, &vos),
            Verification::Verified
        ));
    }
}
