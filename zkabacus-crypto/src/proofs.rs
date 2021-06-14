/*!
This describes the zero-knowledge proofs used in the Establish and Pay subprotocols of
zkChannels.

These proofs are formed by the customer and demonstrate that they know the current state of the
channel and have modified it appropriately. The merchant verifies the proofs, confirming that
the customer is behaving correctly without learning any additional information about the channel state.
*/
use serde::*;

use crate::{
    customer, merchant, revlock::*, states::*, types::*, Nonce, PaymentAmount, Rng, Verification,
    CLOSE_SCALAR,
};
use zkchannels_crypto::{
    challenge::ChallengeBuilder,
    commitment_proof::{CommitmentProof, CommitmentProofBuilder},
    message::Message,
    pedersen_commitments::Commitment,
    range_proof::{RangeProof, RangeProofBuilder},
    signature_proof::{SignatureProof, SignatureProofBuilder},
    SerializeElement,
};

/// Context provides additional information about the setting in which the proof is used, such
/// as a session transcript.
#[derive(Debug, Clone, Copy)]
pub struct Context {}

impl Context {
    /// Convert context to a byte string.
    /// FIXME(Marcella): Implement this correctly once Context is defined.
    pub fn to_bytes(&self) -> [u8; 32] {
        [0; 32]
    }
}

/**
An establish proof demonstrates that a customer is trying to initialize a channel correctly.

This is a zero-knowledge proof that makes the following guarantees:

- The new balances match the previously-agreed-upon values.
- The [`StateCommitment`] and [`CloseStateCommitment`] open to objects that are correctly formed
  relative to each other.
- The close state is well-formed (e.g. with a close tag and corresponding to the state).
*/
#[derive(Debug, Serialize, Deserialize)]
pub struct EstablishProof {
    // Commitment scalars for public values.
    #[serde(with = "SerializeElement")]
    channel_id_commitment_scalar: Scalar,
    #[serde(with = "SerializeElement")]
    close_tag_commitment_scalar: Scalar,
    #[serde(with = "SerializeElement")]
    customer_balance_commitment_scalar: Scalar,
    #[serde(with = "SerializeElement")]
    merchant_balance_commitment_scalar: Scalar,

    // Proof objects.
    state_proof: CommitmentProof<G1Projective>,
    close_state_proof: CommitmentProof<G1Projective>,

    // Commitments for proof objects.
    state_commitment: StateCommitment,
    close_state_commitment: CloseStateCommitment,
}

#[allow(unused)]
impl EstablishProof {
    /// Retrieve the state commitment for the proof.
    pub(crate) fn extract_commitments(self) -> (StateCommitment, CloseStateCommitment) {
        (self.state_commitment, self.close_state_commitment)
    }

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
        context: &Context,
    ) -> (Self, CloseStateBlindingFactor, PayTokenBlindingFactor) {
        let pedersen_parameters = params.merchant_public_key.to_g1_pedersen_parameters();

        // Commit to state and corresponding close state.
        let (state_commitment, pay_token_blinding_factor) = state.commit(rng, &params);
        let (close_state_commitment, close_state_blinding_factor) =
            state.close_state().commit(rng, &params);

        // Start commitment proof to the state.
        let state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[None; 5],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        // Extract commitment scalars from the state proof message to re-use in close state proof.
        // Recall: this only includes those for the 5-part message, *not* the commitment blinding factor.
        let cs = state_proof_builder.conjunction_commitment_scalars();

        // Start commitment proof to the close state. Place an equality constraint on the channel id,
        // the revocation lock, and the balances.
        // Recall: the proof builder *always* chooses a random commitment scalar for the
        // blinding factor.
        let close_state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[Some(cs[0]), None, Some(cs[2]), Some(cs[3]), Some(cs[4])],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        // Form a challenge.
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
            .with_bytes(context.to_bytes())
            .finish();

        // Retrieve commitment scalars from the close state proof for public values:
        // the channel id, the close tag, and the balances.
        // (Recall: the commitment scalars for the channel id and balances will match the
        // state proof by construction)
        let commitment_scalars = close_state_proof_builder.conjunction_commitment_scalars();
        (
            Self {
                channel_id_commitment_scalar: commitment_scalars[0],
                close_tag_commitment_scalar: commitment_scalars[1],
                customer_balance_commitment_scalar: commitment_scalars[3],
                merchant_balance_commitment_scalar: commitment_scalars[4],

                // Complete commitment proof on the state.
                state_proof: state_proof_builder
                    .generate_proof_response(
                        &state.to_message(),
                        pay_token_blinding_factor.0,
                        challenge,
                    )
                    .expect("mismatched length"),

                // Complete commitment proof on the close state.
                close_state_proof: close_state_proof_builder
                    .generate_proof_response(
                        &state.close_state().to_message(),
                        close_state_blinding_factor.0,
                        challenge,
                    )
                    .expect("mismatched length"),

                // Save commitments
                state_commitment,
                close_state_commitment,
            },
            // Return blinding factors from newly-generated commitments.
            close_state_blinding_factor,
            pay_token_blinding_factor,
        )
    }

    /// Verify the [`EstablishProof`] against the provided verification objects.
    ///
    /// This function is typically called by the merchant.
    pub fn verify(
        &self,
        params: &merchant::Config,
        public_values: &EstablishProofPublicValues,
        context: &Context,
    ) -> Verification {
        // Form a challenge.
        let challenge = ChallengeBuilder::new()
            .with_public_key(params.signing_keypair.public_key())
            .with_scalar(public_values.channel_id.to_scalar())
            .with_scalar(CLOSE_SCALAR)
            .with_scalar(public_values.customer_balance.to_scalar())
            .with_scalar(public_values.merchant_balance.to_scalar())
            .with_blinded_message(self.state_commitment.0)
            .with_blinded_message(self.close_state_commitment.0)
            .with_commitment(self.state_proof.scalar_commitment)
            .with_commitment(self.close_state_proof.scalar_commitment)
            .with_bytes(context.to_bytes())
            .finish();

        let pedersen_parameters = params
            .signing_keypair
            .public_key()
            .to_g1_pedersen_parameters();

        // Check that the state proof verifies.
        let state_proof_verifies = self
            .state_proof
            .verify_knowledge_of_opening_of_commitment(
                &pedersen_parameters,
                self.state_commitment.0.as_commitment(),
                challenge,
            )
            .expect("length mismatch");

        // Check that the close state proof verifies.
        let close_state_proof_verifies = self
            .close_state_proof
            .verify_knowledge_of_opening_of_commitment(
                &pedersen_parameters,
                self.close_state_commitment.0.as_commitment(),
                challenge,
            )
            .expect("length mismatch");

        // Retrieve response scalars for the message tuples in the state and close state.
        let state_response_scalars = self.state_proof.conjunction_response_scalars();
        let close_state_response_scalars = self.close_state_proof.conjunction_response_scalars();

        // Check channel identifiers match expected.
        let expected_channel_id = challenge.to_scalar() * public_values.channel_id.to_scalar()
            + self.channel_id_commitment_scalar;
        let channel_ids_match = state_response_scalars[0] == expected_channel_id
            && close_state_response_scalars[0] == expected_channel_id;

        // Check close state contains close tag.
        let expected_close_tag =
            challenge.to_scalar() * CLOSE_SCALAR + self.close_tag_commitment_scalar;
        let close_tag_matches = close_state_response_scalars[1] == expected_close_tag;

        // Check revocation locks match each other
        let revlocks_match = state_response_scalars[2] == close_state_response_scalars[2];

        // Check customer balances match expected
        let expected_customer_balance = challenge.to_scalar()
            * public_values.customer_balance.to_scalar()
            + self.customer_balance_commitment_scalar;
        let customer_balances_match = state_response_scalars[3] == expected_customer_balance
            && close_state_response_scalars[3] == expected_customer_balance;

        // Check merchant balances match expected
        let expected_merchant_balance = challenge.to_scalar()
            * public_values.merchant_balance.to_scalar()
            + self.merchant_balance_commitment_scalar;
        let merchant_balances_match = state_response_scalars[4] == expected_merchant_balance
            && close_state_response_scalars[4] == expected_merchant_balance;

        Verification::from(
            state_proof_verifies
                && close_state_proof_verifies
                && channel_ids_match
                && close_tag_matches
                && revlocks_match
                && customer_balances_match
                && merchant_balances_match,
        )
    }
}

/// Collects the information a merchant needs to verify a [`EstablishProof`].
#[derive(Debug, Clone, Copy)]
pub struct EstablishProofPublicValues {
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
    // Commitment scalars for public items.
    #[serde(with = "SerializeElement")]
    nonce_commitment_scalar: Scalar,
    #[serde(with = "SerializeElement")]
    close_tag_commitment_scalar: Scalar,

    // Proof objects.
    pay_token_proof: SignatureProof,
    revocation_lock_proof: CommitmentProof<G1Projective>,
    state_proof: CommitmentProof<G1Projective>,
    close_state_proof: CommitmentProof<G1Projective>,
    customer_balance_proof: RangeProof,
    merchant_balance_proof: RangeProof,

    // Commitments for the commitment proofs.
    revocation_lock_commitment: RevocationLockCommitment,
    state_commitment: StateCommitment,
    close_state_commitment: CloseStateCommitment,
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
    /// Get the revocation lock commitment out of the proof.
    pub(crate) fn revocation_lock_commitment(&self) -> &RevocationLockCommitment {
        &self.revocation_lock_commitment
    }

    /// Get the state commitment out of the proof.
    pub(crate) fn state_commitment(&self) -> &StateCommitment {
        &self.state_commitment
    }

    /// Get the close state commitment out of the proof.
    pub(crate) fn close_state_commitment(&self) -> &CloseStateCommitment {
        &self.close_state_commitment
    }

    pub(crate) fn extract_commitments(
        self,
    ) -> (
        RevocationLockCommitment,
        StateCommitment,
        CloseStateCommitment,
    ) {
        (
            self.revocation_lock_commitment,
            self.state_commitment,
            self.close_state_commitment,
        )
    }

    /**
    Form a new zero-knowledge [`PayProof`] object.

    It takes the previous [`State`] and corresponding [`PayToken`], and the new [`State`].

    Internally, it forms commitments to items used in the proof: the previous [`State`]'s
    revocation lock, the [`PayToken`], and the [`CloseState`] derived from the given [`State`].
    It returns the blinding factors corresponding to these commitments.

    It also prepares the signature proof on the given [`PayToken`]:

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
        context: &Context,
    ) -> (Self, BlindingFactors) {
        let pedersen_parameters = params.merchant_public_key.to_g1_pedersen_parameters();

        // Form commits to new state, new close state, and old revocation lock.
        let (revocation_lock_commitment, revocation_lock_bf) =
            old_state.commit_to_revocation(rng, params);
        let (state_commitment, state_bf) = state.commit(rng, params);
        let (close_state_commitment, close_state_bf) = state.close_state().commit(rng, params);

        let blinding_factors = BlindingFactors {
            for_revocation_lock: revocation_lock_bf,
            for_pay_token: state_bf,
            for_close_state: close_state_bf,
        };

        // Start range proof on customer balance.
        let customer_range_proof_builder = RangeProofBuilder::generate_proof_commitments(
            state.customer_balance().into_inner() as i64,
            &params.range_proof_parameters,
            rng,
        )
        .unwrap();

        // Start range proof on merchant balance.
        let merchant_range_proof_builder = RangeProofBuilder::generate_proof_commitments(
            state.merchant_balance().into_inner() as i64,
            &params.range_proof_parameters,
            rng,
        )
        .unwrap();

        let customer_balance_commitment_scalar = customer_range_proof_builder.commitment_scalar;
        let merchant_balance_commitment_scalar = merchant_range_proof_builder.commitment_scalar;

        // Start commitment proof to old revocation lock.
        let revocation_lock_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[None],
            &params.revocation_commitment_parameters,
        )
        .expect("mismatched lengths");
        let old_revlock_commitment_scalar =
            revocation_lock_proof_builder.conjunction_commitment_scalars()[0];

        // Start signature proof on pay token, with equality constraints on the old revocation lock
        // and the balances from the range proofs.
        let pay_token_proof_builder = SignatureProofBuilder::generate_proof_commitments(
            rng,
            old_state.to_message(),
            pay_token.0,
            &[
                None,
                None,
                Some(old_revlock_commitment_scalar),
                Some(customer_balance_commitment_scalar),
                Some(merchant_balance_commitment_scalar),
            ],
            &params.merchant_public_key,
        )
        .expect("mismatched lengths");
        let channel_id_commitment_scalar =
            pay_token_proof_builder.conjunction_commitment_scalars()[0];

        // Start commitment proof on new state with an equality constraint on the channel id and
        // a linear relation on the balances from the range proofs.
        let state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[
                Some(channel_id_commitment_scalar),
                None,
                None,
                Some(customer_balance_commitment_scalar),
                Some(merchant_balance_commitment_scalar),
            ],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        // Extract commitment scalars from the state proof message to re-use in close state proof.
        // Recall: this only includes those for the 5-part message, *not* the commitment blinding factor.
        let cs = state_proof_builder.conjunction_commitment_scalars();

        // Start commitment proof on the new close state with equality constraints on the channel
        // id, the revocation lock (from the state), and the balances (from the state).
        let close_state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            &[Some(cs[0]), None, Some(cs[2]), Some(cs[3]), Some(cs[4])],
            &pedersen_parameters,
        )
        .expect("mismatched lengths");

        // Form a challenge.
        let challenge = ChallengeBuilder::new()
            // integrate keys and constants
            .with_public_key(&params.merchant_public_key)
            .with_public_key(params.range_proof_parameters.public_key())
            .with_scalar(old_state.nonce().to_scalar())
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
            // integrate context
            .with_bytes(context.to_bytes())
            .finish();

        (
            Self {
                // Add commitment scalars for publicly revealed values: the old nonce and the close tag.
                nonce_commitment_scalar: pay_token_proof_builder.conjunction_commitment_scalars()
                    [1],
                close_tag_commitment_scalar: close_state_proof_builder
                    .conjunction_commitment_scalars()[1],
                // Complete the pay token signature proof.
                pay_token_proof: pay_token_proof_builder
                    .generate_proof_response(challenge)
                    .unwrap(),
                // Complete the revocation lock proof.
                revocation_lock_proof: revocation_lock_proof_builder
                    .generate_proof_response(
                        &Message::from(old_state.revocation_lock().to_scalar()),
                        blinding_factors.for_revocation_lock.0,
                        challenge,
                    )
                    .unwrap(),
                // Complete the state proof.
                state_proof: state_proof_builder
                    .generate_proof_response(
                        &state.to_message(),
                        blinding_factors.for_pay_token.0,
                        challenge,
                    )
                    .unwrap(),
                // Complete the close state proof.
                close_state_proof: close_state_proof_builder
                    .generate_proof_response(
                        &state.close_state().to_message(),
                        blinding_factors.for_close_state.0,
                        challenge,
                    )
                    .unwrap(),
                // Complete the range proofs.
                customer_balance_proof: customer_range_proof_builder
                    .generate_proof_response(challenge)
                    .unwrap(),
                merchant_balance_proof: merchant_range_proof_builder
                    .generate_proof_response(challenge)
                    .unwrap(),

                // Add commitments.
                revocation_lock_commitment,
                state_commitment,
                close_state_commitment,
            },
            blinding_factors,
        )
    }

    /**
    Verify a PayProof against the given verification objects.

    This function is typically called by the merchant.
    */
    pub fn verify(
        &self,
        params: &merchant::Config,
        public_values: &PayProofPublicValues,
        context: &Context,
    ) -> Verification {
        let PayProofPublicValues { nonce, amount } = public_values;

        // Form the challenge.
        let challenge = ChallengeBuilder::new()
            // integrate keys and constants
            .with_public_key(&params.signing_keypair.public_key())
            .with_public_key(params.range_proof_parameters.public_key())
            .with_scalar(nonce.to_scalar())
            .with_scalar(CLOSE_SCALAR)
            // integrate commitments from commitment proofs
            .with_commitment(self.revocation_lock_commitment.0)
            .with_blinded_message(self.state_commitment.0)
            .with_blinded_message(self.close_state_commitment.0)
            // integrate commitment scalars from commitment proofs
            .with_commitment(self.revocation_lock_proof.scalar_commitment)
            .with_commitment(self.state_proof.scalar_commitment)
            .with_commitment(self.close_state_proof.scalar_commitment)
            // integrate signature and range proofs
            .with_signature_proof(&self.pay_token_proof)
            .with_range_proof(&self.customer_balance_proof)
            .with_range_proof(&self.merchant_balance_proof)
            // integrate context
            .with_bytes(context.to_bytes())
            .finish();

        let pedersen_parameters = params
            .signing_keypair
            .public_key()
            .to_g1_pedersen_parameters();

        // Check that the individual signature and commitment proofs verify.
        let pay_token_proof_verifies = self
            .pay_token_proof
            .verify_knowledge_of_signature(params.signing_keypair.public_key(), challenge)
            .expect("length mismatch");

        let revlock_proof_verifies = self
            .revocation_lock_proof
            .verify_knowledge_of_opening_of_commitment(
                &params.revocation_commitment_parameters,
                self.revocation_lock_commitment.0,
                challenge,
            )
            .expect("length mismatch");

        let state_proof_verifies = self
            .state_proof
            .verify_knowledge_of_opening_of_commitment(
                &pedersen_parameters,
                self.state_commitment.0.as_commitment(),
                challenge,
            )
            .expect("length mismatch");

        let close_state_proof_verifies = self
            .close_state_proof
            .verify_knowledge_of_opening_of_commitment(
                &pedersen_parameters,
                self.close_state_commitment.0.as_commitment(),
                challenge,
            )
            .expect("length mismatch");

        let state_response_scalars = self.state_proof.conjunction_response_scalars();
        let close_state_response_scalars = self.close_state_proof.conjunction_response_scalars();
        let pay_token_response_scalars = self.pay_token_proof.conjunction_response_scalars();

        // Check that range proofs verify against the updated balances in the state.
        let customer_balance_proof_verifies = self
            .customer_balance_proof
            .verify_range_proof(
                &params.range_proof_parameters,
                challenge,
                state_response_scalars[3],
            )
            .unwrap();
        let merchant_balance_proof_verifies = self
            .merchant_balance_proof
            .verify_range_proof(
                &params.range_proof_parameters,
                challenge,
                state_response_scalars[4],
            )
            .unwrap();

        // check channel identifiers match.
        let channel_ids_match = state_response_scalars[0] == close_state_response_scalars[0]
            && close_state_response_scalars[0] == pay_token_response_scalars[0];

        // check close state contains close tag.
        let expected_close_tag =
            challenge.to_scalar() * CLOSE_SCALAR + self.close_tag_commitment_scalar;
        let close_tag_matches = close_state_response_scalars[1] == expected_close_tag;

        // check old revocation locks match each other
        let old_revlocks_match = self.revocation_lock_proof.conjunction_response_scalars()[0]
            == pay_token_response_scalars[2];

        // check new revocation locks match each other
        let new_revlocks_match = state_response_scalars[2] == close_state_response_scalars[2];

        // check pay token nonce matches the passed in nonce
        let pay_token_nonce_matches_expected = pay_token_response_scalars[1]
            == challenge.to_scalar() * nonce.to_scalar() + self.nonce_commitment_scalar;

        // check new balances match between state and close state
        let new_customer_balances_match =
            state_response_scalars[3] == close_state_response_scalars[3];
        let new_merchant_balances_match =
            state_response_scalars[4] == close_state_response_scalars[4];

        // check that customer and merchant balances were properly updated
        let customer_balance_properly_updated = state_response_scalars[3]
            == pay_token_response_scalars[3] - challenge.to_scalar() * amount.to_scalar();
        let merchant_balance_properly_updated = state_response_scalars[4]
            == pay_token_response_scalars[4] + challenge.to_scalar() * amount.to_scalar();

        Verification::from(
            pay_token_proof_verifies
                && revlock_proof_verifies
                && state_proof_verifies
                && close_state_proof_verifies
                && customer_balance_proof_verifies
                && merchant_balance_proof_verifies
                && channel_ids_match
                && close_tag_matches
                && old_revlocks_match
                && new_revlocks_match
                && pay_token_nonce_matches_expected
                && new_customer_balances_match
                && new_merchant_balances_match
                && customer_balance_properly_updated
                && merchant_balance_properly_updated,
        )
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
#[derive(Debug, Clone, Copy)]
pub struct PayProofPublicValues {
    /// Expected nonce revealed at the beginning of Pay.
    pub nonce: Nonce,
    /// Expected payment amount.
    pub amount: PaymentAmount,
}

#[cfg(test)]
mod tests {
    use crate::{
        merchant,
        proofs::*,
        states::{ChannelId, CustomerBalance, MerchantBalance, State},
    };
    use rand::SeedableRng;

    fn rng() -> impl Rng {
        let seed: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
        rand::rngs::StdRng::from_seed(seed)
    }

    #[test]
    fn establish_proof_verifies() {
        let mut rng = rng();
        let merchant_params = merchant::Config::new(&mut rng);
        let params = merchant_params.to_customer_config();

        // Create a new state.
        let channel_id = ChannelId::new(&mut rng);
        let state = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(0).unwrap(),
            CustomerBalance::try_new(100).unwrap(),
        );

        let context = Context {};

        // Form proof, retrieve blinding factors
        let (proof, _, _) = EstablishProof::new(&mut rng, &params, &state, &context);

        // Proof must verify against the provided values.
        let public_values = EstablishProofPublicValues {
            channel_id: *state.channel_id(),
            merchant_balance: *state.merchant_balance(),
            customer_balance: *state.customer_balance(),
        };

        assert!(matches!(
            proof.verify(&merchant_params, &public_values, &context),
            Verification::Verified
        ));
    }

    #[test]
    fn pay_proof_verifies() {
        let mut rng = rng();
        let merchant_params = merchant::Config::new(&mut rng);
        let params = merchant_params.to_customer_config();

        // Create a state.
        let channel_id = ChannelId::new(&mut rng);
        let old_state = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(0).unwrap(),
            CustomerBalance::try_new(100).unwrap(),
        );

        // Update state.
        let amount = PaymentAmount::pay_merchant(10).unwrap();
        let new_state = old_state.apply_payment(&mut rng, amount).unwrap();

        // Get a pay token AKA signature on the old state.
        let (old_state_com, old_pt_bf) = old_state.commit(&mut rng, &params);
        let pay_token =
            BlindedPayToken::new(&mut rng, &merchant_params, &old_state_com).unblind(old_pt_bf);

        // Save a copy of the nonce...
        let nonce = *old_state.nonce();

        let context = Context {};

        // Form proof.
        let (proof, _blinding_factors) = PayProof::new(
            &mut rng, &params, pay_token, &old_state, &new_state, &context,
        );

        // Verify proof against expected objects.
        let public_values = PayProofPublicValues { nonce, amount };

        assert!(matches!(
            proof.verify(&merchant_params, &public_values, &context),
            Verification::Verified
        ));
    }
}
