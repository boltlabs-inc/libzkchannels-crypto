/*!
This describes the zero-knowledge proofs used in the Establish and Pay subprotocols of
zkChannels.

These proofs are formed by the customer and demonstrate that they know the current state of the
channel and have modified it appropriately. The merchant verifies the proofs, confirming that
the customer is behaving correctly without learning any additional information about the channel state.
*/
use serde::*;
use sha3::{Digest, Sha3_256};

use crate::{
    customer, merchant, revlock::*, states::*, types::*, Nonce, PaymentAmount, Rng, CLOSE_SCALAR,
};
use zkchannels_crypto::{
    pedersen::Commitment,
    proofs::{
        ChallengeBuilder, CommitmentProof, CommitmentProofBuilder, RangeConstraint,
        RangeConstraintBuilder, SignatureProof, SignatureProofBuilder, SignatureRequestProof,
        SignatureRequestProofBuilder,
    },
    SerializeElement,
};

/// Context provides additional information about the setting in which the proof is used, such
/// as a session transcript.
#[derive(Debug, Clone, Copy)]
pub struct Context([u8; 32]);

impl Context {
    /// Generate a new `Context` from the given bytes.
    pub fn new(bytes: &[u8]) -> Self {
        // Hash the input bytes.
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        let mut context_digest = [0; 32];
        context_digest.copy_from_slice(hasher.finalize().as_ref());
        Self(context_digest)
    }

    /// Convert context to a byte string.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/**
An establish proof demonstrates that a customer is trying to initialize a channel correctly.

This is a zero-knowledge proof that makes the following guarantees:

- The new balances match the previously-agreed-upon values.
- The channel state and close state are correctly formed relative to each other
- The close state is well-formed (with a close tag and corresponding to the state).
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
    state_proof: SignatureRequestProof<5>,
    close_state_proof: SignatureRequestProof<5>,
}

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
        context: &Context,
    ) -> (Self, CloseStateBlindingFactor, PayTokenBlindingFactor) {
        // Start commitment proof to the new state.
        let state_proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
            rng,
            state.to_message(),
            &[None; 5],
            params.merchant_public_key(),
        );
        let pay_token_blinding_factor =
            PayTokenBlindingFactor(state_proof_builder.message_blinding_factor());

        // Extract commitment scalars from the state proof message to re-use in close state proof.
        // Recall: this only includes those for the 5-part message, *not* the commitment blinding factor.
        let cs = state_proof_builder.conjunction_commitment_scalars();

        // Start commitment proof to the new close state. Add constraints:
        // - equality: channel id must match the one in the new state;
        // - equality: revocation lock must match the one in the new state;
        // - equality: balances must match the one in the new state;
        // Recall: the proof builder *always* chooses a random commitment scalar for the
        // blinding factor.
        let close_state_proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
            rng,
            state.close_state().to_message(),
            &[Some(cs[0]), None, Some(cs[2]), Some(cs[3]), Some(cs[4])],
            params.merchant_public_key(),
        );
        let close_state_blinding_factor =
            CloseStateBlindingFactor(close_state_proof_builder.message_blinding_factor());

        // Form a challenge.
        let challenge = ChallengeBuilder::new()
            // Incorporate public values.
            .with(&params.merchant_public_key)
            .with(&state.channel_id().to_scalar())
            .with(&CLOSE_SCALAR)
            .with(&state.customer_balance().to_scalar())
            .with(&state.merchant_balance().to_scalar())
            // Incorporate commitments and commitment scalars from proofs.
            .with(&state_proof_builder)
            .with(&close_state_proof_builder)
            // Incorporate transcript context.
            .with_bytes(&context.as_bytes())
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
                state_proof: state_proof_builder.generate_proof_response(challenge),

                // Complete commitment proof on the close state.
                close_state_proof: close_state_proof_builder.generate_proof_response(challenge),
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
    ) -> Option<(VerifiedBlindedState, VerifiedBlindedCloseState)> {
        // Form a challenge.
        let challenge = ChallengeBuilder::new()
            // Incorporate public values.
            .with(params.signing_keypair.public_key())
            .with(&public_values.channel_id.to_scalar())
            .with(&CLOSE_SCALAR)
            .with(&public_values.customer_balance.to_scalar())
            .with(&public_values.merchant_balance.to_scalar())
            // Incorporate commitment and commitment scalars from proofs.
            .with(&self.state_proof)
            .with(&self.close_state_proof)
            // Incorporate transcript context.
            .with_bytes(context.as_bytes())
            .finish();

        // Check that the state proof verifies.
        let state_proof_verifies = self
            .state_proof
            .verify_knowledge_of_opening(params.signing_keypair().public_key(), challenge);

        // Check that the close state proof verifies.
        let close_state_proof_verifies = self
            .close_state_proof
            .verify_knowledge_of_opening(params.signing_keypair().public_key(), challenge);

        // Retrieve response scalars for the message tuples in the new state and new close state.
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

        // Only return Verified outputs if everything passed.
        match (
            state_proof_verifies,
            close_state_proof_verifies,
            channel_ids_match
                && close_tag_matches
                && revlocks_match
                && customer_balances_match
                && merchant_balances_match,
        ) {
            (Some(verified_state), Some(verified_close_state), true) => Some((
                VerifiedBlindedState(verified_state),
                VerifiedBlindedCloseState(verified_close_state),
            )),
            _ => None,
        }
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
- The customer knows a [`RevocationLock`] and the current state (and thus close state) of the
  channel, and has correctly formed a corresponding [`CommitmentProof`] and
  [`SignatureRequestProof`]s.
- The new state is correctly updated from the previous state
  (that is, the balances are updated by an agreed-upon amount).
- The close state is well-formed (with a close tag and corresponding to the new state).
- The committed [`RevocationLock`] and revealed [`Nonce`] match the ones in the previous state
- The new balances are non-negative.

*/
#[derive(Debug, Serialize, Deserialize)]
pub struct PayProof {
    // Commitment scalars for public items.
    #[serde(with = "SerializeElement")]
    old_nonce_commitment_scalar: Scalar,
    #[serde(with = "SerializeElement")]
    close_tag_commitment_scalar: Scalar,

    // Proof objects.
    old_pay_token_proof: SignatureProof<5>,
    old_revocation_lock_proof: CommitmentProof<G1Projective, 1>,
    state_proof: SignatureRequestProof<5>,
    close_state_proof: SignatureRequestProof<5>,
    customer_balance_proof: RangeConstraint,
    merchant_balance_proof: RangeConstraint,
}

/// Blinding factors for commitments associated with a particular payment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct BlindingFactors {
    /// The blinding factor for a [`RevocationLockCommitment`] (associated with the previous [`State`])
    pub for_old_revocation_lock: RevocationLockBlindingFactor,
    /// The blinding factor for a [`BlindedState`] (associated with the current [`State`]).
    pub for_pay_token: PayTokenBlindingFactor,
    /// The blinding factor for a [`BlindedCloseState`] (associated with the current [`CloseState`]).
    pub for_close_state: CloseStateBlindingFactor,
}

impl PayProof {
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
        // Start range constraint on customer balance in the new state.
        let customer_range_constraint_builder =
            RangeConstraintBuilder::generate_constraint_commitments(
                state.customer_balance().into_inner() as i64,
                &params.range_constraint_parameters,
                rng,
            )
            .unwrap();

        // Start range constraint on merchant balance in the new state.
        let merchant_range_constraint_builder =
            RangeConstraintBuilder::generate_constraint_commitments(
                state.merchant_balance().into_inner() as i64,
                &params.range_constraint_parameters,
                rng,
            )
            .unwrap();

        let customer_balance_commitment_scalar =
            customer_range_constraint_builder.commitment_scalar();
        let merchant_balance_commitment_scalar =
            merchant_range_constraint_builder.commitment_scalar();

        // Start commitment proof to old revocation lock.
        let old_revocation_lock_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            old_state.revocation_lock().to_message(),
            &[None],
            &params.revocation_commitment_parameters,
        );

        // Retrieve commitment scalar for the old rev lock, to use in future constraints.
        let old_revlock_commitment_scalar =
            old_revocation_lock_proof_builder.conjunction_commitment_scalars()[0];

        // Start signature proof on old pay token. Add constraints:
        // - equality: revocation lock must match the one in the commitment to the old revocation lock;
        // - addition with public value: balances must be correlated with the values from the range constraints.
        let old_pay_token_proof_builder = SignatureProofBuilder::generate_proof_commitments(
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
        );

        // Retrieve commitment scalar corresponding to channel id, to use in future constraints.
        let channel_id_commitment_scalar =
            old_pay_token_proof_builder.conjunction_commitment_scalars()[0];

        // Start commitment proof on new state. Add constraints:
        // - equality: channel id must match the one in the pay token;
        // - equality: balances must match the values from the range constraint.
        let state_proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
            rng,
            state.to_message(),
            &[
                Some(channel_id_commitment_scalar),
                None,
                None,
                Some(customer_balance_commitment_scalar),
                Some(merchant_balance_commitment_scalar),
            ],
            params.merchant_public_key(),
        );

        // Extract commitment scalars from the state proof message to re-use in close state proof.
        // Recall: this only includes those for the 5-part message, *not* the commitment blinding factor.
        let cs = state_proof_builder.conjunction_commitment_scalars();

        // Start commitment proof on the new close state. Add constraints:
        // - equality: channel id must match the one in the state (this also implies equality with the pay token channel id);
        // - equality: revocation lock must match the one in the state;
        // - equality: balances must match the ones in the state (this also implies the addition constraint)
        let close_state_proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
            rng,
            state.close_state().to_message(),
            &[Some(cs[0]), None, Some(cs[2]), Some(cs[3]), Some(cs[4])],
            params.merchant_public_key(),
        );

        let blinding_factors = BlindingFactors {
            for_old_revocation_lock: RevocationLockBlindingFactor(
                old_revocation_lock_proof_builder.message_blinding_factor(),
            ),
            for_pay_token: PayTokenBlindingFactor(state_proof_builder.message_blinding_factor()),
            for_close_state: CloseStateBlindingFactor(
                close_state_proof_builder.message_blinding_factor(),
            ),
        };

        // Form a challenge.
        let challenge = ChallengeBuilder::new()
            // integrate keys and constants
            .with(&params.merchant_public_key)
            .with(params.range_constraint_parameters.public_key())
            .with(&old_state.nonce().as_scalar())
            .with(&CLOSE_SCALAR)
            // integrate commitments and commitment scalars from commitment proofs
            .with(&old_revocation_lock_proof_builder)
            .with(&state_proof_builder)
            .with(&close_state_proof_builder)
            // integrate signature and range constraints
            .with(&old_pay_token_proof_builder)
            .with(&customer_range_constraint_builder)
            .with(&merchant_range_constraint_builder)
            // integrate context
            .with_bytes(context.as_bytes())
            .finish();

        (
            Self {
                // Add commitment scalars for publicly revealed values: the old nonce and the close tag.
                old_nonce_commitment_scalar: old_pay_token_proof_builder
                    .conjunction_commitment_scalars()[1],
                close_tag_commitment_scalar: close_state_proof_builder
                    .conjunction_commitment_scalars()[1],
                // Complete the pay token signature proof.
                old_pay_token_proof: old_pay_token_proof_builder.generate_proof_response(challenge),
                // Complete the revocation lock proof.
                old_revocation_lock_proof: old_revocation_lock_proof_builder
                    .generate_proof_response(challenge),
                // Complete the state proof.
                state_proof: state_proof_builder.generate_proof_response(challenge),
                // Complete the close state proof.
                close_state_proof: close_state_proof_builder.generate_proof_response(challenge),
                // Complete the range constraints.
                customer_balance_proof: customer_range_constraint_builder
                    .generate_constraint_response(challenge),
                merchant_balance_proof: merchant_range_constraint_builder
                    .generate_constraint_response(challenge),
            },
            blinding_factors,
        )
    }

    /**
    Verify a PayProof against the given verification objects.

    This function is typically called by the merchant.
    */
    pub fn verify(
        self,
        params: &merchant::Config,
        public_values: &PayProofPublicValues,
        context: &Context,
    ) -> Option<(
        VerifiedBlindedState,
        VerifiedBlindedCloseState,
        RevocationLockCommitment,
    )> {
        // Form the challenge.
        let challenge = ChallengeBuilder::new()
            // integrate keys and constants
            .with(&params.signing_keypair.public_key())
            .with(params.range_constraint_parameters.public_key())
            .with(&public_values.old_nonce.as_scalar())
            .with(&CLOSE_SCALAR)
            // integrate commitments and commitment scalars from commitment proofs
            .with(&self.old_revocation_lock_proof)
            .with(&self.state_proof)
            .with(&self.close_state_proof)
            // integrate signature and range constraints
            .with(&self.old_pay_token_proof)
            .with(&self.customer_balance_proof)
            .with(&self.merchant_balance_proof)
            // integrate context
            .with_bytes(context.as_bytes())
            .finish();

        // Check that the individual signature and commitment proofs verify.
        let old_pay_token_proof_verifies = self
            .old_pay_token_proof
            .verify_knowledge_of_signature(params.signing_keypair.public_key(), challenge);

        let old_revlock_proof_verifies = self
            .old_revocation_lock_proof
            .verify_knowledge_of_opening(params.revocation_commitment_parameters(), challenge);

        let state_proof_verifies = self
            .state_proof
            .verify_knowledge_of_opening(params.signing_keypair().public_key(), challenge);

        let close_state_proof_verifies = self
            .close_state_proof
            .verify_knowledge_of_opening(params.signing_keypair().public_key(), challenge);

        // Retrieve response scalars for the message tuples in the state, close state, and old pay
        // token (old state). These are used to check constraints.
        let state_response_scalars = self.state_proof.conjunction_response_scalars();
        let close_state_response_scalars = self.close_state_proof.conjunction_response_scalars();
        let old_pay_token_response_scalars =
            self.old_pay_token_proof.conjunction_response_scalars();

        // Check that range constraints verify against the updated balances in the state.
        let customer_balance_proof_verifies = self.customer_balance_proof.verify_range_constraint(
            &params.range_constraint_parameters,
            challenge,
            state_response_scalars[3],
        );
        let merchant_balance_proof_verifies = self.merchant_balance_proof.verify_range_constraint(
            &params.range_constraint_parameters,
            challenge,
            state_response_scalars[4],
        );

        // check channel identifiers match.
        let channel_ids_match = state_response_scalars[0] == close_state_response_scalars[0]
            && close_state_response_scalars[0] == old_pay_token_response_scalars[0];

        // check close state contains close tag.
        let close_tag_matches_expected =
            challenge.to_scalar() * CLOSE_SCALAR + self.close_tag_commitment_scalar;
        let close_tag_matches = close_state_response_scalars[1] == close_tag_matches_expected;

        // check old revocation locks match each other
        let old_revlocks_match = self
            .old_revocation_lock_proof
            .conjunction_response_scalars()[0]
            == old_pay_token_response_scalars[2];

        // check new revocation locks match each other
        let new_revlocks_match = state_response_scalars[2] == close_state_response_scalars[2];

        // check pay token nonce matches the passed in nonce
        let pay_token_nonce_matches_expected = old_pay_token_response_scalars[1]
            == challenge.to_scalar() * public_values.old_nonce.as_scalar()
                + self.old_nonce_commitment_scalar;

        // check new balances match between state and close state
        let new_customer_balances_match =
            state_response_scalars[3] == close_state_response_scalars[3];
        let new_merchant_balances_match =
            state_response_scalars[4] == close_state_response_scalars[4];

        // check that customer and merchant balances were properly updated
        let customer_balance_properly_updated = state_response_scalars[3]
            == old_pay_token_response_scalars[3]
                - challenge.to_scalar() * public_values.amount.to_scalar();
        let merchant_balance_properly_updated = state_response_scalars[4]
            == old_pay_token_response_scalars[4]
                + challenge.to_scalar() * public_values.amount.to_scalar();

        match (
            state_proof_verifies,
            close_state_proof_verifies,
            old_pay_token_proof_verifies
                && old_revlock_proof_verifies
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
        ) {
            (Some(verified_state), Some(verified_close_state), true) => Some((
                VerifiedBlindedState(verified_state),
                VerifiedBlindedCloseState(verified_close_state),
                RevocationLockCommitment(self.old_revocation_lock_proof.commitment()),
            )),
            _ => None,
        }
    }
}

/**
Commitment to the [`State`] underlying a [`PayToken`] for use in a [`PayProof`]

Note: this is a commitment to the [`State`] for use in the proof of knowledge of the opening
of a _signature_. This makes it different from a [`BlindedState`], which is used in the
proof of knowledge of the opening of a _commitment_.

*/
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PayTokenCommitment(Commitment<G2Projective>);

/// Collects the information a merchant needs to verify a [`PayProof`].
#[derive(Debug, Clone, Copy)]
pub struct PayProofPublicValues {
    /// Expected nonce revealed at the beginning of Pay.
    pub old_nonce: Nonce,
    /// Expected payment amount.
    pub amount: PaymentAmount,
}

#[cfg(test)]
mod tests {
    use crate::{
        merchant,
        proofs::*,
        states::{ChannelId, CustomerBalance, MerchantBalance, State},
        RangeConstraintParameters,
    };
    use rand::SeedableRng;
    use std::time::Instant;
    use zkchannels_crypto::pointcheval_sanders::KeyPair;

    fn rng() -> impl Rng {
        let seed: [u8; 32] = *b"NEVER USE THIS FOR ANYTHING REAL";
        rand::rngs::StdRng::from_seed(seed)
    }

    fn channel_id(rng: &mut impl Rng) -> ChannelId {
        let cid_m = MerchantRandomness::new(rng);
        let cid_c = CustomerRandomness::new(rng);
        let pk = KeyPair::new(rng).public_key().clone();
        ChannelId::new(cid_m, cid_c, &pk, &[], &[])
    }

    #[test]
    fn establish_proof_verifies() {
        let _ = run_establish_proof(0, 100);
    }

    #[test]
    fn establish_proof_with_merch_balance_verifies() {
        let _ = run_establish_proof(100, 100);
    }

    #[test]
    fn establish_proof_only_merch_balance_verifies() {
        let _ = run_establish_proof(100, 0);
    }

    #[test]
    fn establish_proof_with_max_merch_balance_verifies() {
        let _ = run_establish_proof(i64::MAX as u64, 100);
    }

    #[test]
    fn establish_proof_with_max_cust_balance_verifies() {
        let _ = run_establish_proof(100, i64::MAX as u64);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_negative_customer_balance_rejected() {
        let _ = run_establish_proof(100, -5_i64 as u64);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_overflow_customer_balance_rejected() {
        let _ = run_establish_proof(100, i64::MAX as u64 + 1);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_negative_merchant_balance_rejected() {
        let _ = run_establish_proof(-5_i64 as u64, 100);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_overflow_merchant_balance_rejected() {
        let _ = run_establish_proof(i64::MAX as u64 + 1, 100);
    }

    fn run_establish_proof(
        merchant_balance: u64,
        customer_balance: u64,
    ) -> (VerifiedBlindedState, PayTokenBlindingFactor) {
        let mut rng = rng();
        let merchant_params = merchant::Config::new(&mut rng);
        let params = merchant_params.to_customer_config();

        // Create a new state.
        let channel_id = channel_id(&mut rng);
        let state = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(merchant_balance).unwrap(),
            CustomerBalance::try_new(customer_balance).unwrap(),
        );

        let context = Context::new(b"establish proof verify test");

        // Form proof, retrieve blinding factors
        let (proof, _, pay_token_bf) = EstablishProof::new(&mut rng, &params, &state, &context);

        // Proof must verify against the provided values.
        let public_values = EstablishProofPublicValues {
            channel_id: *state.channel_id(),
            merchant_balance: *state.merchant_balance(),
            customer_balance: *state.customer_balance(),
        };

        // Unwrap result - will panic if the proof is invalid.
        let (verified_state, _) = proof
            .verify(&merchant_params, &public_values, &context)
            .unwrap();

        // Return state and blinding factor (to be used in pay tests).
        (verified_state, pay_token_bf)
    }

    #[test]
    fn pay_proof_verifies() {
        run_pay_proof(0, 100, 10, PaymentAmount::pay_merchant);
    }

    #[test]
    fn pay_proof_with_negative_amount_verifies() {
        run_pay_proof(100, 100, 10, PaymentAmount::pay_customer);
    }

    #[test]
    #[should_panic(expected = "InsufficientFunds")]
    fn pay_proof_with_customer_going_negative() {
        run_pay_proof(100, 100, 101, PaymentAmount::pay_merchant);
    }

    #[test]
    #[should_panic(expected = "InsufficientFunds")]
    fn pay_proof_with_merchant_going_negative() {
        run_pay_proof(100, 100, 101, PaymentAmount::pay_customer);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn pay_proof_with_customer_going_above_max() {
        run_pay_proof(100, i64::MAX as u64, 100, PaymentAmount::pay_customer);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn pay_proof_with_merchant_going_above_max() {
        run_pay_proof(i64::MAX as u64, 100, 100, PaymentAmount::pay_merchant);
    }

    fn run_pay_proof(
        merchant_balance: u64,
        customer_balance: u64,
        amount: u64,
        pay: fn(u64) -> Result<PaymentAmount, crate::Error>,
    ) {
        let mut rng = rng();
        let merchant_params = merchant::Config::new(&mut rng);
        let params = merchant_params.to_customer_config();

        // Create a state.
        let channel_id = channel_id(&mut rng);
        let old_state = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(merchant_balance).unwrap(),
            CustomerBalance::try_new(customer_balance).unwrap(),
        );

        // Update state.
        let amount = pay(amount).unwrap();
        let new_state = old_state.apply_payment(&mut rng, amount).unwrap();

        // Run establish proof and sign result to get a valid signature on the old state.
        let (verified_state_com, old_pt_bf) =
            run_establish_proof(merchant_balance, customer_balance);
        let pay_token = BlindedPayToken::sign(&mut rng, &merchant_params, verified_state_com)
            .unblind(old_pt_bf);

        // Save a copy of the nonce...
        let nonce = *old_state.nonce();

        let context = Context::new(b"pay proof verify test");

        // Form proof.
        let (proof, _blinding_factors) = PayProof::new(
            &mut rng, &params, pay_token, &old_state, &new_state, &context,
        );

        // Verify proof against expected objects.
        let public_values = PayProofPublicValues {
            old_nonce: nonce,
            amount,
        };

        assert!(proof
            .verify(&merchant_params, &public_values, &context)
            .is_some());
    }

    #[test]
    #[cfg(feature = "bincode")]
    fn test_pay_proof_with_serialize() {
        let merchant_balance = 0;
        let customer_balance = 100;
        let amount = 10;
        let pay = PaymentAmount::pay_merchant;
        let mut rng = rng();
        let merchant_params = merchant::Config::new(&mut rng);
        let params = merchant_params.to_customer_config();

        // Create a state.
        let channel_id = channel_id(&mut rng);
        let old_state = State::new(
            &mut rng,
            channel_id,
            MerchantBalance::try_new(merchant_balance).unwrap(),
            CustomerBalance::try_new(customer_balance).unwrap(),
        );

        // Update state.
        let amount = pay(amount).unwrap();
        let new_state = old_state.apply_payment(&mut rng, amount).unwrap();

        // Run establish proof and sign result to get a valid signature on the old state.
        let (verified_state_com, old_pt_bf) =
            run_establish_proof(merchant_balance, customer_balance);
        let pay_token = BlindedPayToken::sign(&mut rng, &merchant_params, verified_state_com)
            .unblind(old_pt_bf);

        // Save a copy of the nonce...
        let nonce = *old_state.nonce();

        let context = Context::new(b"pay proof verify test");

        // Form proof.
        let param_ser = bincode::serialize(&params).unwrap();
        let start = Instant::now();
        let _ = bincode::deserialize::<customer::Config>(&param_ser).unwrap();
        let start1 = Instant::now();
        let (proof, _blinding_factors) = PayProof::new(
            &mut rng, &params, pay_token, &old_state, &new_state, &context,
        );
        println!(
            "create proof (with deserializing params): {:?}",
            start.elapsed()
        );
        println!("create proof: {:?}", start1.elapsed());

        // Verify proof against expected objects.
        let public_values = PayProofPublicValues {
            old_nonce: nonce,
            amount,
        };

        let param_ser = bincode::serialize(&merchant_params.range_constraint_parameters).unwrap();
        let start = Instant::now();
        let _ = bincode::deserialize::<RangeConstraintParameters>(&param_ser).unwrap();
        let start1 = Instant::now();
        assert!(proof
            .verify(&merchant_params, &public_values, &context)
            .is_some());
        println!(
            "verify proof (with deserializing params): {:?}",
            start.elapsed()
        );
        println!("verify proof: {:?}", start1.elapsed());
    }
}
