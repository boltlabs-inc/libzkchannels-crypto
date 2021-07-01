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
    customer, merchant, revlock::*, states::*, types::*, Nonce, PaymentAmount, Rng, Verification,
    CLOSE_SCALAR,
};

use zkchannels_crypto::{
    pedersen::Commitment,
    proofs::{
        ChallengeBuilder, CommitmentProof, CommitmentProofBuilder, RangeConstraint,
        RangeConstraintBuilder, SignatureProof, SignatureProofBuilder,
    },
    Message, SerializeElement,
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
    state_proof: CommitmentProof<G1Projective, 5>,
    close_state_proof: CommitmentProof<G1Projective, 5>,
}

#[allow(unused)]
impl EstablishProof {
    /// Retrieve the state commitment for the proof.
    pub(crate) fn extract_commitments(self) -> (StateCommitment, CloseStateCommitment) {
        (
            StateCommitment::new(self.state_proof.commitment()),
            CloseStateCommitment::new(self.close_state_proof.commitment()),
        )
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
        // Commit to state and corresponding close state.
        let (state_commitment, pay_token_blinding_factor) = state.commit(rng, &params);
        let (close_state_commitment, close_state_blinding_factor) =
            state.close_state().commit(rng, &params);

        let pedersen_parameters = params.merchant_public_key.to_g1_pedersen_parameters();

        // Start commitment proof to the new state.
        let state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            state_commitment.0.to_commitment(),
            &[None; 5],
            &pedersen_parameters,
        );

        // Extract commitment scalars from the state proof message to re-use in close state proof.
        // Recall: this only includes those for the 5-part message, *not* the commitment blinding factor.
        let cs = state_proof_builder.conjunction_commitment_scalars();

        // Start commitment proof to the new close state. Add constraints:
        // - equality: channel id must match the one in the new state;
        // - equality: revocation lock must match the one in the new state;
        // - equality: balances must match the one in the new state;
        // Recall: the proof builder *always* chooses a random commitment scalar for the
        // blinding factor.
        let close_state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            close_state_commitment.0.to_commitment(),
            &[Some(cs[0]), None, Some(cs[2]), Some(cs[3]), Some(cs[4])],
            &pedersen_parameters,
        );

        // Form a challenge.
        let challenge = ChallengeBuilder::new()
            .with(&params.merchant_public_key)
            .with(&state.channel_id().to_scalar())
            .with(&CLOSE_SCALAR)
            .with(&state.customer_balance().to_scalar())
            .with(&state.merchant_balance().to_scalar())
            .with(&state_proof_builder)
            .with(&close_state_proof_builder)
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
                state_proof: state_proof_builder.generate_proof_response(
                    &state.to_message(),
                    pay_token_blinding_factor.0,
                    challenge,
                ),

                // Complete commitment proof on the close state.
                close_state_proof: close_state_proof_builder.generate_proof_response(
                    &state.close_state().to_message(),
                    close_state_blinding_factor.0,
                    challenge,
                ),
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
            .with(params.signing_keypair.public_key())
            .with(&public_values.channel_id.to_scalar())
            .with(&CLOSE_SCALAR)
            .with(&public_values.customer_balance.to_scalar())
            .with(&public_values.merchant_balance.to_scalar())
            .with(&self.state_proof)
            .with(&self.close_state_proof)
            .with_bytes(context.as_bytes())
            .finish();

        let pedersen_parameters = params
            .signing_keypair
            .public_key()
            .to_g1_pedersen_parameters();

        // Check that the state proof verifies.
        let state_proof_verifies = self
            .state_proof
            .verify_knowledge_of_opening_of_commitment(&pedersen_parameters, challenge);

        // Check that the close state proof verifies.
        let close_state_proof_verifies = self
            .close_state_proof
            .verify_knowledge_of_opening_of_commitment(&pedersen_parameters, challenge);

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
    old_nonce_commitment_scalar: Scalar,
    #[serde(with = "SerializeElement")]
    close_tag_commitment_scalar: Scalar,

    // Proof objects.
    old_pay_token_proof: SignatureProof<5>,
    old_revocation_lock_proof: CommitmentProof<G1Projective, 1>,
    state_proof: CommitmentProof<G1Projective, 5>,
    close_state_proof: CommitmentProof<G1Projective, 5>,
    customer_balance_proof: RangeConstraint,
    merchant_balance_proof: RangeConstraint,
}

/// Blinding factors for commitments associated with a particular payment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct BlindingFactors {
    /// The blinding factor for a [`RevocationLockCommitment`] (associated with the previous [`State`])
    pub for_old_revocation_lock: RevocationLockBlindingFactor,
    /// The blinding factor for a [`StateCommitment`] (associated with the current [`State`]).
    pub for_pay_token: PayTokenBlindingFactor,
    /// The blinding factor for a [`CloseStateCommitment`] (associated with the current [`CloseState`]).
    pub for_close_state: CloseStateBlindingFactor,
}

#[allow(unused)]
impl PayProof {
    /// Get the revocation lock commitment out of the proof.
    pub(crate) fn old_revocation_lock_commitment(&self) -> RevocationLockCommitment {
        RevocationLockCommitment(self.old_revocation_lock_proof.commitment())
    }

    /// Get the state commitment out of the proof.
    pub(crate) fn state_commitment(&self) -> StateCommitment {
        StateCommitment::new(self.state_proof.commitment())
    }

    /// Get the close state commitment out of the proof.
    pub(crate) fn close_state_commitment(&self) -> CloseStateCommitment {
        CloseStateCommitment::new(self.close_state_proof.commitment())
    }

    pub(crate) fn extract_commitments(
        self,
    ) -> (
        RevocationLockCommitment,
        StateCommitment,
        CloseStateCommitment,
    ) {
        (
            RevocationLockCommitment(self.old_revocation_lock_proof.commitment()),
            StateCommitment::new(self.state_proof.commitment()),
            CloseStateCommitment::new(self.close_state_proof.commitment()),
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
        let (old_revocation_lock_commitment, revocation_lock_bf) =
            old_state.commit_to_revocation(rng, params);
        let (state_commitment, state_bf) = state.commit(rng, params);
        let (close_state_commitment, close_state_bf) = state.close_state().commit(rng, params);

        let blinding_factors = BlindingFactors {
            for_old_revocation_lock: revocation_lock_bf,
            for_pay_token: state_bf,
            for_close_state: close_state_bf,
        };

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
            old_revocation_lock_commitment.0,
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
        let state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            state_commitment.0.to_commitment(),
            &[
                Some(channel_id_commitment_scalar),
                None,
                None,
                Some(customer_balance_commitment_scalar),
                Some(merchant_balance_commitment_scalar),
            ],
            &pedersen_parameters,
        );

        // Extract commitment scalars from the state proof message to re-use in close state proof.
        // Recall: this only includes those for the 5-part message, *not* the commitment blinding factor.
        let cs = state_proof_builder.conjunction_commitment_scalars();

        // Start commitment proof on the new close state. Add constraints:
        // - equality: channel id must match the one in the state (this also implies equality with the pay token channel id);
        // - equality: revocation lock must match the one in the state;
        // - equality: balances must match the ones in the state (this also implies the addition constraint)
        let close_state_proof_builder = CommitmentProofBuilder::generate_proof_commitments(
            rng,
            close_state_commitment.0.to_commitment(),
            &[Some(cs[0]), None, Some(cs[2]), Some(cs[3]), Some(cs[4])],
            &pedersen_parameters,
        );

        // Form a challenge.
        let challenge = ChallengeBuilder::new()
            // integrate keys and constants
            .with(&params.merchant_public_key)
            .with(params.range_constraint_parameters.public_key())
            .with(&old_state.nonce().as_scalar())
            .with(&CLOSE_SCALAR)
            // integrate commitment scalars from commitment proofs
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
                    .generate_proof_response(
                        &Message::from(old_state.revocation_lock().to_scalar()),
                        blinding_factors.for_old_revocation_lock.0,
                        challenge,
                    ),
                // Complete the state proof.
                state_proof: state_proof_builder.generate_proof_response(
                    &state.to_message(),
                    blinding_factors.for_pay_token.0,
                    challenge,
                ),
                // Complete the close state proof.
                close_state_proof: close_state_proof_builder.generate_proof_response(
                    &state.close_state().to_message(),
                    blinding_factors.for_close_state.0,
                    challenge,
                ),
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
        &self,
        params: &merchant::Config,
        public_values: &PayProofPublicValues,
        context: &Context,
    ) -> Verification {
        // Form the challenge.
        let challenge = ChallengeBuilder::new()
            // integrate keys and constants
            .with(&params.signing_keypair.public_key())
            .with(params.range_constraint_parameters.public_key())
            .with(&public_values.old_nonce.as_scalar())
            .with(&CLOSE_SCALAR)
            // integrate commitment scalars from commitment proofs
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

        let pedersen_parameters = params
            .signing_keypair
            .public_key()
            .to_g1_pedersen_parameters();

        // Check that the individual signature and commitment proofs verify.
        let old_pay_token_proof_verifies = self
            .old_pay_token_proof
            .verify_knowledge_of_signature(params.signing_keypair.public_key(), challenge);

        let old_revlock_proof_verifies = self
            .old_revocation_lock_proof
            .verify_knowledge_of_opening_of_commitment(
                &params.revocation_commitment_parameters,
                challenge,
            );

        let state_proof_verifies = self
            .state_proof
            .verify_knowledge_of_opening_of_commitment(&pedersen_parameters, challenge);

        let close_state_proof_verifies = self
            .close_state_proof
            .verify_knowledge_of_opening_of_commitment(&pedersen_parameters, challenge);

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

        Verification::from(
            old_pay_token_proof_verifies
                && old_revlock_proof_verifies
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
    };
    use rand::SeedableRng;
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
        run_establish_proof(0, 100);
    }

    #[test]
    fn establish_proof_with_merch_balance_verifies() {
        run_establish_proof(100, 100);
    }

    #[test]
    fn establish_proof_only_merch_balance_verifies() {
        run_establish_proof(100, 0);
    }

    #[test]
    fn establish_proof_with_max_merch_balance_verifies() {
        run_establish_proof(i64::MAX as u64, 100);
    }

    #[test]
    fn establish_proof_with_max_cust_balance_verifies() {
        run_establish_proof(100, i64::MAX as u64);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_negative_customer_balance_rejected() {
        run_establish_proof(100, -5_i64 as u64);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_overflow_customer_balance_rejected() {
        run_establish_proof(100, i64::MAX as u64 + 1);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_negative_merchant_balance_rejected() {
        run_establish_proof(-5_i64 as u64, 100);
    }

    #[test]
    #[should_panic(expected = "AmountTooLarge")]
    fn establish_proof_overflow_merchant_balance_rejected() {
        run_establish_proof(i64::MAX as u64 + 1, 100);
    }

    fn run_establish_proof(merchant_balance: u64, customer_balance: u64) {
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

        // Get a pay token AKA signature on the old state.
        let (old_state_com, old_pt_bf) = old_state.commit(&mut rng, &params);
        let pay_token =
            BlindedPayToken::sign(&mut rng, &merchant_params, &old_state_com).unblind(old_pt_bf);

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

        assert!(matches!(
            proof.verify(&merchant_params, &public_values, &context),
            Verification::Verified
        ));
    }
}
