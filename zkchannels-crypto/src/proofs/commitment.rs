use crate::{
    common::*,
    pedersen::{Commitment, PedersenParameters},
    proofs::{Challenge, ChallengeBuilder, ChallengeInput},
    serde::SerializeElement,
};
use arrayvec::ArrayVec;
use ff::Field;
use group::Group;
use serde::*;

/// Fully constructed proof of knowledge of the opening of a commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "G: SerializeElement")]
pub struct CommitmentProof<G: Group<Scalar = Scalar>, const N: usize> {
    /// The commitment that implicitly represents the proof statement.
    commitment: Commitment<G>,
    /// The commitment to the commitment scalars.
    scalar_commitment: Commitment<G>,
    /// The response scalar for the blinding factor, conceptually prepended to the tuple of response
    /// scalars for this commitment proof.
    #[serde(with = "SerializeElement")]
    blinding_factor_response_scalar: Scalar,
    /// The remaining response scalars.
    ///
    /// Uses Box to avoid stack overflows for proofs on large messages.
    #[serde(with = "SerializeElement")]
    message_response_scalars: Box<[Scalar; N]>,
}

impl<G: Group<Scalar = Scalar>, const N: usize> CommitmentProof<G, N> {
    /// Verify knowledge of the opening of a commitment.
    pub fn verify_knowledge_of_opening_of_commitment(
        &self,
        pedersen_params: &PedersenParameters<G, N>,
        challenge: Challenge,
    ) -> bool {
        // Construct commitment to response scalars.
        let rhs = Message::new(*self.message_response_scalars).commit(
            pedersen_params,
            BlindingFactor::from_scalar(self.blinding_factor_response_scalar),
        );

        let expected_commitment = self.scalar_commitment.to_element()
            + (self.commitment.to_element() * challenge.to_scalar());

        // Compare to challenge, commitments to message, scalars
        rhs.to_element() == expected_commitment
    }

    /// Get the response scalars corresponding to the message to verify conjunctions of proofs.
    ///
    /// This does not include the response scalar for the blinding factor.
    pub fn conjunction_response_scalars(&self) -> &[Scalar; N] {
        &self.message_response_scalars
    }

    /// Get the commitment to the response scalars.
    fn scalar_commitment(&self) -> Commitment<G> {
        self.scalar_commitment
    }

    /// Get the commitment to the message
    pub fn commitment(&self) -> Commitment<G> {
        self.commitment
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeInput
    for CommitmentProof<G, N>
{
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.commitment());
        builder.consume(&self.scalar_commitment());
    }
}

/// A partially-built [`CommitmentProof`].
///
/// Built up to (but not including) the challenge phase of a Schnorr proof.
#[derive(Debug, Clone)]
pub struct CommitmentProofBuilder<G: Group<Scalar = Scalar>, const N: usize> {
    /// The message used to define the proof statement.
    msg: Message<N>,
    /// The commitment that implicitly represents the proof statement.
    commitment: Commitment<G>,
    /// The blinding factor of the commitment that implicitly represents the proof statement.
    message_blinding_factor: BlindingFactor,
    /// Commitment to the commitment scalars.
    scalar_commitment: Commitment<G>,
    /// The commitment scalar for the blinding factor.
    blinding_factor_commitment_scalar: Scalar,
    /// The commitment scalars for the message, conceptually appended to the commitment scalar for
    /// the blinding factor.
    ///
    /// Uses Box to avoid stack overflows for proofs on large messages.
    message_commitment_scalars: Box<[Scalar; N]>,
}

impl<G: Group<Scalar = Scalar>, const N: usize> CommitmentProofBuilder<G, N> {
    /// Run the commitment phase of a Schnorr-style commitment proof.
    ///
    /// This is a proof of knowledge of the message `msg`.
    /// The `conjunction_commitment_scalars` argument allows the caller to choose particular
    /// commitment scalars for the message tuple. This allows them to express constraints among
    /// messages in one or more proof objects. For example, equality of two message elements is
    /// enforced by using the same commitment scalar for those elements. A linear equation (message
    /// tuples `a`, `b`, `c` where `c = a + b`) is enforced by setting the commitment scalar for `c`
    /// to the sum of the commitment scalars for `a` and `b`.
    pub fn generate_proof_commitments(
        rng: &mut impl Rng,
        msg: Message<N>,
        conjunction_commitment_scalars: &[Option<Scalar>; N],
        pedersen_params: &PedersenParameters<G, N>,
    ) -> Self {
        let message_blinding_factor = BlindingFactor::new(&mut *rng);
        let commitment = msg.commit(pedersen_params, message_blinding_factor);

        let blinding_factor_commitment_scalar = Scalar::random(&mut *rng);
        // Choose commitment scalars (that haven't already been specified)
        let message_commitment_scalars = Box::new(
            conjunction_commitment_scalars
                .iter()
                .map(|&maybe_scalar| maybe_scalar.unwrap_or_else(|| Scalar::random(&mut *rng)))
                .collect::<ArrayVec<_, N>>()
                .into_inner()
                .expect("length mismatch impossible"),
        );

        // Commit to the scalars
        let scalar_commitment = Message::new(*message_commitment_scalars).commit(
            pedersen_params,
            BlindingFactor::from_scalar(blinding_factor_commitment_scalar),
        );

        Self {
            msg,
            commitment,
            message_blinding_factor,
            scalar_commitment,
            blinding_factor_commitment_scalar,
            message_commitment_scalars,
        }
    }

    /// Get the commitment.
    pub fn commitment(&self) -> Commitment<G> {
        self.commitment
    }

    /// Get the blinding factor
    pub fn message_blinding_factor(&self) -> BlindingFactor {
        self.message_blinding_factor
    }

    /// Get the commitment scalars corresponding to the message tuple to use when constructing
    /// conjunctions of proofs.
    ///
    /// This does not include the commitment scalar corresponding to the blinding factor.
    pub fn conjunction_commitment_scalars(&self) -> &[Scalar; N] {
        &self.message_commitment_scalars
    }

    /// Get the commitment to the response scalars.
    fn scalar_commitment(&self) -> Commitment<G> {
        self.scalar_commitment
    }

    /// Run the response phase of the Schnorr-style commitment proof to complete the proof.
    pub fn generate_proof_response(self, challenge: Challenge) -> CommitmentProof<G, N> {
        // Generate response scalars.
        let blinding_factor_response_scalar = challenge.to_scalar()
            * self.message_blinding_factor.as_scalar()
            + self.blinding_factor_commitment_scalar;
        let message_response_scalars = Box::new(
            self.msg
                .iter()
                .zip(&*self.message_commitment_scalars)
                .map(|(mi, cs)| challenge.to_scalar() * mi + cs)
                .collect::<ArrayVec<_, N>>()
                .into_inner()
                .expect("length mismatch impossible"),
        );

        CommitmentProof {
            commitment: self.commitment,
            scalar_commitment: self.scalar_commitment,
            blinding_factor_response_scalar,
            message_response_scalars,
        }
    }
}

impl<G: Group<Scalar = Scalar> + GroupEncoding, const N: usize> ChallengeInput
    for CommitmentProofBuilder<G, N>
{
    fn consume(&self, builder: &mut ChallengeBuilder) {
        builder.consume(&self.commitment());
        builder.consume(&self.scalar_commitment());
    }
}
