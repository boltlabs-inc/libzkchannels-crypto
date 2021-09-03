//! Constraint that a message lies within the range `[0, 2^63)`.

use crate::{
    common::*,
    pointcheval_sanders::{KeyPair, PublicKey, Signature},
    proofs::{Challenge, ChallengeBuilder, ChallengeInput, SignatureProof, SignatureProofBuilder},
};
use arrayvec::ArrayVec;
use serde::*;
use std::convert::TryFrom;
use thiserror::Error;

/// The error type returned when attempting to form a range constraint for a value outside the range.
#[derive(Debug, Clone, Copy, Error)]
#[error("cannot form a range constraint for a value outside the range of [0, 2^63) (received {0})")]
pub struct ValueOutsideRange(pub i64);

/// The arity of our digits used in the range constraint.
const RP_PARAMETER_U: u64 = 128;

/// Number of digits used in the range constraint.
const RP_PARAMETER_L: usize = 9;

/// Parameters used to create and verify a [`RangeConstraint`].
///
/// **Usage**: These should be generated by a trusted party (e.g. the verifier) and can be shared
/// with any potential provers. They are computatationally intesive to generate but can be reused
/// to generate any number of [`RangeConstraint`]s.
///
/// These parameters contain Pointcheval-Sanders [`Signature`]s on on each possible `u`-ary digit
/// --- here, the values 0 to 128.
/// The signatures are formed with a Pointcheval-Sanders key; the secret part is discarded after
/// generation.
/// This follows the work of Camenish, Chaabouni, and shelat. See [`RangeConstraint`] for citation.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedRangeConstraintParameters")]
pub struct RangeConstraintParameters {
    /// A signature on every `u`-ary digit
    ///
    /// Uses Box to avoid stack overflows (since U is large).
    #[serde(with = "crate::serde::big_boxed_array")]
    digit_signatures: Box<[Signature; RP_PARAMETER_U as usize]>,
    /// Public key corresponding _exclusively with the signatures above.
    public_key: PublicKey<1>,
}

/// Parameters for a [`RangeConstraint`] before validation.
///
/// Used during deserialization before validation checks have been done.
#[derive(Debug, Deserialize)]
struct UncheckedRangeConstraintParameters {
    #[serde(with = "crate::serde::big_boxed_array")]
    digit_signatures: Box<[Signature; RP_PARAMETER_U as usize]>,
    public_key: PublicKey<1>,
}

impl TryFrom<UncheckedRangeConstraintParameters> for RangeConstraintParameters {
    type Error = String;
    /// During deserialization verify the signature inside the RangeConstraintParameters are valid signatures on the appropriate scalars
    fn try_from(unchecked: UncheckedRangeConstraintParameters) -> Result<Self, Self::Error> {
        let UncheckedRangeConstraintParameters {
            digit_signatures,
            public_key,
        } = unchecked;
        for (i, sig) in digit_signatures.iter().enumerate() {
            if !sig.verify(&public_key, &Scalar::from(i as u64).into()) {
                return Err("The signatures in the RangeConstraintParameters must be valid signatures on the appropriate scalars".to_string());
            }
        }

        Ok(RangeConstraintParameters {
            digit_signatures,
            public_key,
        })
    }
}

#[cfg(feature = "sqlite")]
crate::impl_sqlx_for_bincode_ty!(RangeConstraintParameters);

impl RangeConstraintParameters {
    /// Generate new parameters for use in range constraints.
    ///
    /// Note that this generates a [`KeyPair`](crate::pointcheval_sanders::KeyPair) to produce the
    /// `digit_signatures`, but discards the secret half after use. This is to prevent misuse; it
    /// should never be used again.
    pub fn new(rng: &mut impl Rng) -> Self {
        // Workaround for not being able to use `as` in const type variables for now.
        const RP_PARAMETER_U_AS_USIZE: usize = RP_PARAMETER_U as usize;
        let keypair = KeyPair::<1>::new(rng);
        let digit_signatures = (0..RP_PARAMETER_U)
            .map(|i| Signature::new(rng, &keypair, &Scalar::from(i).into()))
            .collect::<ArrayVec<_, RP_PARAMETER_U_AS_USIZE>>();

        RangeConstraintParameters {
            digit_signatures: Box::new(digit_signatures.into_inner().expect("known length")),
            public_key: keypair.public_key().clone(),
        }
    }

    /// Return the public key used to form the `RangeConstraintParameters`.
    pub fn public_key(&self) -> &PublicKey<1> {
        &self.public_key
    }
}

/// A partially-built [`RangeConstraint`].
///
/// It represents the output of the setup and commitment phases of the proofs of knowledge of
/// [signatures](SignatureProof) on the digits of the constrained value.
#[derive(Debug)]
pub struct RangeConstraintBuilder {
    /// Partially-constructed proofs of knowledge of the opening of signatures on each digit.
    ///
    /// Uses Box to avoid stack overflows (since U is large).
    digit_proof_builders: Box<[SignatureProofBuilder<1>; RP_PARAMETER_L]>,
    /// Commitment scalar for the value being proven in the range.
    commitment_scalar: Scalar,
}

/// Constraint on knowledge of a value in the range `[0, 2^63)`.
/// This is **not** a complete range proof unless supplied in conjunction with a
/// [`CommitmentProof`](crate::proofs::CommitmentProof), a [`SignatureProof`], or a
/// [`SignatureRequestProof`](crate::proofs::SignatureRequestProof).
///
/// # Algorithm
/// This is a Camenish, Chaabouni, and shelat-style range constraint \[2\] built using standard
/// Schnorr. It replaces the signature scheme in \[2\] with single-message Pointcheval-Sanders
/// signatures \[1\], and uses the pairing in BLS12-381 \[3\].
/// It does not support the techniques in \[2\] for constraints over an arbitrary interval, and
/// the parameters are fixed as `u = 128` and `l = 9`.
///
/// Since the range constraint is formed using a set of [`SignatureProof`]s, it follows the
/// standard Schnorr 3-phase procedure: commit, challenge, response.
/// The [`RangeConstraintBuilder`] type has functions to execute the
/// [commitment](RangeConstraintBuilder::generate_constraint_commitments()) and
/// [response](RangeConstraintBuilder::generate_constraint_response()) phases.
///
/// # Intuition
/// The prover writes the value in `u`-ary. That is, a value `B` is written `B0 .. Bl`, where each
/// `Bi` is in the range `[0,u)`. These have the property that `B = sum( u^i * Bi )`.
///
/// The prover proves knowledge of a signature on each digit and proves that the digits are a
/// correct `u`-ary representation of the value.
/// [Signatures on each possible digit](RangeConstraintParameters) are provided by a party trusted
/// by the verifier: this party publishes signatures on the values 0 to `u`.
/// The signing key is discarded after use so it cannot produce signatures on invalid digits.
///
/// A `RangeConstraint` describes a proof of knowledge of the digit signatures for a given value.
/// However, it alone *does not* show that the digits match a meaningful value!
/// This step requires a conjunction with a `Proof` type
/// (see module-level documentation for additional details).
///
/// # References
/// 1. David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor,
///    Topics in Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International
///    Publishing, Cham, 2016.
///
/// 2. Jan Camenisch, Rafik Chaabouni, and abhi shelat. Efficient protocols for set membership and
///    range proofs. In Josef Pieprzyk, editor, Advances in Cryptology - ASIACRYPT 2008, pages
///    234–252, Berlin, Heidelberg, 2008. Springer Berlin Heidelberg.
///
/// 3. Dan Boneh, Sergey Gorbunov, Riad S. Wahby, Hoeteck Wee, and Zhenfei Zhang. BLS Signatures,
///    revision 4. Internet draft, Internet Engineering Task Force, 2020.
///    <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04>
///
#[derive(Debug, Serialize, Deserialize)]
pub struct RangeConstraint {
    /// Complete PoKs of the opening of a signature on each digit of the value.
    ///
    /// Uses Box to avoid stack overflows (since U is large).
    digit_proofs: Box<[SignatureProof<1>; RP_PARAMETER_L]>,
}

impl RangeConstraintBuilder {
    /// Run the commitment phase of a Schnorr-style range constraint on the value, to show that
    /// `0 <= value < 2^63`.
    pub fn generate_constraint_commitments(
        value: i64,
        params: &RangeConstraintParameters,
        rng: &mut impl Rng,
    ) -> Result<Self, ValueOutsideRange> {
        // Make sure value lies within the correct range: a normal i64 is in the range [-2^63, 2^63).
        // A non-negative i64 must be in the range [0, 2^63).
        if value.is_negative() {
            return Err(ValueOutsideRange(value));
        }
        // It is now safe to convert to u64 (the value cannot be in the overflow range [2^63, 2^64).)
        let mut decomposing_value = value as u64;

        // Decompose the value into digits.
        let mut digits = [0; RP_PARAMETER_L];
        for digit in &mut digits {
            *digit = decomposing_value % RP_PARAMETER_U;
            decomposing_value /= RP_PARAMETER_U;
        }

        // Compute signature proof builders on each digit.
        let digit_proof_builders: Box<[SignatureProofBuilder<1>; RP_PARAMETER_L]> = Box::new(
            digits
                .iter()
                .map(|&digit| {
                    SignatureProofBuilder::generate_proof_commitments(
                        rng,
                        // N.B. u64s are being encoded to `Scalar`s using the builtin bls12_381
                        // `From<u64>` implementation.
                        Scalar::from(digit).into(),
                        params.digit_signatures[digit as usize],
                        &[None],
                        &params.public_key,
                    )
                })
                .collect::<ArrayVec<_, RP_PARAMETER_L>>()
                .into_inner()
                .expect("impossible; len will always be RP_PARAMETER_L"),
        );

        // Construct cumulative commitment scalar for value from the commitment scalars of its digits.
        let mut commitment_scalar = Scalar::zero();
        // u_pow holds the term u^j for j = 0 .. RP_PARAMETER_L
        let mut u_pow = Scalar::one();
        // Compute sum ( u^j * commitment_scalar[j] )
        for proof_builder in &*digit_proof_builders {
            // The message here is always of length 1, so it's always okay to index it at the 0th element.
            commitment_scalar += u_pow * proof_builder.conjunction_commitment_scalars()[0];
            u_pow *= Scalar::from(RP_PARAMETER_U);
        }

        Ok(Self {
            digit_proof_builders,
            commitment_scalar,
        })
    }

    /// Run the response phase of a Schnorr-style constraint that a value is in a range.
    pub fn generate_constraint_response(self, challenge: Challenge) -> RangeConstraint {
        let digit_proofs = Box::new(
            ArrayVec::from(*self.digit_proof_builders)
                .into_iter()
                .map(|builder| builder.generate_proof_response(challenge))
                .collect::<ArrayVec<_, RP_PARAMETER_L>>()
                .into_inner()
                .expect("impossible; len will always be RP_PARAMETER_L"),
        );

        RangeConstraint { digit_proofs }
    }

    /// Get the commitment scalar to the cumulative sum of the commitment scalars of the range constraint
    /// digits.
    pub fn commitment_scalar(&self) -> Scalar {
        self.commitment_scalar
    }
}

impl ChallengeInput for RangeConstraintBuilder {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        for digit_proof in &*self.digit_proof_builders {
            builder.consume(digit_proof);
        }
    }
}

impl RangeConstraint {
    /// Verify that the PoKs on the opening of signatures for each digit are valid.
    fn verify_range_constraint_digits(
        &self,
        params: &RangeConstraintParameters,
        challenge: Challenge,
    ) -> bool {
        for proof in &*self.digit_proofs {
            if !proof.verify_knowledge_of_signature(&params.public_key, challenge) {
                return false;
            }
        }

        true
    }

    /// Verify that the response scalar for a given value is correctly constructed from the range
    /// constraint digits.
    pub fn verify_range_constraint(
        &self,
        params: &RangeConstraintParameters,
        challenge: Challenge,
        expected_response_scalar: Scalar,
    ) -> bool {
        let valid_digits = self.verify_range_constraint_digits(params, challenge);

        // Construct cumulative response scalar from the response scalars of the individual digits.
        let mut response_scalar = Scalar::zero();
        // u_pow holds the term u^j for j = 0 .. RP_PARAMETER_L
        let mut u_pow = Scalar::one();
        // sum ( u^j * response_scalar[j] )
        for proof in &*self.digit_proofs {
            response_scalar += u_pow * proof.conjunction_response_scalars()[0];
            u_pow *= Scalar::from(RP_PARAMETER_U);
        }

        valid_digits && response_scalar == expected_response_scalar
    }
}

impl ChallengeInput for RangeConstraint {
    fn consume(&self, builder: &mut ChallengeBuilder) {
        for digit_proof in &*self.digit_proofs {
            builder.consume(digit_proof);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::rng;
    use crate::SerializeElement;
    use ff::Field;
    use rand::Rng;
    use std::convert::TryFrom;
    use std::iter;

    pub struct CommitmentProofBuilderWithPublicFields<G: Group<Scalar = Scalar>, const N: usize> {
        pub msg: Message<N>,
        pub commitment: Commitment<G>,
        pub message_blinding_factor: BlindingFactor,
        pub scalar_commitment: Commitment<G>,
        pub blinding_factor_commitment_scalar: Scalar,
        pub message_commitment_scalars: Box<[Scalar; N]>,
    }

    pub struct SignatureProofBuilderWithPublicFields<const N: usize> {
        pub blinded_signature: BlindedSignature,
        pub commitment_proof_builder: CommitmentProofBuilder<G2Projective, N>,
    }

    #[test]
    fn test_range_constraint_challenge() {
        run_test_range_constraint_challenge::<1>();
        run_test_range_constraint_challenge::<2>();
        run_test_range_constraint_challenge::<3>();
        run_test_range_constraint_challenge::<5>();
        run_test_range_constraint_challenge::<8>();
        run_test_range_constraint_challenge::<13>();
    }

    fn run_test_range_constraint_challenge<const N: usize>() {
        let mut rng = rng();

        // Generate message and signature.
        let range_tested_value = rng.gen_range(0..i64::MAX) as u32;

        // Proof commitment phase. Form range constraint on element and use resulting commitment scalar in
        // signature proof.
        let rp_params = RangeConstraintParameters::new(&mut rng);
        let range_constraint_builder = RangeConstraintBuilder::generate_constraint_commitments(
            range_tested_value.into(),
            &rp_params,
            &mut rng,
        )
        .unwrap();

        let builder_challenge = ChallengeBuilder::new()
            .with(&range_constraint_builder)
            .finish();
        let constraint = range_constraint_builder.generate_constraint_response(builder_challenge);
        let constraint_challenge = ChallengeBuilder::new().with(&constraint).finish();
        assert_eq!(
            builder_challenge.to_scalar(),
            constraint_challenge.to_scalar()
        );
    }

    /// Test the validation code during deserialization of the range constraint parameters
    #[test]
    #[cfg(feature = "bincode")]
    fn serialize_deserialize_range_constraint_parameters() {
        let mut rng = rng();
        let params = RangeConstraintParameters::new(&mut rng);

        // Check normal serialization/deserialization
        let ser_params = bincode::serialize(&params).unwrap();
        let new_params = bincode::deserialize::<RangeConstraintParameters>(&ser_params).unwrap();
        assert_eq!(params, new_params);

        // Check validation when the first signature is a signature on the second element
        let mut bad_params = RangeConstraintParameters::new(&mut rng);
        let mut sigs = bad_params.digit_signatures.to_vec();
        sigs[0] = sigs[1];
        bad_params.digit_signatures = Box::try_from(sigs.into_boxed_slice()).unwrap();
        let ser_params = bincode::serialize(&bad_params).unwrap();
        assert!(bincode::deserialize::<RangeConstraintParameters>(&ser_params).is_err());

        // Check validation when a signature at random position is a random signature
        let mut bad_params = RangeConstraintParameters::new(&mut rng);
        let mut sigs = bad_params.digit_signatures.to_vec();
        let kp = KeyPair::<5>::new(&mut rng);
        let msg = Message::<5>::random(&mut rng);
        let pos = rng.gen_range(0..RP_PARAMETER_U as usize);
        sigs[pos] = Signature::new(&mut rng, &kp, &msg);
        bad_params.digit_signatures = Box::try_from(sigs.into_boxed_slice()).unwrap();
        let ser_params = bincode::serialize(&bad_params).unwrap();
        assert!(bincode::deserialize::<RangeConstraintParameters>(&ser_params).is_err());
    }
}
