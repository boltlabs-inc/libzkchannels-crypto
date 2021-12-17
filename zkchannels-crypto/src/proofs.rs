//! Schnorr-based zero-knowledge proofs of knowledge for Pedersen commitments and Pointcheval
//! Sanders efficient protocols.
//!
//! In addition to standard proofs of knowledge of an opening of a commitment or of a signature on
//! a committed message, these proofs are designed to be combinable and to support a variety of
//! common constraints:
//! - Linear relationships of committed messages;
//! - Partial openings of committed messages;
//! - Range constraints for the range `[0, 2^63)`.
//!
//! This module provides convenient constructors and verification functions for the types of
//! proof and constraints described above. The API allows users to manually _combine_
//! these proofs to form complex proof statements and to manually verify these additional
//! constraints.
//!
//!
//! # Proofs
//! Each proof and constraint is constructed with a three phase process, based on the original
//! Schnorr protocol [\[1\]](#references). This section gives a generic overview of the
//! construction of a proof.
//!
//! 1. **Commit**. The prover forms a commitment to the underlying message. Some proof types
//!    require additional information at this step. The prover chooses
//!    "commitment scalars" for each message in the tuple and the commitment blinding factor
//!    and form a commitment to the commitment scalars.
//!
//!    This step is executed in the `generate_proof_commitments()` functions; the result is stored
//!    in the `ProofBuilder` types.
//!
//! 2. **Challenge**. In an interactive proof, the prover obtains a random challenge from the
//!     verifier. However, it is standard practice to use the Fiat-Shamir heuristic to transform an
//!     interactive proof into a non-interactive proof; see [`Challenge`] for details.
//!
//! 3. **Response**. The prover constructs response scalars, which mask each element of the message
//!     tuple and the blinding factor with the corresponding commitment scalar and the challenge.
//!
//!     This step is executed in the `generate_proof_response()` functions; the completed proof is
//!     stored in the `Proof` types.
//!
//! To verify a proof, the verifier runs the verification function on the `Proof` object. These
//! functions check the consistency of the components of the proof (including the commitment to
//! the underlying message, the commitment to commitment scalars, the response scalars, and the
//! challenge). A malicious prover cannot produce a consistent set of these components without
//! knowing the underlying message.
//!
//! In the following sections, we expand on additional details for each proof type.
//!
//! ## Commitment proofs
//!
//! This is a proof of knowledge of the opening of a Pedersen commitment --- that is, a [`Message`].
//! The structure described above is complete for a commitment proof. The commitment phase takes
//! the `Message` for which the prover is proving knowledge. The generated commitment and blinding
//! factor are stored in the [`CommitmentProofBuilder`] and can be retrieved for other uses.
//!
//! Verification checks that the proof is consistent as described in the overview.
//!
//! - [`CommitmentProofBuilder`]
//! - [`CommitmentProof`]
//!
//! ## Signature proofs
//!
//! This is a proof of knowledge of a Pointcheval_Sanders signature [\[2\]](#references). It is
//! used when the prover wants to demonstrate that they have a valid [`Signature`] on a [`Message`] with
//! respect to a specific public key, without revealing the underlying message.
//!
//! The protocol is based on Schnorr proofs of knowledge of the opening of a commitment
//! [\[1\]](#references), but adds an additional setup step to adapt it for signatures (this is
//! not revealed in the API; it is executed along with the commitment phase in
//! [`generate_proof_commitments()`](SignatureProofBuilder::generate_proof_commitments())).
//! The setup phase blinds and randomizes the signature. The commitment phase uses the same
//! blinding factor to form the commitment to the `Message`.
//!
//! The generated proof includes the blinded, randomized signature and the underlying commitment
//! proof. Verification checks the following:
//! 1. The underlying commitment proof is consistent;
//! 2. The blinded, randomized signature is valid;
//! 3. The signature is consistent with the commitment to the message.
//!
//! - [`SignatureProofBuilder`]
//! - [`SignatureProof`]
//!
//! ## Signature request proofs
//!
//! This is a proof of knowledge of the opening of a Pointcheval Sanders blinded message --- that is, a [`Message`].
//! It is used when the prover wants the verifier to blindly sign a [`BlindedMessage`]
//! of which the prover knows the opening.
//!
//! In general, a blind signature scheme _must not_ allow signatures on arbitrary messages.
//! Typically, a signature request proof should be paired with additional constraints that
//! demonstrate that the message satisfies some set of criteria agreed on by both parties.
//!
//! The structure is similar to that of a commitment proof, but with two important changes:
//! - The commitment phase generates a [`BlindedMessage`] instead of a [`Commitment`].
//! - Successful verification provides a blind-signable [`VerifiedBlindedMessage`].
//!   In fact, this is the _only way_ to obtain a [`VerifiedBlindedMessage`] for blind signing!
//!
//! **A note on verification:**
//! This library provides a [`VerifiedBlindedMessage`] for any [`SignatureRequestProof`] that
//! verifies successfully. However, any additional [constraints](#constraints)
//! require additional, manual verification.
//!
//! If such constraints are not checked correctly, it is possible to get a
//! [`VerifiedBlindedMessage`] on an invalid proof! Be sure to validate _all_ constraints before
//! blind signing.
//!
//! - [`SignatureRequestProofBuilder`]
//! - [`SignatureRequestProof`]
//!
//!
//! # Constraints
//! The library includes integrated support for range constraints and allows manual addition and
//! verification of other types of constraints.
//!
//! The library supports the combination of multiple proof objects and message constraints.
//! But this combination requires some expertise to do correctly!
//!
//! In general, constraints involve manipulation of the challenge scalars. Applying relationships
//! to the challenge scalars can enforce properties on the underlying messages, and will lead to
//! equivalent relationships in the response scalars. To validate the proof, check that these
//! relationships still hold with respect to the response scalars.
//!
//! The [`Message`] type has a length parameter; we refer to these objects as _message tuples_,
//! and to each element of the underlying tuple as a message. Constraints are applied to
//! messages, not to the entire message tuple.
//!
//! To apply a specific commitment scalar for a message, pass it to the commitment phase in the
//! appropriate index of the
//! [`conjunction_commitment_scalars`](CommitmentProofBuilder::generate_proof_commitments())
//! parameter.
//!
//! To access commitment scalars from a `ProofBuilder`, use the `conjunction_commitment_scalars()`
//! function.
//! To access response scalars from a `Proof`, use the `conjunction_response_scalars()` function.
//! Each of these functions return a list; the `j`th element corresponds to the `j`th message in
//! the message tuple.
//!
//! Some general guidelines follow:
//!
//! 1. All components of the proof must be generated in parallel. That is, you must run the
//!    commitment phase for all proof objects and constraints before generating a challenge.
//!    You must use the same challenge to execute each response phase.
//!
//! 2. The challenge phase must generate a single challenge that incorporates _all_ proof
//!    components.
//!
//! 3. All constraints that are manually added must also be manually verified. Calling the
//!    built-in verification functions on `Proof`s is _not sufficient_.
//!
//! The following sections will give details on how to enforce specific types of constraints.
//! For complete code, see the examples in this crate.
//!
//!
//!
//! ## Partial openings
//! A partial opening proves that one message in the message tuple matches a known, public
//! value.
//!
//! Modifications to standard flow:
//! 1. **Challenge phase**. Include the proof and the commitment scalar corresponding to the public
//!   value in the challenge.
//! 2. **Final proof**. Include the public value and its commitment scalar along with the proof.
//! 3. **Verification**. Check the following equality for each opened value:
//!    ```ignore
//!    challenge * public_value + public_value_commitment_scalar == public_value_response_scalar
//!    ```
//!    Also check that the public value in the proof statement matches the expected value.
//!
//!
//! ## Equality checks
//! An equality check can enforce that two messages have the same value.
//!
//! To enforce an equality constraint, make these additions:
//! 1. **Commitment phase**. The two messages must have the same commitment scalar. If they are in
//!    the same proof, generate a new commitment scalar (uniformly at random) and pass it to the
//!    commitment phase.
//!
//!    If they are in different proofs, generate the first proof normally, then retrieve
//!    the commitment scalar corresponding to the message and pass it to the second proof.
//!
//! 2. **Verification**. Check that the response scalars for each matching value are equal.
//!
//!
//! ## Linear combinations
//! A linear combination enforces modular relations modulo the group order.
//! These small examples can be composed to describe more complex relations.
//!
//! To enforce the relationship `m1 + m2 = m3`, make these additions:
//! 1. **Commitment phase**. The commitment scalar for `m3` must equal the sum of the commitment
//!    scalars for `m1` and `m2`.
//!
//! 2. **Verification**. The response scalar for `m3` must equal the sum of the response scalars
//!    for `m1` and `m2`.
//!
//! To enforce the relationship `m1 + public = m2`, where `public` is some value known to both
//! parties (and is not part of a message tuple), make these additions:
//! 1. **Commitment phase**. The commitment scalar for `m2` must equal that of `m1`.
//!
//! 2. **Challenge phase**. Include the public value in the challenge.
//!
//! 2. **Final proof**. Include the public value along with the proof.
//!
//! 3. **Verification**. Let `r1` and `r2` be the response scalars corresponding to `m1` and `m2`:
//!    ```ignore
//!    r2 == r1 + challenge * public
//!    ```
//!    Also check that the public value in the proof statement matches the expected value.
//!
//! To enforce the relationship `m1 * public = m2`, where `public` is as above, make these
//! additions:
//! 1. **Commitment phase**. The commitment scalar for `m2` must equal that of `m1` multiplied by
//!    `public`.
//!
//! 2. **Challenge phase**. Include the public value in the challenge.
//!
//! 2. **Final proof**. Include the public value along with the proof.
//!
//! 3. **Verification**. Let `r1` and `r2` be the response scalars corresponding to `m1` and `m2`:
//!    ```ignore
//!    r2 == r1 * public
//!    ```
//!    Also check that the public value in the proof statement matches the expected value.
//!
//! ## Range constraints
//! A range constraint enforces that a value lies within the range `[0, 2^63)`.
//! Unlike the other constraints, they require the verifier to supply a set of public
//! [`RangeConstraintParameters`].
//!
//! As with other constraints, this requires that the relevant message `m` contained in another
//! `Proof`. To add the range constraint, make these additions:
//! 1. **Commitment phase**. Create a [`RangeConstraintBuilder`] on `m`. In the main `Proof`, the
//!    commitment scalar for `m` must equal the
//!    [`commitment_scalar`](RangeConstraintBuilder::commitment_scalar()) from the range
//!    constraint.
//!
//! 2. **Challenge phase**. Incorporate the range constraint and parameters into the challenge.
//!
//! 3. **Response phase**. Execute the response phase for both the main `Proof` and the
//!    [`RangeConstraintBuilder`](RangeConstraintBuilder::generate_constraint_response()).
//!
//! 4. **Final proof**. Include the [`RangeConstraint`] along with the proof.
//!
//! 5. **Verification**. Verify the [`RangeConstraint`] by passing the response scalar for `m`
//!    from the `Proof` to the
//!    [range constraint verification function](RangeConstraint::verify_range_constraint()).
//!
//! For more details on the range constraint algorithm and implementation, see:
//! - [`RangeConstraint`]
//! - [`RangeConstraintBuilder`]
//! - [`RangeConstraintParameters`]
//!
//! ## References
//! 1. C. P. Schnorr. Efficient signature generation by smart cards. Journal of Cryptology,
//!     4(3):161–174, Jan 1991.
//!
//! 2. David Pointcheval and Olivier Sanders. Short Randomizable Signatures. In Kazue Sako, editor,
//!    Topics in Cryptology - CT-RSA 2016, volume 9610, pages 111–126. Springer International
//!    Publishing, Cham, 2016.
//!
//! 3. Jan Camenisch, Rafik Chaabouni, and abhi shelat. Efficient protocols for set membership and
//!    range proofs. In Josef Pieprzyk, editor, Advances in Cryptology - ASIACRYPT 2008, pages
//!    234–252, Berlin, Heidelberg, 2008. Springer Berlin Heidelberg.
//!
//! 4. Dan Boneh, Sergey Gorbunov, Riad S. Wahby, Hoeteck Wee, and Zhenfei Zhang. BLS Signatures,
//!    revision 4. Internet draft, Internet Engineering Task Force, 2020.
//!    <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04>
//!
//! [`Message`]:crate::Message
//! [`Commitment`]:crate::pedersen::Commitment
//! [`Signature`]:crate::pointcheval_sanders::Signature
//! [`BlindedMessage`]:crate::pointcheval_sanders::BlindedMessage
//! [`VerifiedBlindedMessage`]:crate::pointcheval_sanders::VerifiedBlindedMessage

mod challenge;
mod commitment;
mod range;
mod range2;
mod signature;
mod signaturerequest;

pub use self::{challenge::*, commitment::*, range2::*, signature::*, signaturerequest::*};
