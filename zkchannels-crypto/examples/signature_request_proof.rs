use {
    bls12_381::Scalar,
    chrono::{Datelike, Utc},
    std::convert::TryInto,
};

use rand::thread_rng;
use zkchannels_crypto::{
    pointcheval_sanders::{BlindedSignature, KeyPair, PublicKey, Signature},
    proofs::{ChallengeBuilder, SignatureRequestProof, SignatureRequestProofBuilder},
    BlindingFactor, Message, Rng,
};

fn main() {
    // Time to bid!
    //
    // An organization is holding a sealed-bid auction to offload some items.
    // Parties can bid over a bidding period, but shouldn't reveal their bids until the
    // auction concludes. Sealed bids must be registered with the organization to count.
    //
    // A bid is a signature over the amount and the date that the bid was placed.
    // To receive a valid bid, parties must submit a `SignatureRequestProof` with the correct date
    // and their (secret) amount.
    // On auction day, each party will unseal their bids and the results will be tallied.

    let mut rng = thread_rng();
    let key_pair = KeyPair::new(&mut rng);

    // Describes the period over which parties are allowed to bid. For this example, it's just
    // the current date.
    let voting_period = [date()];

    // 0. Party selects their bid amount in whole-dollar increments
    let bid_amount = 150;

    // 1. Party generates a bid request
    let (blinding_factor, bid_request) =
        BidRequest::new(&mut rng, key_pair.public_key(), bid_amount);

    // 2. Party sends the `bid_request` to the organization, who verifies it and returns an
    // official `SealedBid` if the request was valid
    let sealed_bid = match bid_request.verify_bid(&key_pair, &mut rng) {
        Some(sealed_bid) => sealed_bid,
        None => {
            eprintln!("Invalid bid request! Rejected");
            return;
        }
    };

    // 3. Organization sends the sealed bid, which is a blind signature over the date and amount,
    // back to the party. At no point during (2) or (3) can the organization determine the
    // bid amount in the request!
    //
    // On auction day, the party unseals their bid (by unblinding the signature) and can provide
    // that bid to claim their item.
    let bid = sealed_bid.unseal(blinding_factor);

    if bid.verify_bid_amount(key_pair.public_key(), bid_amount, &voting_period) {
        println!("One bid for {}!", bid_amount);
    } else {
        unreachable!("You tried to fake your bid :(");
    }

    // An party cannot retroactively change their bid amount
    if !bid.verify_bid_amount(key_pair.public_key(), 125, &voting_period) {
        println!("That's not the amount you agreed to pay!");
    }
}

/// Zero-knowledge proof of knowledge of a bid amount made on a specific date.
/// The date is publicly verifiable, and a successfully verified `BidRequest` generates a valid
/// `SealedBid`.
pub struct BidRequest {
    date: Scalar,
    date_commitment_scalar: Scalar,
    proof: SignatureRequestProof<2>,
}

pub struct SealedBid(BlindedSignature);

pub struct Bid(Signature);

impl BidRequest {
    pub fn new(
        rng: &mut impl Rng,
        public_key: &PublicKey<2>,
        bid_amount: u64,
    ) -> (BlindingFactor, Self) {
        // Encode date and bid amount in the message
        // Note on encoding: for this example, we assume that the bid amount is smaller than the
        // Scalar modulus. A real application should clearly document such an assumption.
        // See Message docs for more details
        let message = Message::new([Scalar::from(bid_amount), date()]);

        // Create the proof builder with no constraints on the message
        let proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
            rng,
            message,
            &[None, None],
            public_key,
        );

        // Save the commitment scalar for the date so it can be revealed with the proof
        let date_commitment_scalar = proof_builder.conjunction_commitment_scalars()[1];

        // Generate challenge with all public components of the proof
        // - signature request proof statement & underlying commitment (via `proof_builder`)
        // - expected value for the revealed date
        // - commitment scalar for the revealed date
        // - public key corresponding to the requested signature
        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&date())
            .with(&date_commitment_scalar)
            .with(public_key)
            .finish();

        (
            // Save the blinding factor so the party can unseal the sealed bid they will receive
            proof_builder.message_blinding_factor(),
            // Generate the proof
            Self {
                date: date(),
                date_commitment_scalar,
                proof: proof_builder.generate_proof_response(challenge),
            },
        )
    }

    pub fn verify_bid(&self, key_pair: &KeyPair<2>, rng: &mut impl Rng) -> Option<SealedBid> {
        // Make sure date is correct
        let date_is_correct = self.date == date();

        // Reconstruct challenge with all public components of the proof
        // - signature request proof statement & underlying commitment (via `self.proof`)
        // - expected value for the revealed date
        // - stated commitment scalar for the revealed date
        // - public key corresponding to the requested signature
        let challenge = ChallengeBuilder::new()
            .with(&self.proof)
            .with(&self.date)
            .with(&self.date_commitment_scalar)
            .with(key_pair.public_key())
            .finish();

        // Make sure proof contains date
        let date_opens_correctly = challenge * self.date + self.date_commitment_scalar
            == self.proof.conjunction_response_scalars()[1];

        // Make sure proof verifies
        let maybe_bid = self
            .proof
            .verify_knowledge_of_opening(key_pair.public_key(), challenge);

        match (maybe_bid, date_is_correct, date_opens_correctly) {
            (Some(blinded_bid_request), true, true) => {
                Some(SealedBid(blinded_bid_request.blind_sign(key_pair, rng)))
            }
            _ => None,
        }
    }
}

impl SealedBid {
    fn unseal(self, blinding_factor: BlindingFactor) -> Bid {
        Bid(self.0.unblind(blinding_factor))
    }
}

impl Bid {
    /// Verify that the sealed bid is correctly formed (a valid signature) and was made in the
    /// correct time period.
    fn verify_bid_amount(
        &self,
        public_key: &PublicKey<2>,
        bid_amount: u64,
        voting_period: &[Scalar],
    ) -> bool {
        for date in voting_period {
            if self
                .0
                .verify(public_key, &Message::new([Scalar::from(bid_amount), *date]))
            {
                return true;
            }
        }
        false
    }
}

/// Encode the current date as a `Scalar`.
fn date() -> Scalar {
    let date = Utc::now();
    let date_bytes = [date.month().to_le_bytes(), date.day().to_le_bytes()].concat();
    Scalar::from(u64::from_le_bytes(date_bytes.try_into().unwrap()))
}
