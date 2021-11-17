use {
    bls12_381::Scalar,
    chrono::{Datelike, Utc},
    std::convert::TryInto,
};

use rand::thread_rng;
use zkchannels_crypto::{
    pointcheval_sanders::{BlindedSignature, KeyPair, PublicKey},
    proofs::{ChallengeBuilder, SignatureRequestProof, SignatureRequestProofBuilder},
    BlindingFactor, Message, Rng,
};

fn main() {
    // Time to vote!
    //
    // A certain cryptography-minded organization is holding a vote to determine their employees'
    // collectively favorite color.
    // Each employee must vote before the final official voting day, but shouldn't
    // reveal what they voted for until then.

    // A ballot is a signature over their favorite color and the date that they voted.
    // To receive a valid ballot, they must submit a `SignatureRequestProof` with the correct date
    // and their (secret) candidate. On election day, each employee will provide their
    // ballot and the results will be tallied.

    let mut rng = thread_rng();
    let key_pair = KeyPair::new(&mut rng);

    // Describes the period over which employees are allowed to vote. For this example, it's just
    // the current date.
    let voting_period = [date()];

    // 0. Employee selects their favorite color
    let favorite_color = "olive green";

    // 1. Employee generates a ballot request with their favorite color
    let (blinding_factor, ballot_request) =
        ColorBallotRequest::new(&mut rng, key_pair.public_key(), favorite_color);

    // 2. Employee sends the `ballot_request` to the company, who verifies it and returns an
    // official `ColorVote` if the ballot was valid
    let color_vote = match ballot_request.verify_ballot(&key_pair, &mut rng) {
        Some(color_vote) => color_vote,
        None => {
            eprintln!("Invalid ballot! Rejected");
            return;
        }
    };

    // 3. Company sends the `color_vote`, which is a blinded signature over the date and color,
    // back to the employee. At no point during (2) or (3) can the company determine the
    // candidate color in the ballot!
    //
    // On election day, the employee unblinds and reveals their vote:
    if color_vote.verify_candidate(
        key_pair.public_key(),
        blinding_factor,
        favorite_color,
        &voting_period,
    ) {
        println!("One vote for {}!", favorite_color);
    } else {
        println!("Somebody tried voter fraud :(");
    }

    // An employee cannot retroactively change their ballot
    if !color_vote.verify_candidate(
        key_pair.public_key(),
        blinding_factor,
        "purple",
        &voting_period,
    ) {
        println!("It wasn't a vote for purple...");
    }
}

pub struct ColorBallotRequest {
    date: Scalar,
    date_commitment_scalar: Scalar,
    proof: SignatureRequestProof<2>,
}

pub struct ColorVote(BlindedSignature);

impl ColorBallotRequest {
    pub fn new(
        rng: &mut impl Rng,
        public_key: &PublicKey<2>,
        favorite_color: &str,
    ) -> (BlindingFactor, Self) {
        // Encode date and color in the message
        let message = Message::new([to_scalar(favorite_color), date()]);

        // Create the proof builder with no constraints on the message
        let proof_builder = SignatureRequestProofBuilder::generate_proof_commitments(
            rng,
            message,
            &[None, None],
            public_key,
        );

        // Save the commitment scalar for the date so it can be revealed with the proof
        let date_commitment_scalar = proof_builder.conjunction_commitment_scalars()[1];

        let challenge = ChallengeBuilder::new()
            .with(&proof_builder)
            .with(&date())
            .with(&date_commitment_scalar)
            .with(public_key)
            .finish();

        (
            // Save the blinding factor so the employee can unblind the signature they eventually get
            proof_builder.message_blinding_factor(),
            // Generate the proof
            Self {
                date: date(),
                date_commitment_scalar,
                proof: proof_builder.generate_proof_response(challenge),
            },
        )
    }

    pub fn verify_ballot(&self, key_pair: &KeyPair<2>, rng: &mut impl Rng) -> Option<ColorVote> {
        // Make sure date is correct
        let date_is_correct = self.date == date();

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
        let maybe_ballot = self
            .proof
            .verify_knowledge_of_opening(key_pair.public_key(), challenge);

        match (maybe_ballot, date_is_correct, date_opens_correctly) {
            (Some(blinded_ballot), true, true) => {
                Some(ColorVote(blinded_ballot.blind_sign(key_pair, rng)))
            }
            _ => None,
        }
    }
}

impl ColorVote {
    // Verify vote against the given candidate
    fn verify_candidate(
        &self,
        public_key: &PublicKey<2>,
        blinding_factor: BlindingFactor,
        favorite_color: &str,
        voting_period: &[Scalar],
    ) -> bool {
        for date in voting_period {
            if self.0.unblind(blinding_factor).verify(
                public_key,
                &Message::new([to_scalar(favorite_color), *date]),
            ) {
                return true;
            }
        }
        false
    }
}

fn to_scalar(string: &str) -> Scalar {
    let mut bytes: Vec<u8> = string.as_bytes().into();
    while bytes.len() < 8 {
        bytes.push(0);
    }
    if bytes.len() > 8 {
        bytes.truncate(8);
    }
    let mut raw_bytes: [u8; 8] = [0; 8];
    raw_bytes.clone_from_slice(&bytes);

    Scalar::from(u64::from_le_bytes(raw_bytes))
}

fn date() -> Scalar {
    let date = Utc::now();
    let date_bytes = [date.month().to_le_bytes(), date.day().to_le_bytes()].concat();
    Scalar::from(u64::from_le_bytes(date_bytes.try_into().unwrap()))
}
