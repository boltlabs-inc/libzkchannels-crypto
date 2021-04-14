// Implementation of randomizable multi-message Pointcheval-Sanders signatures
use crate::blinded_signatures::*;

pub(crate) struct SecretKey {}

pub struct PublicKey {}

pub struct KeyPair {
    sk: SecretKey,
    pub pk: PublicKey,
}

pub struct Message {}

pub struct Signature {}

impl SecretKey {
    pub fn new(_length: u64) -> Self {
        SecretKey {}
    }

    pub fn sign(&self, _msg: Message) -> Signature {
        unimplemented!()
    }
}

impl PublicKey {
    fn from_secret_key(_sk: &SecretKey) -> Self {
        unimplemented!();
    }

    pub fn verify(&self, _sig: Signature) -> bool {
        unimplemented!();
    }
}

impl KeyPair {
    pub fn new(length: u64) -> Self {
        let sk = SecretKey::new(length);
        let pk = PublicKey::from_secret_key(&sk);
        KeyPair { sk, pk }
    }

    pub fn get_blinded_keypair(&self) -> BlindKeyPair {
        BlindKeyPair::from_secret_key(&self.sk)
    }

    pub fn sign(&self, msg: Message) -> Signature {
        self.sk.sign(msg)
    }

    pub fn verify(&self, sig: Signature) -> bool {
        self.pk.verify(sig)
    }
}
