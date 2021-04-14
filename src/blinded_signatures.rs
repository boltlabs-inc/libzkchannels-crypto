// Implementation of Pointcheval-Sanders blind signatures with efficient protocols over BLS12-381
use crate::signatures::*;

pub(crate) struct BlindSecretKey {}

pub struct BlindPublicKey {}

pub struct BlindKeyPair {
    sk: BlindSecretKey,
    pub pk: BlindPublicKey,
}

pub struct BlindedMessage {}

pub struct BlindedSignature {}

impl BlindSecretKey {
    pub fn new(_length: u64) -> Self {
        unimplemented!();
    }

    pub fn from_secret_key(_sk: &SecretKey) -> Self {
        unimplemented!();
    }

    pub fn blind_sign(&self, _msg: BlindedMessage) -> BlindedSignature {
        unimplemented!();
    }
}

impl BlindPublicKey {
    fn from_secret_key(_sk: &BlindSecretKey) -> Self {
        unimplemented!();
    }
}

impl BlindKeyPair {
    pub fn new(length: u64) -> Self {
        let sk = BlindSecretKey::new(length);
        let pk = BlindPublicKey::from_secret_key(&sk);
        BlindKeyPair { sk, pk }
    }

    pub(crate) fn from_secret_key(sk: &SecretKey) -> Self {
        let bsk = BlindSecretKey::from_secret_key(sk);
        let pk = BlindPublicKey::from_secret_key(&bsk);
        BlindKeyPair { sk: bsk, pk }
    }

    pub fn blind_sign(&self, msg: BlindedMessage) -> BlindedSignature {
        self.sk.blind_sign(msg)
    }
}
