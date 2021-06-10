//! Cryptographically random nonces.
use crate::{types::*, Rng};
use ff::Field;
use serde::*;
use zkchannels_crypto::SerializeElement;

#[allow(unused)]
/// A random nonce.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Nonce(#[serde(with = "SerializeElement")] Scalar);

#[allow(unused)]
impl Nonce {
    /// Generate a new cryptographically random nonce with the given random number generator. This
    /// is not part of the public API and may change between major releases.
    #[doc(hidden)]
    pub fn new(rng: &mut impl Rng) -> Self {
        Self(Scalar::random(rng))
    }

    /// Convert a nonce to its canonical `Scalar` representation.
    pub(crate) fn to_scalar(&self) -> Scalar {
        self.0
    }
}

#[cfg(feature = "sqlx")]
use sqlx::{
    database::HasArguments,
    encode::{Encode, IsNull},
    sqlite::{Sqlite, SqliteTypeInfo},
    Type,
};

#[cfg(feature = "sqlx")]
impl Encode<'_, Sqlite> for Nonce {
    fn encode_by_ref(&self, buf: &mut <Sqlite as HasArguments<'_>>::ArgumentBuffer) -> IsNull {
        let bytes = self.0.to_bytes().to_vec();
        <Vec<u8> as sqlx::Encode<'_, Sqlite>>::encode_by_ref(&bytes, buf)
    }

    fn encode(self, buf: &mut <Sqlite as HasArguments<'_>>::ArgumentBuffer) -> IsNull {
        let bytes = self.0.to_bytes().to_vec();
        <Vec<u8> as sqlx::Encode<'_, Sqlite>>::encode(bytes, buf)
    }
}

#[cfg(feature = "sqlx")]
impl Type<Sqlite> for Nonce {
    fn type_info() -> SqliteTypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <Vec<u8> as Type<Sqlite>>::compatible(ty)
    }
}
