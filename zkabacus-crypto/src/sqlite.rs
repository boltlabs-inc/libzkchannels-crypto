use crate::revlock::{RevocationLock, RevocationSecret};
use crate::Nonce;
use std::convert::TryInto;

macro_rules! impl_type_for_scalar_newtype {
    ($type:ty) => {
        impl sqlx::Type<::sqlx::Sqlite> for $type {
            fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
                <Vec<u8> as sqlx::Type<sqlx::Sqlite>>::type_info()
            }
        }
    };
}

macro_rules! impl_encode_for_scalar_newtype {
    ($type:ty) => {
        impl sqlx::Encode<'_, sqlx::Sqlite> for $type {
            fn encode_by_ref(
                &self,
                buf: &mut <sqlx::Sqlite as sqlx::database::HasArguments<'_>>::ArgumentBuffer,
            ) -> sqlx::encode::IsNull {
                let bytes = self.to_scalar().to_bytes().to_vec();
                <Vec<u8> as sqlx::Encode<'_, sqlx::Sqlite>>::encode_by_ref(&bytes, buf)
            }

            fn encode(
                self,
                buf: &mut <sqlx::Sqlite as sqlx::database::HasArguments<'_>>::ArgumentBuffer,
            ) -> ::sqlx::encode::IsNull {
                let bytes = self.to_scalar().to_bytes().to_vec();
                <Vec<u8> as sqlx::Encode<'_, sqlx::Sqlite>>::encode(bytes, buf)
            }
        }
    };
}

macro_rules! impl_decode_for_scalar_newtype {
    ($type:ty, $constructor:ident) => {
        impl sqlx::Decode<'_, sqlx::Sqlite> for $type {
            fn decode(
                value: sqlx::sqlite::SqliteValueRef<'_>,
            ) -> Result<Self, ::sqlx::error::BoxDynError> {
                if sqlx::ValueRef::is_null(&value) {
                    return Err(Box::new(sqlx::error::UnexpectedNullError));
                }

                let blob = <&[u8] as sqlx::Decode<sqlx::Sqlite>>::decode(value)?.try_into()?;
                let maybe_scalar: Option<$crate::types::Scalar> =
                    $crate::types::Scalar::from_bytes(blob).into();

                let res = maybe_scalar.map($constructor).ok_or_else(|| {
                    sqlx::Error::Decode(
                        String::from("tried to decode a nonce from non-canonical byte input")
                            .into(),
                    )
                })?;

                Ok(res)
            }
        }
    };
}

impl_encode_for_scalar_newtype!(Nonce);
impl_type_for_scalar_newtype!(Nonce);

impl_encode_for_scalar_newtype!(RevocationLock);
impl_decode_for_scalar_newtype!(RevocationLock, RevocationLock);
impl_type_for_scalar_newtype!(RevocationLock);

impl_encode_for_scalar_newtype!(RevocationSecret);
impl_decode_for_scalar_newtype!(RevocationSecret, RevocationSecret);
impl_type_for_scalar_newtype!(RevocationSecret);
