use crate::revlock::{RevocationLock, RevocationSecret};
use crate::Nonce;
use std::convert::TryInto;

macro_rules! impl_sqlx_for_scalar_newtype {
    ($type:ty, $constructor:ident) => {
        impl ::sqlx::Type<::sqlx::Sqlite> for $type {
            fn type_info() -> ::sqlx::sqlite::SqliteTypeInfo {
                <::std::vec::Vec<::std::primitive::u8> as ::sqlx::Type<::sqlx::Sqlite>>::type_info()
            }
        }

        impl ::sqlx::Encode<'_, ::sqlx::Sqlite> for $type {
            fn encode_by_ref(
                &self,
                buf: &mut <::sqlx::Sqlite as ::sqlx::database::HasArguments<'_>>::ArgumentBuffer,
            ) -> ::sqlx::encode::IsNull {
                let bytes = self.to_scalar().to_bytes().to_vec();
                <::std::vec::Vec<::std::primitive::u8> as ::sqlx::Encode<'_, ::sqlx::Sqlite>>::encode_by_ref(&bytes, buf)
            }

            fn encode(
                self,
                buf: &mut <::sqlx::Sqlite as ::sqlx::database::HasArguments<'_>>::ArgumentBuffer,
            ) -> ::sqlx::encode::IsNull {
                let bytes = self.to_scalar().to_bytes().to_vec();
                <::std::vec::Vec<::std::primitive::u8> as ::sqlx::Encode<'_, ::sqlx::Sqlite>>::encode(bytes, buf)
            }
        }

        impl ::sqlx::Decode<'_, ::sqlx::Sqlite> for $type {
            fn decode(
                value: ::sqlx::sqlite::SqliteValueRef<'_>,
            ) -> ::std::result::Result<Self, ::sqlx::error::BoxDynError> {
                if ::sqlx::ValueRef::is_null(&value) {
                    return ::std::result::Result::Err(Box::new(
                        ::sqlx::error::UnexpectedNullError,
                    ));
                }

                let blob =
                    <&[::std::primitive::u8] as ::sqlx::Decode<::sqlx::Sqlite>>::decode(value)?
                        .try_into()?;
                let maybe_scalar: ::std::option::Option<$crate::types::Scalar> =
                    $crate::types::Scalar::from_bytes(blob).into();

                let res = maybe_scalar.map($constructor).ok_or_else(|| {
                    ::sqlx::Error::Decode(
                        String::from("tried to decode a nonce from non-canonical byte input")
                            .into(),
                    )
                })?;

                Ok(res)
            }
        }
    };
}

impl_sqlx_for_scalar_newtype!(Nonce, Nonce);
impl_sqlx_for_scalar_newtype!(RevocationLock, RevocationLock);
impl_sqlx_for_scalar_newtype!(RevocationSecret, RevocationSecret);
