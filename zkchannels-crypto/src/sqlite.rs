#[macro_export]
/// This derives `sqlx::Encode`, `sqlx::Decode`, and `sqlx::Type` into a [u8] using bincode for
/// types that already implement `serde::Deserialize` and `serde::Serialize`.
macro_rules! impl_sqlx_for_bincode_ty {
    ($type:ty) => {
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
                let bytes = ::bincode::serialize(self).expect(::std::concat!(
                    "could not serialize {}",
                    ::std::stringify!($type)
                ));

                <::std::vec::Vec<::std::primitive::u8>
                            as ::sqlx::Encode<'_, ::sqlx::Sqlite>>::encode_by_ref(&bytes, buf)
            }

            fn size_hint(&self) -> ::std::primitive::usize {
                let size = ::bincode::serialized_size(&self).expect(::std::concat!(
                    "could not serialize {}", ::std::stringify!($type)
                ));

                ::std::convert::TryInto::try_into(size).expect(
                    "could not convert u64 size hint to usize"
                )
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

                let blob = ::std::convert::TryInto::try_into(
                    <&[::std::primitive::u8] as ::sqlx::Decode<::sqlx::Sqlite>>::decode(value)?,
                )?;

                let maybe_decoded = ::bincode::deserialize(blob);

                let res = maybe_decoded.map_err(|_err| {
                    ::sqlx::Error::Decode(
                        String::from("tried to decode from incorrect byte input").into(),
                    )
                })?;

                Ok(res)
            }
        }
    };
}
