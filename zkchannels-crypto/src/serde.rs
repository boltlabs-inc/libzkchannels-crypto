//! Utilities for serializing and deserializing `libzkchannels_crypto` types using Serde.
//!
//! There are three public items in this module; `SerializeElement`, `SerializeG1`, and
//! `SerializeG2`. To Serde, these look like "modules" which can be used with the `#[serde(with =
//! "SerializeElement")]` syntax in order to add serialization/deserialization functionality to
//! bls12-381 types which otherwise do not provide `Serialize` and `Deserialize` implementations.
//! [`SerializeElement`] is the trait which should be used for this; [`SerializeG1`] and
//! [`SerializeG2`] exist for when we need to bound on a type which is generic over the group
//! element used, want to use the `Serialize` and `Deserialize` derive macros, but only want to
//! allow serialize/deserialization when the group element is specifically G1 or specifically G2.

use crate::common::*;
use arrayvec::ArrayVec;
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::marker::PhantomData;

#[derive(Serialize)]
#[serde(transparent)]
struct SerWrapper<'a, G: SerializeElement>(
    #[serde(serialize_with = "<G as SerializeElement>::serialize")] &'a G,
);

#[derive(Deserialize)]
#[serde(transparent)]
struct DeWrapper<G: SerializeElement>(#[serde(with = "SerializeElement")] G);

/// A trait synonym for [`SerializeElement`] which only accepts elements of G1 and will not compile
/// if used to serialize elements from G2.
pub trait SerializeG1: SerializeElement + sealed::SerializeG1 {}
impl<G: SerializeElement + sealed::SerializeG1> SerializeG1 for G {}

/// A trait synonym for [`SerializeElement`] which only accepts elements of G2 and will not compile
/// if used to serialize elements from G1.
pub trait SerializeG2: SerializeElement + sealed::SerializeG2 {}
impl<G: SerializeElement + sealed::SerializeG2> SerializeG2 for G {}

/// Serialization/deserialization functionality for external `bls12_381` types.
///
/// Currently, serialization/deserialization for BLS12 `G1` and `G2` elements rely on the
/// `bls12_381` crate's compressed encoding scheme.
pub trait SerializeElement: Sized {
    /// Proxy serialization function telling serde how to serialize the implementing type.
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;

    /// Proxy deserialization function telling serde how to deserialize the implementing type.
    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

impl SerializeElement for G1Affine {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_big_array::BigArray::serialize(&this.to_compressed(), serializer)
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let maybe_g1: Option<G1Affine> =
            G1Affine::from_compressed(&serde_big_array::BigArray::deserialize(deserializer)?)
                .into();
        maybe_g1.ok_or_else(|| de::Error::custom("invalid element encoding"))
    }
}

impl SerializeElement for G1Projective {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        G1Affine::serialize(&this.into(), serializer)
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        G1Affine::deserialize(deserializer).map(Into::into)
    }
}

impl SerializeElement for G2Affine {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_big_array::BigArray::serialize(&this.to_compressed(), serializer)
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let maybe_g1: Option<G2Affine> =
            G2Affine::from_compressed(&serde_big_array::BigArray::deserialize(deserializer)?)
                .into();
        maybe_g1.ok_or_else(|| de::Error::custom("invalid element encoding"))
    }
}

impl SerializeElement for G2Projective {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        G2Affine::serialize(&this.into(), serializer)
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        G2Affine::deserialize(deserializer).map(Into::into)
    }
}

impl SerializeElement for Scalar {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        this.to_bytes().serialize(serializer)
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        let maybe_scalar: Option<Scalar> = Scalar::from_bytes(&bytes).into();
        maybe_scalar.ok_or_else(|| de::Error::custom("invalid scalar encoding"))
    }
}

impl<G: SerializeElement> SerializeElement for Vec<G> {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(this.len()))?;
        for g in this {
            seq.serialize_element(&SerWrapper(g))?;
        }
        seq.end()
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ElementVisitor<G> {
            _phantom: PhantomData<G>,
        }

        impl<'de, G> Visitor<'de> for ElementVisitor<G>
        where
            G: SerializeElement,
        {
            type Value = Vec<G>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut elems = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(elem) = seq.next_element::<DeWrapper<G>>()? {
                    elems.push(elem.0);
                }
                Ok(elems)
            }
        }

        let visitor = ElementVisitor {
            _phantom: PhantomData,
        };

        deserializer.deserialize_seq(visitor)
    }
}

impl<G: SerializeElement, const N: usize> SerializeElement for Box<[G; N]> {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let this: &[G; N] = &*this;
        SerializeElement::serialize(this, serializer)
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Box::new(SerializeElement::deserialize(deserializer)?))
    }
}

impl<G: SerializeElement, const N: usize> SerializeElement for [G; N] {
    fn serialize<S>(this: &Self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(this.len()))?;
        for g in this {
            seq.serialize_element(&SerWrapper(g))?;
        }
        seq.end()
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ElementVisitor<G, const N: usize> {
            _phantom: PhantomData<G>,
        }

        impl<'de, G, const N: usize> Visitor<'de> for ElementVisitor<G, N>
        where
            G: SerializeElement,
        {
            type Value = [G; N];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut elems = ArrayVec::new();
                while let Some(elem) = seq.next_element::<DeWrapper<G>>()? {
                    elems.push(elem.0);
                }
                elems
                    .into_inner()
                    .map_err(|_| de::Error::custom("wrong number of elements for array"))
            }
        }

        let visitor = ElementVisitor {
            _phantom: PhantomData,
        };

        deserializer.deserialize_seq(visitor)
    }
}

pub mod big_boxed_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S, const N: usize>(array: &[T; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize + for<'de> Deserialize<'de>,
        S: Serializer,
    {
        serde_big_array::BigArray::serialize(&*array, serializer)
    }

    pub fn deserialize<'de, T, D, const N: usize>(deserializer: D) -> Result<Box<[T; N]>, D::Error>
    where
        T: Serialize + Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Ok(Box::new(serde_big_array::BigArray::deserialize(
            deserializer,
        )?))
    }
}

mod sealed {
    use crate::common::*;

    pub trait SerializeG1 {}
    impl SerializeG1 for G1Projective {}
    impl SerializeG1 for G1Affine {}

    pub trait SerializeG2 {}
    impl SerializeG2 for G2Projective {}
    impl SerializeG2 for G2Affine {}
}
