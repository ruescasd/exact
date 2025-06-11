use hybrid_array::{
    typenum::{Prod, Sum, Unsigned},
    Array, ArraySize,
};

use core::fmt;
use core::ops::{Add as CoreAdd, Mul as CoreMul, Sub as CoreSub}; // For Error Display

// Define a simple Error type for serialization/deserialization failures
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    DeserializationError,
    SerializationError,
    Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DeserializationError => write!(f, "Deserialization failed"),
            Error::SerializationError => write!(f, "Serialization failed"),
            Error::Custom(s) => write!(f, "Serialization error: {}", s),
        }
    }
}

pub trait Size {
    type SizeType: ArraySize;
}

pub trait FSerializable<S: ArraySize>: Sized {
    fn serialize(&self) -> Array<u8, S>;
    fn deserialize(buffer: Array<u8, S>) -> Result<Self, Error>;
}

#[derive(Debug, Clone)]
pub struct Pair<A, B>(pub A, pub B);

impl<A, B> Size for Pair<A, B>
where
    A: Size,
    B: Size,
    A::SizeType: CoreAdd<B::SizeType>,
    Sum<A::SizeType, B::SizeType>: ArraySize,
{
    type SizeType = Sum<A::SizeType, B::SizeType>;
}

impl<A, B> FSerializable<Sum<A::SizeType, B::SizeType>> for Pair<A, B>
where
    A: FSerializable<A::SizeType> + Size,
    B: FSerializable<B::SizeType> + Size,
    A::SizeType: CoreAdd<B::SizeType>,
    Sum<A::SizeType, B::SizeType>: ArraySize
        // For split: (S1+S2) - S1 = S2
        + CoreSub<A::SizeType, Output = B::SizeType>,
{
    fn serialize(&self) -> Array<u8, Sum<A::SizeType, B::SizeType>> {
        let arr1 = self.0.serialize();
        let arr2 = self.1.serialize();
        arr1.concat(arr2)
    }

    fn deserialize(buffer: Array<u8, Sum<A::SizeType, B::SizeType>>) -> Result<Self, Error> {
        let (view1, view2) = buffer.split::<A::SizeType>();
        let arr1 = view1.to_owned();
        let arr2 = view2.to_owned();
        let val_a = A::deserialize(arr1)?;
        let val_b = B::deserialize(arr2)?;
        Ok(Pair(val_a, val_b))
    }
}

#[derive(Debug, Clone)]
pub struct Product<T, NLen: ArraySize>(pub Array<T, NLen>);

impl<T, NLen> Product<T, NLen>
where
    // T: Clone,
    NLen: ArraySize,
{
    pub fn new<const N: usize>(array: [T; N]) -> Self
    where
        NLen: ArraySize<ArrayType<T> = [T; N]>,
    {
        Self(Array::from(array))
    }

    pub fn uniform(value: &T) -> Self
    where
        T: Clone,
    {
        let ret: Array<T, NLen> = Array::from_fn(|_| (*value).clone());
        Self(ret)
    }

    pub fn map<F, O>(&self, f: F) -> Product<O, NLen>
    where
        F: Fn(&T) -> O,
    {
        let ret = self.0.iter().map(|e| f(e));
        Product(ret.collect())
    }
}

impl<T, NLen> Size for Product<T, NLen>
where
    T: Size,
    NLen: ArraySize,
    T::SizeType: CoreMul<NLen>,
    Prod<T::SizeType, NLen>: ArraySize,
{
    type SizeType = Prod<T::SizeType, NLen>;
}

impl<T, NLen> FSerializable<Prod<T::SizeType, NLen>> for Product<T, NLen>
where
    T: FSerializable<T::SizeType> + Size,
    NLen: ArraySize,
    T::SizeType: CoreMul<NLen>,
    Prod<T::SizeType, NLen>: ArraySize,
{
    fn serialize(&self) -> Array<u8, Prod<T::SizeType, NLen>> {
        let mut result = Array::<u8, Prod<T::SizeType, NLen>>::default();

        for i in 0..NLen::USIZE {
            let item_bytes = self.0.as_slice()[i].serialize();
            let start = i * T::SizeType::USIZE;
            let end = start + T::SizeType::USIZE;
            result.as_mut_slice()[start..end].copy_from_slice(item_bytes.as_slice());
        }
        result
    }

    fn deserialize(buffer: Array<u8, Prod<T::SizeType, NLen>>) -> Result<Self, Error> {
        let result = Array::<T, NLen>::try_from_fn(|i| {
            let start = i * T::SizeType::USIZE;
            let end = start + T::SizeType::USIZE;

            let item_array: Result<Array<u8, T::SizeType>, _> = buffer[start..end].try_into();
            // This failure should not be possible, as the array size is known
            let item_array = item_array.map_err(|_| Error::DeserializationError)?;

            T::deserialize(item_array)
        });

        Ok(Product(result?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::{ristretto255::RistrettoElement, Ristretto255Group};
    use crate::traits::CryptoGroup;
    use hybrid_array::typenum::{Prod, Sum, Unsigned, U3, U32};

    #[test]
    fn test_pair_element_serialization() {
        let e1 = Ristretto255Group::random_element();
        let e2 = Ristretto255Group::random_element();
        let p = Pair(e1, e2);
        let serialized: Array<u8, Sum<U32, U32>> = p.serialize();
        let _byte_form: [u8; 64] = serialized.into();
        assert_eq!(serialized.len(), <Sum<U32, U32> as Unsigned>::USIZE);
        let deserialized =
            Pair::<RistrettoElement, RistrettoElement>::deserialize(serialized).unwrap();
        assert_eq!(p.0, deserialized.0);
        assert_eq!(p.1, deserialized.1);
    }

    #[test]
    fn test_product_element_serialization() {
        let e1 = Ristretto255Group::random_element();
        let e2 = Ristretto255Group::random_element();
        let e3 = Ristretto255Group::random_element();

        let r = Product(Array::<RistrettoElement, U3>::from([e1, e2, e3]));

        let serialized = r.serialize();
        let _byte_form: [u8; 96] = serialized.into();
        assert_eq!(serialized.len(), <Prod<U32, U3> as Unsigned>::USIZE); // U32 for RistrettoElement
        assert_eq!(<Prod<U32, U3> as Unsigned>::USIZE, 32 * 3);
        let deserialized = Product::<RistrettoElement, U3>::deserialize(serialized).unwrap();

        assert_eq!(r.0.as_slice()[0], deserialized.0.as_slice()[0]);
        assert_eq!(r.0.as_slice()[1], deserialized.0.as_slice()[1]);
        assert_eq!(r.0.as_slice()[2], deserialized.0.as_slice()[2]);
        assert_eq!(r.0, deserialized.0);
    }
}
