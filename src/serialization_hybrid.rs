
use hybrid_array::{
    typenum::{self, Prod, Sum, Unsigned, NonZero, U1, U2, U3, U4, U5, U8}, // Added U3, U5
    Array, ArraySize,
};


use core::ops::{Add as CoreAdd, Mul as CoreMul, Sub as CoreSub};
use core::fmt; // For Error Display

// Define a simple Error type for serialization/deserialization failures
#[derive(Debug, PartialEq, Eq)] // Added PartialEq, Eq for error comparison in tests if needed
pub enum Error {
    DeserializationError,
    SerializationError, // If needed later
    Custom(String),     // For more specific errors
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
    // Ensure SizeType itself must be NonZero for FSerializable's S parameter.
    type SizeType: ArraySize;
}

// New FSerializable trait definition
pub trait FSerializable<S: ArraySize>: Sized {
    fn serialize(&self) -> Array<u8, S>;
    fn deserialize(buffer: Array<u8, S>) -> Result<Self, Error>;
}

#[derive(Debug)]
pub struct Pair<A, B>(pub A, pub B);

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
        // A::deserialize and B::deserialize now return Result
        let val_a = A::deserialize(arr1)?;
        let val_b = B::deserialize(arr2)?;
        Ok(Pair(val_a, val_b))
    }
}

#[derive(Debug)]
pub struct Product<T, NLen: ArraySize>(pub Array<T, NLen>);

impl<T, NLen> FSerializable<Prod<T::SizeType, NLen>> for Product<T, NLen>
where
    T: FSerializable<T::SizeType> + Size,
    T::SizeType: CoreMul<NLen>,
    NLen: ArraySize,
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

            let item_array: Result<Array::<u8, T::SizeType>, _> = buffer[start..end].try_into();

            // This failure should not be possible, as the array size is known
            T::deserialize(item_array.map_err(|_| Error::DeserializationError)?)
        });
        
        Ok(Product(result?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::RistrettoElement;
    use hybrid_array::typenum::{U1, U2, U3, U4, U5, U8, U32, Sum, Prod, Unsigned};

    #[test]
    fn test_pair_element_serialization() {
        let p = Pair(RistrettoElement::default(), RistrettoElement::default());
        let serialized: Array<u8, Sum<U32, U32>> = p.serialize(); // U32 for RistrettoElement
        assert_eq!(serialized.as_slice().len(), <Sum<U32, U32> as Unsigned>::USIZE);
        let deserialized = Pair::<RistrettoElement, RistrettoElement>::deserialize(serialized).unwrap();
        assert_eq!(p.0, deserialized.0);
        assert_eq!(p.1, deserialized.1);
    }

    #[test]
    fn test_product_element_serialization() { // Renamed from test_product_mystruct_serialization
        // RistrettoElement implements Size (U32), FSerializable<U32>, Default, Clone, Eq, PartialEq
        let e1 = RistrettoElement::default();
        // To get a different element, one might use a specific operation if available,
        // or serialize known distinct byte patterns if from_bytes was more flexible.
        // For simplicity, we'll use default and one variant if easily constructible,
        // otherwise, multiple defaults are fine for testing serialization structure.
        // RistrettoElement::default() is identity. Let's assume we can make another one.
        // If RistrettoElement had an easy way to make a distinct one, e.g. RistrettoElement::new(some_point_not_identity)
        // For now, just using default elements.
        let e2 = RistrettoElement::default();
        let e3 = RistrettoElement::default();

        let r = Product(Array::<RistrettoElement, U3>::from([e1, e2, e3]));

        let serialized = r.serialize();
        assert_eq!(serialized.as_slice().len(), <Prod<U32, U3> as Unsigned>::USIZE); // U32 for RistrettoElement
        assert_eq!(<Prod<U32, U3> as Unsigned>::USIZE, 32 * 3);
        let deserialized = Product::<RistrettoElement, U3>::deserialize(serialized).unwrap();

        assert_eq!(r.0.as_slice()[0], deserialized.0.as_slice()[0]);
        assert_eq!(r.0.as_slice()[1], deserialized.0.as_slice()[1]);
        assert_eq!(r.0.as_slice()[2], deserialized.0.as_slice()[2]);
        assert_eq!(r.0, deserialized.0);
    }
}


/* 
// u8
impl Size for u8 { type SizeType = U1; }
impl FSerializable<U1> for u8 {
    fn serialize(&self) -> Array<u8, U1> {
        Array::from([*self])
    }

    fn deserialize(buffer: Array<u8, U1>) -> Result<Self, Error> {
        Ok(buffer.as_slice()[0])
    }
}

// u16
impl Size for u16 { type SizeType = U2; }
impl FSerializable<U2> for u16 {
    fn serialize(&self) -> Array<u8, U2> {
        Array::from(self.to_be_bytes())
    }

    fn deserialize(buffer: Array<u8, U2>) -> Result<Self, Error> {
        buffer.as_slice()
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| Error::DeserializationError)
    }
}

// u32
impl Size for u32 { type SizeType = U4; }
impl FSerializable<U4> for u32 {
    fn serialize(&self) -> Array<u8, U4> {
        Array::from(self.to_be_bytes())
    }

    fn deserialize(buffer: Array<u8, U4>) -> Result<Self, Error> {
        buffer.as_slice()
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| Error::DeserializationError)
    }
}

// u64
impl Size for u64 { type SizeType = U8; }
impl FSerializable<U8> for u64 {
    fn serialize(&self) -> Array<u8, U8> {
        Array::from(self.to_be_bytes())
    }

    fn deserialize(buffer: Array<u8, U8>) -> Result<Self, Error> {
        buffer.as_slice()
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| Error::DeserializationError)
    }
}
*/