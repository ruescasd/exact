
// Updated import to include Prod, Sum, Unsigned, NonZero, U1, U2, U3, U4, U5, U8 directly for clarity
// Ensure NonZero is available from typenum
use hybrid_array::{
    typenum::{self, Prod, Sum, Unsigned, NonZero, U1, U2, U3, U4, U5, U8}, // Added U3, U5
    Array, ArraySize,
};

// Use the specific imports needed
use core::ops::{Add as CoreAdd, Mul as CoreMul, Sub as CoreSub}; // Alias for core::ops operators
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

// Required for std::error::Error (optional, but good practice)
// impl std::error::Error for Error {}
// ^ This requires std, but the crate might be no_std. Let's skip this for now.

pub trait Size {
    // Ensure SizeType itself must be NonZero for FSerializable's S parameter.
    type SizeType: typenum::Unsigned + typenum::NonZero + ArraySize;
}

// New FSerializable trait definition
pub trait FSerializable<S: typenum::Unsigned + typenum::NonZero + ArraySize>: Sized {
    fn serialize(&self) -> Array<u8, S>;
    // Changed deserialize to return Result<Self, Error>
    fn deserialize(buffer: Array<u8, S>) -> Result<Self, Error>;
}


// Removing old Product<L,T> struct and its impls
/*
#[derive(Debug)]
pub struct Product<L, T>
where
    L: Unsigned + ArraySize,
    T: Size,
    T::SizeType: core::ops::Mul<L>, // Required for Prod
    Prod<T::SizeType, L>: Unsigned + ArraySize, // The result of multiplication must be a valid size
{
    elements: Array<T, L>,
    // PhantomData is not strictly needed here based on original Product,
    // but if T or L were not used in a field, it might be.
    // For now, 'elements' uses both T and L.
}

impl<L, T> Size for Product<L, T>
where
    L: Unsigned + ArraySize,
    T: Size,
    T::SizeType: core::ops::Mul<L>, // Trait bound for typenum::Prod
    Prod<T::SizeType, L>: Unsigned + ArraySize, // Result of Prod must be a valid size
{
    type SizeType = Prod<T::SizeType, L>;
}

impl<L, T> Product<L, T>
where
    L: Unsigned + ArraySize,
    T: Size, // T only needs to be Size for the constructor, not FSerializable
    T::SizeType: core::ops::Mul<L>,
    Prod<T::SizeType, L>: Unsigned + ArraySize,
{
    pub fn new(elements: Array<T, L>) -> Self {
        Product { elements }
    }
}
*/

// Define the new Product<A, B> struct (tuple struct)
#[derive(Debug, PartialEq, Eq, Clone, Copy)] // Added common derives
pub struct Product<A, B>(pub A, pub B);

// Implement FSerializable for the new Product<A, B>
impl<A, B> FSerializable<Sum<A::SizeType, B::SizeType>> for Product<A, B>
where
    A: FSerializable<A::SizeType> + Size,
    B: FSerializable<B::SizeType> + Size,
    A::SizeType: typenum::Unsigned + typenum::NonZero + ArraySize + CoreAdd<B::SizeType>, // For Sum
    B::SizeType: typenum::Unsigned + typenum::NonZero + ArraySize, // For Sum and as result of subtraction
    Sum<A::SizeType, B::SizeType>: typenum::Unsigned + typenum::NonZero + ArraySize
                                 + CoreSub<A::SizeType, Output = B::SizeType>, // For split: (S1+S2) - S1 = S2
    // Required for Array::split and Array::concat.
    // concat requires S1: Add<S2>.
    // split<S1> on Sum<S1,S2> requires Sum<S1,S2>: Sub<S1, Output=S2>.
    // All ArraySize bounds are also necessary.
    // These are covered by the bounds on A::SizeType, B::SizeType and Sum<A::SizeType,B::SizeType> along with typenum's provided Sub impls.
    // Add1/Sub1/NonZero bounds on A::SizeType/B::SizeType might be needed by some Array operations if not implied by ArraySize.
    // For now, let's rely on ArraySize and the direct arithmetic trait bounds.
    // The `hybrid_array` docs for `split` mention `N: Sub<M, Output = O>, M: ArraySize, O: ArraySize`.
    // So `Sum<A::SizeType, B::SizeType>: Sub<A::SizeType, Output = B::SizeType>` is needed. This is typically provided by typenum.
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
        Ok(Product(val_a, val_b))
    }
}

// Define the Repeated<T, NLen> struct (N_LEN -> NLen)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repeated<T, NLen: ArraySize>(pub Array<T, NLen>) where T: PartialEq + Eq;

// Implement FSerializable for Repeated<T, NLen>
impl<T, NLen> FSerializable<Prod<T::SizeType, NLen>> for Repeated<T, NLen>
where
    T: FSerializable<T::SizeType> + Size + Default + PartialEq + Eq,
    T::SizeType: typenum::Unsigned + typenum::NonZero + ArraySize + CoreMul<NLen>,
    NLen: typenum::Unsigned + typenum::NonZero + ArraySize,
    Prod<T::SizeType, NLen>: typenum::Unsigned + typenum::NonZero + ArraySize,
    // Sub-component requirements for operations:
    // For serialize loop: NLen::USIZE must be valid.
    // For deserialize loop: NLen::USIZE, T::SizeType::USIZE must be valid.
    // Array<T, NLen> iterators and indexing are fine.
    // Array<u8, Prod<T::SizeType, NLen>> as_mut_slice and as_slice are fine.
    // Array<u8, T::SizeType> default and as_mut_slice are fine.
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
        let mut deserialized_items_array = Array::<T, NLen>::default();

        for i in 0..NLen::USIZE {
            let start = i * T::SizeType::USIZE;
            let end = start + T::SizeType::USIZE;

            let mut item_buffer = Array::<u8, T::SizeType>::default();
            item_buffer.as_mut_slice().copy_from_slice(&buffer.as_slice()[start..end]);

            // T::deserialize now returns Result
            deserialized_items_array.as_mut_slice()[i] = T::deserialize(item_buffer)?;
        }
        Ok(Repeated(deserialized_items_array))
    }
}


// Removing old Pair struct and its impls, as Product<A,B> replaces it.
/*
#[derive(Debug)]
pub struct Pair<T1, T2>
where
    T1: Size,
    T2: Size,
    T1::SizeType: core::ops::Add<T2::SizeType>, // Required for Sum
    Sum<T1::SizeType, T2::SizeType>: Unsigned + ArraySize, // Result of Sum must be a valid size
{
    pub fst: T1,
    pub snd: T2,
}

impl<T1, T2> Size for Pair<T1, T2>
where
    T1: Size,
    T2: Size,
    T1::SizeType: core::ops::Add<T2::SizeType>, // Required for Sum
    Sum<T1::SizeType, T2::SizeType>: Unsigned + ArraySize,
{
    type SizeType = Sum<T1::SizeType, T2::SizeType>;
}

impl<T1, T2> Pair<T1, T2>
where
    T1: Size,
    T2: Size,
    T1::SizeType: core::ops::Add<T2::SizeType>,
    Sum<T1::SizeType, T2::SizeType>: Unsigned + ArraySize,
{
    pub fn new(fst: T1, snd: T2) -> Self {
        Pair { fst, snd }
    }
}
*/


#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::RistrettoElement;
    // Explicitly import typenum constants used in this module's tests for clarity/resolution
    use hybrid_array::typenum::{U1, U2, U3, U4, U5, U8, U32, Sum, Prod, Unsigned};

    // MyStruct and its impls are removed.

    #[test]
    fn test_u8_serialization() {
        let val: u8 = 0xAB;
        let serialized = val.serialize();
        assert_eq!(serialized.as_slice().len(), U1::USIZE);
        let deserialized = u8::deserialize(serialized).unwrap();
        assert_eq!(val, deserialized);
    }

    #[test]
    fn test_u16_serialization() {
        let val: u16 = 0xABCD;
        let serialized = val.serialize();
        assert_eq!(serialized.as_slice().len(), U2::USIZE);
        let deserialized = u16::deserialize(serialized).unwrap();
        assert_eq!(val, deserialized);

        let val_zero: u16 = 0;
        let serialized_zero = val_zero.serialize();
        let deserialized_zero = u16::deserialize(serialized_zero).unwrap();
        assert_eq!(val_zero, deserialized_zero);

        let val_max: u16 = u16::MAX;
        let serialized_max = val_max.serialize();
        let deserialized_max = u16::deserialize(serialized_max).unwrap();
        assert_eq!(val_max, deserialized_max);
    }

    #[test]
    fn test_u32_serialization() {
        let val: u32 = 0x12345678;
        let serialized = val.serialize();
        assert_eq!(serialized.as_slice().len(), U4::USIZE);
        let deserialized = u32::deserialize(serialized).unwrap();
        assert_eq!(val, deserialized);
    }

    #[test]
    fn test_u64_serialization() {
        let val: u64 = 0x123456789ABCDEF0;
        let serialized = val.serialize();
        assert_eq!(serialized.as_slice().len(), U8::USIZE);
        let deserialized = u64::deserialize(serialized).unwrap();
        assert_eq!(val, deserialized);
    }

    #[test]
    fn test_product_element_serialization() { // Renamed from test_product_serialization
        // RistrettoElement implements Size (U32) and FSerializable<U32>
        // u16 implements Size (U2) and FSerializable<U2>
        let p = Product(RistrettoElement::default(), 0xABCD_u16);
        let serialized: Array<u8, Sum<U32, U2>> = p.serialize(); // U32 for RistrettoElement
        assert_eq!(serialized.as_slice().len(), <Sum<U32, U2> as Unsigned>::USIZE);
        let deserialized = Product::<RistrettoElement, u16>::deserialize(serialized).unwrap();
        assert_eq!(p.0, deserialized.0);
        assert_eq!(p.1, deserialized.1);
    }

    #[test]
    fn test_product_basic_types_serialization() {
        let p = Product(0xABCD_u16, 0x12345678_u32);
        let serialized: Array<u8, Sum<U2, U4>> = p.serialize();
        assert_eq!(serialized.as_slice().len(), <Sum<U2, U4> as Unsigned>::USIZE);
        assert_eq!(<Sum<U2, U4> as Unsigned>::USIZE, 6);
        let deserialized = Product::<u16, u32>::deserialize(serialized).unwrap();
        assert_eq!(p.0, deserialized.0);
        assert_eq!(p.1, deserialized.1);
    }

    #[test]
    fn test_repeated_u8_serialization() {
        let data_slice = &[10, 20, 30, 40, 50];
        let r = Repeated(Array::<u8, U5>::from(*data_slice));

        let serialized = r.serialize();
        assert_eq!(serialized.as_slice().len(), <Prod<U1, U5> as Unsigned>::USIZE);
        assert_eq!(<Prod<U1, U5> as Unsigned>::USIZE, 5);
        let deserialized = Repeated::<u8, U5>::deserialize(serialized).unwrap();
        assert_eq!(r.0.as_slice(), deserialized.0.as_slice());
    }

    #[test]
    fn test_repeated_element_serialization() { // Renamed from test_repeated_mystruct_serialization
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

        let r = Repeated(Array::<RistrettoElement, U3>::from([e1, e2, e3]));

        let serialized = r.serialize();
        assert_eq!(serialized.as_slice().len(), <Prod<U32, U3> as Unsigned>::USIZE); // U32 for RistrettoElement
        assert_eq!(<Prod<U32, U3> as Unsigned>::USIZE, 32 * 3);
        let deserialized = Repeated::<RistrettoElement, U3>::deserialize(serialized).unwrap();

        assert_eq!(r.0.as_slice()[0], deserialized.0.as_slice()[0]);
        assert_eq!(r.0.as_slice()[1], deserialized.0.as_slice()[1]);
        assert_eq!(r.0.as_slice()[2], deserialized.0.as_slice()[2]);
        assert_eq!(r.0, deserialized.0);
    }
}

// FSerializable implementations for basic types & Size impls for them

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
