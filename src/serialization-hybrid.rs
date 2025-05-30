use core::marker::PhantomData;
// Updated import to include Prod, Sum, Unsigned, True, IsEqual, Add1, Sub1, NonZero directly for clarity
use hybrid_array::{
    typenum::{self, Prod, Sum, Unsigned, True, IsEqual, Add1, Sub1, NonZero},
    Array, ArraySize,
};

pub trait Size {
    type SizeType: typenum::Unsigned + ArraySize;
}

// Size trait should be previously defined or imported if it's in the same file.
// Assuming Size trait from the previous step:
// pub trait Size {
//     type SizeType: typenum::Unsigned + ArraySize;
// }

pub trait FSerializable<SerializationLength: typenum::Unsigned + ArraySize>: Sized + Size
where
    Self::SizeType: typenum::IsEqual<SerializationLength, Output = typenum::True> // Ensure FSerializable is implemented for the correct length.
{
    fn read_bytes(bytes: Array<u8, SerializationLength>) -> Self;
    fn write_bytes(&self) -> Array<u8, SerializationLength>;
}

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

// Ensure necessary imports are present at the top of the file:
// use hybrid_array::{
//     typenum::{self, Prod, Unsigned, True, IsEqual},
//     Array, ArraySize,
// };
// use crate::serialization_hybrid::{Size, FSerializable}; // Assuming these are in the same module or crate::*

impl<L, T> FSerializable<Prod<T::SizeType, L>> for Product<L, T>
where
    L: Unsigned + ArraySize, // Length of the product array
    T: Size + FSerializable<T::SizeType>, // Element type must be serializable
    T::SizeType: core::ops::Mul<L>, // For calculating Prod<T::SizeType, L>
    Prod<T::SizeType, L>: Unsigned + ArraySize, // The total size of the serialized product
    // This constraint ensures we are implementing FSerializable for the Product's actual SizeType
    Self::SizeType: IsEqual<Prod<T::SizeType, L>, Output = True>,
{
    fn read_bytes(bytes: Array<u8, Prod<T::SizeType, L>>) -> Self {
        // We need to convert Array<u8, Prod<T::SizeType, L>> into Array<T, L>
        // Each T is read from a chunk of size T::SizeType.
        // The total number of elements is L::USIZE.
        // The size of each element T is T::SizeType::USIZE.

        let mut elements_builder = Array::<T, L>::builder();
        let mut offset = 0usize;

        for _i in 0..L::USIZE {
            let element_size = T::SizeType::USIZE;
            // Create a temporary byte array for the current element
            let mut element_bytes_array = Array::<u8, T::SizeType>::default(); // Requires T::SizeType to impl Default, which ArraySize does.

            // Copy the slice from the input `bytes` array.
            // `bytes.as_slice()` gives `&[u8]`.
            // We need to get `&[u8; T::SizeType::USIZE]` to convert to `Array<u8, T::SizeType>`.
            let chunk_slice = &bytes.as_slice()[offset..offset + element_size];
            element_bytes_array.as_mut_slice().copy_from_slice(chunk_slice);

            elements_builder.push(T::read_bytes(element_bytes_array));
            offset += element_size;
        }
        Product { elements: elements_builder.finish() }
    }

    fn write_bytes(&self) -> Array<u8, Prod<T::SizeType, L>> {
        // We need to convert Array<T, L> into Array<u8, Prod<T::SizeType, L>>.
        // Each T is written into a chunk of size T::SizeType.
        let mut result_bytes = Array::<u8, Prod<T::SizeType, L>>::default();
        let mut offset = 0usize;

        for i in 0..L::USIZE {
            let element_bytes = self.elements.as_slice()[i].write_bytes();
            let element_size = T::SizeType::USIZE;
            result_bytes.as_mut_slice()[offset..offset + element_size]
                .copy_from_slice(element_bytes.as_slice());
            offset += element_size;
        }
        result_bytes
    }
}

// Add constructor for Product for easier use, similar to original
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

    // If map and zip_with are needed, they would be implemented here.
    // For now, focusing on serialization.
}

// Ensure necessary imports are present at the top of the file:
// use hybrid_array::{
//     typenum::{self, Prod, Sum, Unsigned, True, IsEqual, Add1, Sub1, NonZero}, // Add Sum
//     Array, ArraySize,
// };
// use crate::serialization_hybrid::{Size, FSerializable}; // Or other path if different

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

impl<T1, T2> FSerializable<Sum<T1::SizeType, T2::SizeType>> for Pair<T1, T2>
where
    T1: Size + FSerializable<T1::SizeType>,
    T2: Size + FSerializable<T2::SizeType>,
    T1::SizeType: core::ops::Add<T2::SizeType>,
    Sum<T1::SizeType, T2::SizeType>: Unsigned + ArraySize,
    // This constraint ensures we are implementing FSerializable for the Pair's actual SizeType
    Self::SizeType: IsEqual<Sum<T1::SizeType, T2::SizeType>, Output = True>,
    // Additional bounds for Array::split and Array::concat
    T1::SizeType: Add1 + Sub1 + NonZero, // Required for split/concat points
    T2::SizeType: Add1 + Sub1 + NonZero, // Required for split/concat points
{
    fn read_bytes(bytes: Array<u8, Sum<T1::SizeType, T2::SizeType>>) -> Self {
        // Split the incoming array into two parts for T1 and T2
        // T1::SizeType gives us the split point.
        let (bytes_t1, bytes_t2) = bytes.split::<T1::SizeType>();

        let field1_val = T1::read_bytes(bytes_t1.into_owned()); // into_owned converts ArrayView to Array
        let field2_val = T2::read_bytes(bytes_t2.into_owned());

        Pair {
            fst: field1_val,
            snd: field2_val,
        }
    }

    fn write_bytes(&self) -> Array<u8, Sum<T1::SizeType, T2::SizeType>> {
        let bytes_t1 = self.fst.write_bytes();
        let bytes_t2 = self.snd.write_bytes();

        // Concatenate the two byte arrays
        bytes_t1.concat(bytes_t2)
    }
}

// Add constructor for Pair
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

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module (serialization_hybrid)
    use hybrid_array::typenum::{U2, U4, U8}; // Example type numbers for sizes

    // 1. Define a simple struct for testing
    #[derive(Debug, PartialEq, Clone, Copy)] // Added Copy for simpler Product init
    struct MyStruct {
        val: u32,
    }

    // 2. Implement Size for MyStruct
    impl Size for MyStruct {
        type SizeType = U4; // Assuming u32 takes 4 bytes
    }

    // 3. Implement FSerializable for MyStruct
    impl FSerializable<U4> for MyStruct {
        fn read_bytes(bytes: Array<u8, U4>) -> Self {
            let mut u32_bytes = [0u8; 4];
            u32_bytes.copy_from_slice(bytes.as_slice());
            MyStruct {
                val: u32::from_ne_bytes(u32_bytes),
            }
        }

        fn write_bytes(&self) -> Array<u8, U4> {
            Array::from(self.val.to_ne_bytes())
        }
    }

    #[test]
    fn test_mystruct_serialization() {
        let original = MyStruct { val: 0x12345678 };
        let serialized = original.write_bytes();
        let deserialized = MyStruct::read_bytes(serialized);
        assert_eq!(original, deserialized);
        assert_eq!(MyStruct::SizeType::USIZE, 4);
        assert_eq!(serialized.len(), 4);
    }

    #[test]
    fn test_product_serialization() {
        // Product of 2 MyStructs
        type MyProduct = Product<U2, MyStruct>; // U2 is length, MyStruct is type

        let val1 = MyStruct { val: 100 };
        let val2 = MyStruct { val: 200 };
        let elements = Array::<MyStruct, U2>::from([val1, val2]);
        let original_product = MyProduct::new(elements);

        // Check size calculation: U2 * U4 = U8
        assert_eq!(MyProduct::SizeType::USIZE, 8);

        let serialized_product = original_product.write_bytes();
        assert_eq!(serialized_product.len(), 8);

        let deserialized_product = MyProduct::read_bytes(serialized_product);

        assert_eq!(original_product.elements.as_slice()[0], deserialized_product.elements.as_slice()[0]);
        assert_eq!(original_product.elements.as_slice()[1], deserialized_product.elements.as_slice()[1]);
    }

    #[test]
    fn test_pair_serialization() {
        // Pair of MyStruct and MyStruct
        type MyPair = Pair<MyStruct, MyStruct>;

        let val1 = MyStruct { val: 300 };
        let val2 = MyStruct { val: 400 };
        let original_pair = MyPair::new(val1, val2);

        // Check size calculation: U4 + U4 = U8
        assert_eq!(MyPair::SizeType::USIZE, 8);

        let serialized_pair = original_pair.write_bytes();
        assert_eq!(serialized_pair.len(), 8);

        let deserialized_pair = MyPair::read_bytes(serialized_pair);

        assert_eq!(original_pair.fst, deserialized_pair.fst);
        assert_eq!(original_pair.snd, deserialized_pair.snd);
    }

    // Test for Product with a different length
    #[test]
    fn test_product_serialization_len_1() {
        type MyProductLen1 = Product<hybrid_array::typenum::U1, MyStruct>;

        let val1 = MyStruct { val: 500 };
        let elements = Array::<MyStruct, hybrid_array::typenum::U1>::from([val1]);
        let original_product = MyProductLen1::new(elements);

        assert_eq!(MyProductLen1::SizeType::USIZE, 4); // U1 * U4 = U4

        let serialized_product = original_product.write_bytes();
        assert_eq!(serialized_product.len(), 4);

        let deserialized_product = MyProductLen1::read_bytes(serialized_product);
        assert_eq!(original_product.elements.as_slice()[0], deserialized_product.elements.as_slice()[0]);
    }
}
