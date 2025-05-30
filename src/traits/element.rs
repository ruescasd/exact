use crate::serialization_hybrid::{FSerializable, Repeated, Size as SerHySize}; // Using new serialization_hybrid, aliased Size
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use core::fmt::Debug;
use hybrid_array::typenum::{Unsigned, NonZero, Prod}; // Removed Mul from here
use hybrid_array::ArraySize; // For ArraySize constraint
use core::ops::Mul as CoreMul; // For Mul trait bound

/// Represents an element in a cryptographic group.
/// Generic over S (ElementSerializedSize) and SS (ScalarSerializedSize) which are typenum types.
pub trait GroupElement<S, SS>:
    SerHySize<SizeType = S> + FSerializable<S> + Clone + Debug + PartialEq + Eq + Sized
where
    S: Unsigned + NonZero + ArraySize, // Element size
    SS: Unsigned + NonZero + ArraySize, // Scalar size (used by associated Scalar type)
{
    // Associated type for the scalar field of this group element
    // GroupScalar will also need to be generic over SS (a typenum type)
    type Scalar: GroupScalar<SS>;

    // Group operations
    fn identity() -> Self;
    fn add_element(&self, other: &Self) -> Self;
    fn negate_element(&self) -> Self;
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;
}

// --- Generic ElementN struct and implementations ---
// ElementN is a collection of LenType group elements.
// It should use Repeated from serialization_hybrid.
// G::ElementSerializedSize is the size of one element.
// LenType is the number of elements (a typenum type).
#[derive(Debug, Clone)] // Assuming G::Element will be Clone
pub struct ElementN<G, LenType>(pub Repeated<G::Element, LenType>)
where
    G: CryptoGroup,
    LenType: Unsigned + NonZero + ArraySize,
    G::Element: Clone + Default, // Default needed for Repeated if T: Default is used there.
    G::ElementSerializedSize: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<G::ElementSerializedSize, LenType>: Unsigned + NonZero + ArraySize;


impl<G, LenType> ElementN<G, LenType>
where
    G: CryptoGroup,
    LenType: Unsigned + NonZero + ArraySize,
    G::Element: Clone + Default, // Default needed for Repeated
    G::ElementSerializedSize: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<G::ElementSerializedSize, LenType>: Unsigned + NonZero + ArraySize,
{
    /// Creates a new ElementN from a Repeated struct of group elements.
    pub fn new(elements: Repeated<G::Element, LenType>) -> Self {
        ElementN(elements)
    }
}

// No need for `impl serialization::Size for ElementN` anymore.
// It will implement `serialization_hybrid::FSerializable<Prod<G::ElementSerializedSize, LenType>>`

impl<G, LenType> FSerializable<Prod<G::ElementSerializedSize, LenType>>
    for ElementN<G, LenType>
where
    G: CryptoGroup,
    G::Element: FSerializable<G::ElementSerializedSize>
               + SerHySize<SizeType=G::ElementSerializedSize>
               + Default
               + Clone, // Added Clone here
    LenType: Unsigned + NonZero + ArraySize,
    G::ElementSerializedSize: Unsigned + NonZero + ArraySize + CoreMul<LenType>, // For Prod
    Prod<G::ElementSerializedSize, LenType>: Unsigned + NonZero + ArraySize, // Result of Prod must be valid size
{
    fn serialize(&self) -> hybrid_array::Array<u8, Prod<G::ElementSerializedSize, LenType>> {
        self.0.serialize() // Delegate to Repeated's implementation
    }

    fn deserialize(buffer: hybrid_array::Array<u8, Prod<G::ElementSerializedSize, LenType>>) -> Result<Self, crate::serialization_hybrid::Error> {
        Ok(ElementN(Repeated::<G::Element, LenType>::deserialize(buffer)?)) // Delegate and handle Result
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports ElementN, GroupElement
    use crate::serialization_hybrid::{FSerializable, Repeated, Size as SerHySize};
    use crate::traits::group::CryptoGroup;
    use crate::traits::scalar::GroupScalar; // For TestElement's associated type
    use hybrid_array::typenum::{Prod, Unsigned, NonZero, U3, U16, U32}; // More specific imports
    use hybrid_array::{Array, ArraySize};
    use core::fmt::Debug;

    // --- Mock Implementations ---

    // 1. Mock Scalar (minimal for Element tests, more fleshed out in scalar.rs tests)
    #[derive(Clone, Debug, PartialEq, Eq, Default)] // Added Eq
    pub struct TestScalar(Array<u8, U16>); // Example size U16

    impl SerHySize for TestScalar {
        type SizeType = U16;
    }
    impl FSerializable<U16> for TestScalar {
        fn serialize(&self) -> Array<u8, U16> { self.0.clone() }
        fn deserialize(buffer: Array<u8, U16>) -> Result<Self, crate::serialization_hybrid::Error> { Ok(TestScalar(buffer)) }
    }
    impl GroupScalar<U16> for TestScalar {
        fn zero() -> Self { TestScalar::default() }
        fn one() -> Self { TestScalar::default() } // Stub
        fn random<R: rand::RngCore + rand::CryptoRng>(_rng: &mut R) -> Self { TestScalar::default() }
        fn add(&self, _other: &Self) -> Self { TestScalar::default() }
        fn sub(&self, _other: &Self) -> Self { TestScalar::default() }
        fn mul(&self, _other: &Self) -> Self { TestScalar::default() }
        fn negate(&self) -> Self { TestScalar::default() }
        fn invert(&self) -> Option<Self> { Some(TestScalar::default()) }
    }

    // 2. Mock Element
    #[derive(Clone, Debug, PartialEq, Eq, Default)] // Added Eq
    pub struct TestElement(Array<u8, U32>); // Example size U32

    impl SerHySize for TestElement {
        type SizeType = U32;
    }
    impl FSerializable<U32> for TestElement {
        fn serialize(&self) -> Array<u8, U32> { self.0.clone() }
        fn deserialize(buffer: Array<u8, U32>) -> Result<Self, crate::serialization_hybrid::Error> { Ok(TestElement(buffer)) }
    }
    impl GroupElement<U32, U16> for TestElement { // U32 for Element, U16 for Scalar
        type Scalar = TestScalar;
        fn identity() -> Self { TestElement::default() }
        fn add_element(&self, _other: &Self) -> Self { TestElement::default() }
        fn negate_element(&self) -> Self { TestElement::default() }
        fn scalar_mul(&self, _scalar: &Self::Scalar) -> Self { TestElement::default() }
    }

    // 3. Mock CryptoGroup
    #[derive(Debug)]
    pub struct TestGroup;

    impl CryptoGroup for TestGroup {
        type ElementSerializedSize = U32;
        type ScalarSerializedSize = U16;
        type Element = TestElement;
        type Scalar = TestScalar;

        fn generator() -> Self::Element { TestElement::default() }
        fn hash_to_scalar(_input_slices: &[&[u8]]) -> Self::Scalar { TestScalar::default() }
    }

    // --- Tests for ElementN ---
    #[test]
    fn test_element_n_serialization() {
        // Prepare data for ElementN
        let e1_data = Array::<u8, U32>::from([1u8; U32::USIZE]); // Changed from_slice().unwrap()
        let e2_data = Array::<u8, U32>::from([2u8; U32::USIZE]); // Changed from_slice().unwrap()
        let e3_data = Array::<u8, U32>::from([3u8; U32::USIZE]); // Changed from_slice().unwrap()

        let e1 = TestElement(e1_data.clone());
        let e2 = TestElement(e2_data.clone());
        let e3 = TestElement(e3_data.clone());

        type ElementNTestType = ElementN<TestGroup, U3>;
        // Removed ElementNInnerRepeatedType, it's just Repeated<TestElement, U3>
        type ElementNSerializedLen = Prod<U32, U3>;

        let elements_array = Array::<TestElement, U3>::from([e1.clone(), e2.clone(), e3.clone()]);
        let repeated_elements = Repeated(elements_array); // Use struct directly
        let element_n_val = ElementNTestType::new(repeated_elements);

        // Serialize
        let serialized_bytes = element_n_val.serialize();
        assert_eq!(serialized_bytes.as_slice().len(), ElementNSerializedLen::USIZE);

        // Check content (simple check based on mock TestElement serialization)
        let mut expected_bytes = Vec::new();
        expected_bytes.extend_from_slice(e1_data.as_slice());
        expected_bytes.extend_from_slice(e2_data.as_slice());
        expected_bytes.extend_from_slice(e3_data.as_slice());
        assert_eq!(serialized_bytes.as_slice(), expected_bytes.as_slice());

        // Deserialize
        let deserialized_element_n_result = ElementNTestType::deserialize(serialized_bytes);
        assert!(deserialized_element_n_result.is_ok());
        let deserialized_element_n = deserialized_element_n_result.unwrap();

        // Assert equality
        assert_eq!(element_n_val.0.0.as_slice()[0], deserialized_element_n.0.0.as_slice()[0]);
        assert_eq!(element_n_val.0.0.as_slice()[1], deserialized_element_n.0.0.as_slice()[1]);
        assert_eq!(element_n_val.0.0.as_slice()[2], deserialized_element_n.0.0.as_slice()[2]);
        // For full equality, Repeated needs PartialEq, which means Array needs it, which means TestElement needs it (already derived)
        assert_eq!(element_n_val.0.0, deserialized_element_n.0.0); // Compare Array<TestElement, U3>
    }
}
