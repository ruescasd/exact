use crate::serialization_hybrid::{FSerializable, Product, Size}; // Using new serialization_hybrid, aliased Size
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use core::fmt::Debug;
use hybrid_array::typenum::{Prod}; // Removed Mul from here
use hybrid_array::ArraySize; // For ArraySize constraint
use core::ops::Mul as CoreMul; // For Mul trait bound

pub trait GroupElement: Size + Debug
    // Common group operations as trait bounds (optional, can be methods too)
    // + Add<Self, Output = Self>
    // + Neg<Output = Self>
    // + Sub<Self, Output = Self> // Usually derived from Add + Neg
{
    // Associated type for the scalar field of this group element
    type Scalar: GroupScalar;

    // Group operations
    fn identity() -> Self; // Can often be Self::default()
    fn add_element(&self, other: &Self) -> Self;
    fn negate_element(&self) -> Self;
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;
}

#[derive(Debug)]
pub struct ElementN<G, LenType>(pub Product<G::Element, LenType>)
where
    G: CryptoGroup,
    LenType: ArraySize;

impl<G, LenType> ElementN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
{
    pub fn new(elements: Product<G::Element, LenType>) -> Self {
        ElementN(elements)
    }
}
impl<G, LenType> FSerializable<Prod<<G::Element as Size>::SizeType, LenType>>
    for ElementN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    G::Element: FSerializable<<G::Element as Size>::SizeType> + Size,
    <G::Element as Size>::SizeType: CoreMul<LenType>,
    Prod<<G::Element as Size>::SizeType, LenType>: ArraySize,
{
    fn serialize(&self) -> hybrid_array::Array<u8, Prod<<G::Element as Size>::SizeType, LenType>> {
        self.0.serialize()
    }

    fn deserialize(buffer: hybrid_array::Array<u8, Prod<<G::Element as Size>::SizeType, LenType>>) -> Result<Self, crate::serialization_hybrid::Error> {
        Ok(ElementN(Product::<G::Element, LenType>::deserialize(buffer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports ElementN, GroupElement
    use crate::serialization_hybrid::{FSerializable, Product, Size as Size};
    use crate::traits::group::CryptoGroup;
    use crate::traits::scalar::GroupScalar; // For TestElement's associated type
    use hybrid_array::typenum::{Prod, Unsigned, U3, U16, U32}; // More specific imports
    use hybrid_array::{Array};
    use core::fmt::Debug;

    use core::ops::{Add, Sub, Neg};
    
    // --- Mock Implementations ---

    // 1. Mock Scalar (minimal for Element tests, more fleshed out in scalar.rs tests)
    // GroupScalar trait will be updated to have no size generics.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct TestScalar(Array<u8, U16>);

    impl Size for TestScalar {
        type SizeType = U16;
    }
    impl FSerializable<U16> for TestScalar {
        fn serialize(&self) -> Array<u8, U16> { self.0.clone() }
        fn deserialize(buffer: Array<u8, U16>) -> Result<Self, crate::serialization_hybrid::Error> { Ok(TestScalar(buffer)) }
    }
    // Implement ops traits for TestScalar
    impl Add for TestScalar { type Output = Self; fn add(self, _rhs: Self) -> Self { Default::default() } }
    impl Sub for TestScalar { type Output = Self; fn sub(self, _rhs: Self) -> Self { Default::default() } }
    impl CoreMul for TestScalar { type Output = Self; fn mul(self, _rhs: Self) -> Self { Default::default() } }
    impl Neg for TestScalar { type Output = Self; fn neg(self) -> Self { Default::default() } }

    impl GroupScalar for TestScalar { // No U16 generic here
        fn zero() -> Self { TestScalar::default() }
        fn one() -> Self { TestScalar::default() }
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

    impl Size for TestElement {
        type SizeType = U32;
    }
    impl FSerializable<U32> for TestElement {
        fn serialize(&self) -> Array<u8, U32> { self.0.clone() }
        fn deserialize(buffer: Array<u8, U32>) -> Result<Self, crate::serialization_hybrid::Error> { Ok(TestElement(buffer)) }
    }
    // Implement ops traits for TestElement
    impl Add for TestElement { type Output = Self; fn add(self, _rhs: Self) -> Self { Default::default() } }
    impl Sub for TestElement { type Output = Self; fn sub(self, _rhs: Self) -> Self { Default::default() } } // Not strictly required by GroupElement if it uses Add/Neg
    impl Neg for TestElement { type Output = Self; fn neg(self) -> Self { Default::default() } }

    impl GroupElement for TestElement {
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
        // ElementSerializedSize and ScalarSerializedSize removed from trait
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
        let repeated_elements = Product(elements_array); // Use struct directly
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
        
        assert_eq!(element_n_val.0.0, deserialized_element_n.0.0); // Compare Array<TestElement, U3>
    }
}
