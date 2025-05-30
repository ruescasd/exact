use crate::serialization_hybrid::{FSerializable, Repeated, Size as SerHySize}; // Using new serialization_hybrid, aliased Size
use crate::traits::group::CryptoGroup;
use core::fmt::Debug;
use rand::RngCore;
use hybrid_array::typenum::{Unsigned, NonZero, Prod}; // Removed Mul from here
use hybrid_array::ArraySize; // For ArraySize constraint
use core::ops::Mul as CoreMul; // For Mul trait bound


/// Represents a scalar in a cryptographic group.
/// Generic over S (ScalarSerializedSize) which is a typenum type.
pub trait GroupScalar<S>:
    SerHySize<SizeType = S> + FSerializable<S> + Clone + Debug + PartialEq + Eq + Sized
where
    S: Unsigned + NonZero + ArraySize, // Scalar size
{
    // Constants
    fn zero() -> Self;
    fn one() -> Self;

    // Random generation
    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self;

    // Arithmetic operations
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn negate(&self) -> Self;
    fn invert(&self) -> Option<Self>;
}

// --- Generic ExponentN struct and implementations ---
// ExponentN is a collection of LenType group scalars.
// It should use Repeated from serialization_hybrid.
// G::ScalarSerializedSize is the size of one scalar.
// LenType is the number of scalars (a typenum type).
#[derive(Debug, Clone)] // Assuming G::Scalar will be Clone
pub struct ExponentN<G, LenType>(pub Repeated<G::Scalar, LenType>)
where
    G: CryptoGroup,
    LenType: Unsigned + NonZero + ArraySize,
    G::Scalar: Clone + Default, // Default needed for Repeated
    G::ScalarSerializedSize: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<G::ScalarSerializedSize, LenType>: Unsigned + NonZero + ArraySize;

impl<G, LenType> ExponentN<G, LenType>
where
    G: CryptoGroup,
    LenType: Unsigned + NonZero + ArraySize,
    G::Scalar: Clone + Default, // Default needed for Repeated
    G::ScalarSerializedSize: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<G::ScalarSerializedSize, LenType>: Unsigned + NonZero + ArraySize,
{
    /// Creates a new ExponentN from a Repeated struct of group scalars.
    pub fn new(elements: Repeated<G::Scalar, LenType>) -> Self {
        ExponentN(elements)
    }
}

// No need for `impl serialization::Size for ExponentN` anymore.
// It will implement `serialization_hybrid::FSerializable<Prod<G::ScalarSerializedSize, LenType>>`

impl<G, LenType> FSerializable<Prod<G::ScalarSerializedSize, LenType>>
    for ExponentN<G, LenType>
where
    G: CryptoGroup,
    G::Scalar: FSerializable<G::ScalarSerializedSize>
               + SerHySize<SizeType=G::ScalarSerializedSize>
               + Default
               + Clone, // Added Clone here
    LenType: Unsigned + NonZero + ArraySize,
    G::ScalarSerializedSize: Unsigned + NonZero + ArraySize + CoreMul<LenType>, // For Prod
    Prod<G::ScalarSerializedSize, LenType>: Unsigned + NonZero + ArraySize, // Result of Prod must be valid size
{
    fn serialize(&self) -> hybrid_array::Array<u8, Prod<G::ScalarSerializedSize, LenType>> {
        self.0.serialize() // Delegate to Repeated's implementation
    }

    fn deserialize(buffer: hybrid_array::Array<u8, Prod<G::ScalarSerializedSize, LenType>>) -> Result<Self, crate::serialization_hybrid::Error> {
        Ok(ExponentN(Repeated::<G::Scalar, LenType>::deserialize(buffer)?)) // Delegate and handle Result
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Imports ExponentN, GroupScalar
    use crate::serialization_hybrid::{FSerializable, Repeated, Size as SerHySize};
    use crate::traits::group::CryptoGroup;
    use crate::traits::element::GroupElement;
    use hybrid_array::typenum::{Prod, Unsigned, NonZero, U3, U16, U32}; // More specific imports
    use hybrid_array::{Array, ArraySize};
    use core::fmt::Debug;
    use rand::thread_rng;

    // --- Mock Implementations ---
    // Use the same TestGroup, TestElement, TestScalar from element.rs tests if possible,
    // or redefine if more specific scalar behavior is needed.
    // For simplicity, we can copy/adapt the mocks if they are not too large.
    // Assuming TestScalar, TestElement, TestGroup are accessible (e.g. if put in a common test utils file, or element.rs tests are pub)
    // For now, let's redefine simplified versions here, focusing on Scalar.

    // 1. Mock Element (minimal for Scalar tests, if needed by CryptoGroup)
    #[derive(Clone, Debug, PartialEq, Eq, Default)] // Added Eq
    pub struct TestElementForScalarTests(Array<u8, U32>);
    impl SerHySize for TestElementForScalarTests { type SizeType = U32; }
    impl FSerializable<U32> for TestElementForScalarTests {
        fn serialize(&self) -> Array<u8, U32> { self.0.clone() }
        fn deserialize(buffer: Array<u8, U32>) -> Result<Self, crate::serialization_hybrid::Error> { Ok(Self(buffer)) }
    }
    // Forward GroupScalar needed by GroupElement's Scalar associated type
    #[derive(Clone, Debug, PartialEq, Eq, Default)] // Added Eq
    pub struct TestScalarForElementTests(Array<u8, U16>);
    impl SerHySize for TestScalarForElementTests { type SizeType = U16; }
    impl FSerializable<U16> for TestScalarForElementTests {
        fn serialize(&self) -> Array<u8, U16> { self.0.clone() }
        fn deserialize(buffer: Array<u8, U16>) -> Result<Self, crate::serialization_hybrid::Error> { Ok(Self(buffer)) }
    }
    impl GroupScalar<U16> for TestScalarForElementTests { // Actual scalar trait
        fn zero() -> Self { Default::default() } fn one() -> Self { Default::default() }
        fn random<R: rand::RngCore + rand::CryptoRng>(_rng: &mut R) -> Self { Default::default() }
        fn add(&self, _other: &Self) -> Self { Default::default() } fn sub(&self, _other: &Self) -> Self { Default::default() }
        fn mul(&self, _other: &Self) -> Self { Default::default() } fn negate(&self) -> Self { Default::default() }
        fn invert(&self) -> Option<Self> { Some(Default::default()) }
    }
    impl GroupElement<U32, U16> for TestElementForScalarTests { // U32 for Element, U16 for Scalar
        type Scalar = TestScalar; // Corrected: Use the main TestScalar for this group
        fn identity() -> Self { Default::default() }
        fn add_element(&self, _other: &Self) -> Self { Default::default() }
        fn negate_element(&self) -> Self { Default::default() }
        fn scalar_mul(&self, _scalar: &Self::Scalar) -> Self { Default::default() }
    }


    // 2. Mock Scalar (this is the one we're really testing via ExponentN)
    #[derive(Clone, Debug, PartialEq, Eq, Default)] // Added Eq
    pub struct TestScalar(Array<u8, U16>); // Example size U16 for this scalar

    impl SerHySize for TestScalar {
        type SizeType = U16;
    }
    impl FSerializable<U16> for TestScalar {
        fn serialize(&self) -> Array<u8, U16> { self.0.clone() }
        fn deserialize(buffer: Array<u8, U16>) -> Result<Self, crate::serialization_hybrid::Error> { Ok(TestScalar(buffer)) }
    }
    impl GroupScalar<U16> for TestScalar {
        fn zero() -> Self { TestScalar::default() }
        fn one() -> Self { // Implement one to be different from zero for meaningful tests
            let mut arr = Array::<u8, U16>::default(); arr.as_mut_slice()[0] = 1; TestScalar(arr)
        }
        fn random<R: rand::RngCore + rand::CryptoRng>(_rng: &mut R) -> Self {
            let mut arr = Array::<u8, U16>::default();
            _rng.fill_bytes(arr.as_mut_slice()); // Fill with random bytes
            TestScalar(arr)
        }
        fn add(&self, other: &Self) -> Self { // Dummy add
            let mut res = self.0.clone();
            for (r, o) in res.as_mut_slice().iter_mut().zip(other.0.as_slice().iter()) {
                *r = r.wrapping_add(*o);
            }
            TestScalar(res)
        }
        fn sub(&self, _other: &Self) -> Self { TestScalar::default() } // Stubs
        fn mul(&self, _other: &Self) -> Self { TestScalar::default() }
        fn negate(&self) -> Self { TestScalar::default() }
        fn invert(&self) -> Option<Self> { Some(TestScalar::default()) }
    }

    // 3. Mock CryptoGroup
    #[derive(Debug)]
    pub struct TestGroupForScalar;

    impl CryptoGroup for TestGroupForScalar {
        type ElementSerializedSize = U32; // Size of TestElementForScalarTests
        type ScalarSerializedSize = U16;  // Size of TestScalar
        type Element = TestElementForScalarTests;
        type Scalar = TestScalar; // The scalar we are testing

        fn generator() -> Self::Element { TestElementForScalarTests::default() }
        fn hash_to_scalar(_input_slices: &[&[u8]]) -> Self::Scalar { TestScalar::default() }
    }

    // --- Tests for ExponentN ---
    #[test]
    fn test_exponent_n_serialization() {
        let mut rng = thread_rng();
        let s1_val = TestScalar::random(&mut rng);
        let s2_val = TestScalar::random(&mut rng);
        let s3_val = TestScalar::random(&mut rng);

        type ExponentNTestType = ExponentN<TestGroupForScalar, U3>;
        // Removed ExponentNInnerRepeatedType, it's just Repeated<TestScalar, U3>
        type ExponentNSerializedLen = Prod<U16, U3>;

        let scalars_array = Array::<TestScalar, U3>::from([s1_val.clone(), s2_val.clone(), s3_val.clone()]);
        let repeated_scalars = Repeated(scalars_array); // Use struct directly
        let exponent_n_val = ExponentNTestType::new(repeated_scalars);

        // Serialize
        let serialized_bytes = exponent_n_val.serialize();
        assert_eq!(serialized_bytes.as_slice().len(), ExponentNSerializedLen::USIZE);

        // Check content
        let mut expected_bytes = Vec::new();
        expected_bytes.extend_from_slice(s1_val.serialize().as_slice());
        expected_bytes.extend_from_slice(s2_val.serialize().as_slice());
        expected_bytes.extend_from_slice(s3_val.serialize().as_slice());
        assert_eq!(serialized_bytes.as_slice(), expected_bytes.as_slice());

        // Deserialize
        let deserialized_exponent_n_result = ExponentNTestType::deserialize(serialized_bytes);
        assert!(deserialized_exponent_n_result.is_ok());
        let deserialized_exponent_n = deserialized_exponent_n_result.unwrap();

        // Assert equality
        assert_eq!(exponent_n_val.0.0, deserialized_exponent_n.0.0);
    }
}
