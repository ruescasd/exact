use crate::serialization_hybrid::{FSerializable, Product, Size};
use crate::traits::group::CryptoGroup;
use core::fmt::Debug;
use core::ops::Mul as CoreMul;
use hybrid_array::ArraySize;
use hybrid_array::typenum::{NonZero, Prod};
use rand::RngCore;

pub trait GroupScalar: Sized
// + Add<Self, Output = Self>
// + Sub<Self, Output = Self>
// + CoreOpsMul<Self, Output = Self>
// + Neg<Output = Self>
{
    fn zero() -> Self;
    fn one() -> Self;
    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn negate(&self) -> Self;
    fn invert(&self) -> Option<Self>;
}

#[derive(Debug)]
pub struct ExponentN<G, LenType>(pub Product<G::Scalar, LenType>)
where
    G: CryptoGroup,
    LenType: ArraySize,
    G::Scalar: Size,
    <G::Scalar as Size>::SizeType: CoreMul<LenType>,
    Prod<<G::Scalar as Size>::SizeType, LenType>: ArraySize;

impl<G, LenType> ExponentN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    G::Scalar: Size,
    <G::Scalar as Size>::SizeType: CoreMul<LenType>,
    Prod<<G::Scalar as Size>::SizeType, LenType>: ArraySize,
{
    pub fn new(elements: Product<G::Scalar, LenType>) -> Self {
        ExponentN(elements)
    }
}

impl<G, LenType> FSerializable<Prod<<G::Scalar as Size>::SizeType, LenType>>
    for ExponentN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    G::Scalar: FSerializable<<G::Scalar as Size>::SizeType> + Size,
    <G::Scalar as Size>::SizeType: NonZero + CoreMul<LenType>,
    Prod<<G::Scalar as Size>::SizeType, LenType>: ArraySize,
{
    fn serialize(&self) -> hybrid_array::Array<u8, Prod<<G::Scalar as Size>::SizeType, LenType>> {
        self.0.serialize()
    }

    fn deserialize(
        buffer: hybrid_array::Array<u8, Prod<<G::Scalar as Size>::SizeType, LenType>>,
    ) -> Result<Self, crate::serialization_hybrid::Error> {
        Ok(ExponentN(Product::<G::Scalar, LenType>::deserialize(
            buffer,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization_hybrid::{Error as SerError, FSerializable, Product, Size};
    use crate::traits::element::GroupElement;
    use crate::traits::group::CryptoGroup;
    use core::fmt::Debug;
    use core::ops::{Add, Mul as CoreOpsMul, Neg, Sub};
    use hybrid_array::Array;
    use hybrid_array::typenum::{Prod, U3, U16, U32, Unsigned};
    use rand::thread_rng;

    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct TestElementForScalarTests(Array<u8, U32>);
    impl Size for TestElementForScalarTests {
        type SizeType = U32;
    }
    impl FSerializable<U32> for TestElementForScalarTests {
        fn serialize(&self) -> Array<u8, U32> {
            self.0.clone()
        }
        fn deserialize(buffer: Array<u8, U32>) -> Result<Self, SerError> {
            Ok(Self(buffer))
        }
    }
    impl Add for TestElementForScalarTests {
        type Output = Self;
        fn add(self, _rhs: Self) -> Self {
            Default::default()
        }
    }
    impl Neg for TestElementForScalarTests {
        type Output = Self;
        fn neg(self) -> Self {
            Default::default()
        }
    }
    impl Sub for TestElementForScalarTests {
        type Output = Self;
        fn sub(self, _rhs: Self) -> Self {
            Default::default()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct TestScalar(Array<u8, U16>);
    impl Size for TestScalar {
        type SizeType = U16;
    }
    impl FSerializable<U16> for TestScalar {
        fn serialize(&self) -> Array<u8, U16> {
            self.0.clone()
        }
        fn deserialize(buffer: Array<u8, U16>) -> Result<Self, SerError> {
            Ok(TestScalar(buffer))
        }
    }
    impl Add for TestScalar {
        type Output = Self;
        fn add(self, rhs: Self) -> Self {
            let mut res = self.0.clone();
            for (r_byte, rhs_byte) in res.as_mut_slice().iter_mut().zip(rhs.0.as_slice().iter()) {
                *r_byte = r_byte.wrapping_add(*rhs_byte);
            }
            TestScalar(res)
        }
    }
    impl Sub for TestScalar {
        type Output = Self;
        fn sub(self, _rhs: Self) -> Self {
            Default::default()
        }
    }
    impl CoreOpsMul for TestScalar {
        type Output = Self;
        fn mul(self, _rhs: Self) -> Self {
            Default::default()
        }
    }
    impl Neg for TestScalar {
        type Output = Self;
        fn neg(self) -> Self {
            Default::default()
        }
    }
    impl GroupScalar for TestScalar {
        fn zero() -> Self {
            TestScalar::default()
        }
        fn one() -> Self {
            let mut arr = Array::<u8, U16>::default();
            arr.as_mut_slice()[0] = 1;
            TestScalar(arr)
        }
        fn random<R: rand::RngCore + rand::CryptoRng>(_rng: &mut R) -> Self {
            let mut arr = Array::<u8, U16>::default();
            _rng.fill_bytes(arr.as_mut_slice());
            TestScalar(arr)
        }
        fn add(&self, other: &Self) -> Self {
            self.clone() + other.clone()
        }
        fn sub(&self, other: &Self) -> Self {
            self.clone() - other.clone()
        }
        fn mul(&self, other: &Self) -> Self {
            self.clone() * other.clone()
        }
        fn negate(&self) -> Self {
            -(self.clone())
        }
        fn invert(&self) -> Option<Self> {
            Some(TestScalar::default())
        }
    }

    impl GroupElement for TestElementForScalarTests {
        type Scalar = TestScalar;
        fn identity() -> Self {
            Default::default()
        }
        fn add_element(&self, _other: &Self) -> Self {
            Default::default()
        }
        fn negate_element(&self) -> Self {
            Default::default()
        }
        fn scalar_mul(&self, _scalar: &Self::Scalar) -> Self {
            Default::default()
        }
    }

    #[derive(Debug)]
    pub struct TestGroupForScalar;
    impl CryptoGroup for TestGroupForScalar {
        type Element = TestElementForScalarTests;
        type Scalar = TestScalar;
        fn generator() -> Self::Element {
            TestElementForScalarTests::default()
        }
        fn hash_to_scalar(_input_slices: &[&[u8]]) -> Self::Scalar {
            TestScalar::default()
        }
    }

    #[test]
    fn test_exponent_n_serialization() {
        let mut rng = thread_rng();
        let s1_val = TestScalar::random(&mut rng);
        let s2_val = TestScalar::random(&mut rng);
        let s3_val = TestScalar::random(&mut rng);

        type ExponentNTestType = ExponentN<TestGroupForScalar, U3>;
        type ExponentNSerializedLen = Prod<U16, U3>;

        let scalars_array =
            Array::<TestScalar, U3>::from([s1_val.clone(), s2_val.clone(), s3_val.clone()]);
        let repeated_scalars = Product(scalars_array);
        let exponent_n_val = ExponentNTestType::new(repeated_scalars);

        let serialized_bytes = exponent_n_val.serialize();
        assert_eq!(
            serialized_bytes.as_slice().len(),
            ExponentNSerializedLen::USIZE
        );

        let mut expected_bytes = Vec::new();
        expected_bytes.extend_from_slice(s1_val.serialize().as_slice());
        expected_bytes.extend_from_slice(s2_val.serialize().as_slice());
        expected_bytes.extend_from_slice(s3_val.serialize().as_slice());
        assert_eq!(serialized_bytes.as_slice(), expected_bytes.as_slice());

        let deserialized_exponent_n_result = ExponentNTestType::deserialize(serialized_bytes);
        assert!(deserialized_exponent_n_result.is_ok());
        let deserialized_exponent_n = deserialized_exponent_n_result.unwrap();

        assert_eq!(exponent_n_val.0.0, deserialized_exponent_n.0.0);
    }
}
