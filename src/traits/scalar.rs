use crate::serialization_hybrid::{FSerializable, Product, Size};
use crate::traits::group::CryptoGroup;
use core::ops::Mul as CoreMul;
use hybrid_array::typenum::Prod;
use hybrid_array::{Array, ArraySize};
use rand::RngCore;

pub trait GroupScalar: Sized {
    fn zero() -> Self;
    fn one() -> Self;
    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn negate(&self) -> Self;
    fn invert(&self) -> Option<Self>;
}

impl<S, LenType> GroupScalar for Product<S, LenType>
where
    S: GroupScalar,
    LenType: ArraySize,
{
    fn zero() -> Self {
        let array = Array::from_fn(|_| S::zero());
        Self(array)
    }
    fn one() -> Self {
        let array = Array::from_fn(|_| S::one());
        Self(array)
    }
    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let array = Array::from_fn(|_| S::random(rng));
        Self(array)
    }
    fn add(&self, other: &Self) -> Self {
        let pairs = self.0.iter().zip(other.0.iter());
        let result = pairs.map(|(a, b): (&S, &S)| a.add(&b));
        let result: Array<S, LenType> = result.collect();
        Self(result)
    }
    fn sub(&self, other: &Self) -> Self {
        let pairs = self.0.iter().zip(other.0.iter());
        let result = pairs.map(|(a, b): (&S, &S)| a.sub(&b));
        let result: Array<S, LenType> = result.collect();
        Self(result)
    }
    fn mul(&self, other: &Self) -> Self {
        let pairs = self.0.iter().zip(other.0.iter());
        let result = pairs.map(|(a, b): (&S, &S)| a.mul(&b));
        let result: Array<S, LenType> = result.collect();
        Self(result)
    }
    fn negate(&self) -> Self {
        let ret = self.0.iter().map(|s| s.negate()).collect();
        Self(ret)
    }
    fn invert(&self) -> Option<Self> {
        let ret: Option<Array<S, LenType>> = self.0.iter().map(|s| s.invert()).collect();
        ret.map(Self)
    }
}

pub type ExponentN_<G, LenType> = Product<<G as CryptoGroup>::Scalar, LenType>;
type ExponentNSize<G, LenType> = <Product<<G as CryptoGroup>::Scalar, LenType> as Size>::SizeType;

pub struct ExponentN<G, LenType>(pub ExponentN_<G, LenType>)
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
    pub fn new(elements: ExponentN_<G, LenType>) -> Self {
        ExponentN(elements)
    }
}

impl<G, LenType> FSerializable<ExponentNSize<G, LenType>> for ExponentN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    G::Scalar: Size + FSerializable<<G::Scalar as Size>::SizeType>,
    <G::Scalar as Size>::SizeType: CoreMul<LenType>,
    Prod<<G::Scalar as Size>::SizeType, LenType>: ArraySize,
{
    fn serialize(&self) -> hybrid_array::Array<u8, ExponentNSize<G, LenType>> {
        self.0.serialize()
    }

    fn deserialize(
        buffer: hybrid_array::Array<u8, ExponentNSize<G, LenType>>,
    ) -> Result<Self, crate::serialization_hybrid::Error> {
        Ok(ExponentN(ExponentN_::<G, LenType>::deserialize(buffer)?))
    }
}
