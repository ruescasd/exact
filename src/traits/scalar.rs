use crate::serialization_hybrid::{FSerializable, Product, Size};
use crate::traits::group::CryptoGroup;
use core::fmt::Debug;
use core::ops::Mul as CoreMul;
use hybrid_array::ArraySize;
use hybrid_array::typenum::Prod;
use rand::RngCore;

pub trait GroupScalar: Size + Debug + Sized {
    fn zero() -> Self;
    fn one() -> Self;
    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn negate(&self) -> Self;
    fn invert(&self) -> Option<Self>;
}

type ExponentN_<G, LenType> = Product<<G as CryptoGroup>::Scalar, LenType>;
type ExponentNSize<G, LenType> = <Product<<G as CryptoGroup>::Scalar, LenType> as Size>::SizeType;

#[derive(Debug)]
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

impl<G, LenType> FSerializable<ExponentNSize<G, LenType>>
    for ExponentN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    G::Scalar: FSerializable<<G::Scalar as Size>::SizeType>,
    <G::Scalar as Size>::SizeType: CoreMul<LenType>,
    Prod<<G::Scalar as Size>::SizeType, LenType>: ArraySize,
{
    fn serialize(&self) -> hybrid_array::Array<u8, ExponentNSize<G, LenType>> {
        self.0.serialize()
    }

    fn deserialize(
        buffer: hybrid_array::Array<u8, ExponentNSize<G, LenType>>,
    ) -> Result<Self, crate::serialization_hybrid::Error> {
        Ok(ExponentN(ExponentN_::<G, LenType>::deserialize(
            buffer,
        )?))
    }
}