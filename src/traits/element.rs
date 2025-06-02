use crate::serialization_hybrid::{FSerializable, Product, Size};
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use core::fmt::Debug;
use hybrid_array::ArraySize;

pub trait GroupElement: Size + Debug + Sized {
    type Scalar: GroupScalar;

    fn identity() -> Self;
    fn add_element(&self, other: &Self) -> Self;
    fn negate_element(&self) -> Self;
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;
}

type ElementN_<G, LenType> = Product<<G as CryptoGroup>::Element, LenType>;
type ElementNSize<G, LenType> = <Product<<G as CryptoGroup>::Element, LenType> as Size>::SizeType;

#[derive(Debug)]
pub struct ElementN<G, LenType>(pub ElementN_<G, LenType>)
where
    G: CryptoGroup,
    LenType: ArraySize,
    ElementN_<G, LenType>: Size;

impl<G, LenType> ElementN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    ElementN_<G, LenType>: Size,
{
    pub fn new(elements: ElementN_<G, LenType>) -> Self {
        ElementN(elements)
    }
}
impl<G, LenType> FSerializable<ElementNSize<G, LenType>>
    for ElementN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    ElementN_<G, LenType>: Size + FSerializable<ElementNSize<G, LenType>>,
{
    fn serialize(&self) -> hybrid_array::Array<u8, ElementNSize<G, LenType>> {
        self.0.serialize()
    }

    fn deserialize(
        buffer: hybrid_array::Array<u8, ElementNSize<G, LenType>>,
    ) -> Result<Self, crate::serialization_hybrid::Error> {
        Ok(ElementN(ElementN_::<G, LenType>::deserialize(
            buffer,
        )?))
    }
}