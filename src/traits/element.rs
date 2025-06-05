use crate::serialization_hybrid::{FSerializable, Product, Size};
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use hybrid_array::Array;
use hybrid_array::ArraySize;

pub trait GroupElement: Sized {
    type Scalar: GroupScalar;

    fn identity() -> Self;
    fn add_element(&self, other: &Self) -> Self;
    fn negate_element(&self) -> Self;
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;
}

type ElementN_<G, LenType> = Product<<G as CryptoGroup>::Element, LenType>;

impl<E, LenType> GroupElement for Product<E, LenType>
where
    E: GroupElement,
    LenType: ArraySize,
{
    type Scalar = Product<E::Scalar, LenType>;

    fn identity() -> Self {
        let array = Array::from_fn(|_| E::identity());
        Self(array)
    }
    fn add_element(&self, other: &Self) -> Self {
        let pairs = self.0.iter().zip(other.0.iter());
        let result = pairs.map(|(a, b): (&E, &E)| a.add_element(&b));
        let result: Array<E, LenType> = result.collect();
        Self(result)
    }
    fn negate_element(&self) -> Self {
        let neg = self.0.iter().map(|e| e.negate_element());
        let neg = neg.collect();
        Self(neg)
    }

    fn scalar_mul(&self, other: &Self::Scalar) -> Self {
        let pairs = self.0.iter().zip(other.0.iter());
        let result = pairs.map(|(a, b): (&E, &E::Scalar)| a.scalar_mul(&b));
        let result: Array<E, LenType> = result.collect();
        Self(result)
    }
}

type ElementNSize<G, LenType> = <Product<<G as CryptoGroup>::Element, LenType> as Size>::SizeType;

pub struct ElementN<G, LenType>(pub ElementN_<G, LenType>)
where
    G: CryptoGroup,
    LenType: ArraySize;

impl<G, LenType> ElementN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
{
    pub fn new(elements: ElementN_<G, LenType>) -> Self {
        ElementN(elements)
    }
}
impl<G, LenType> FSerializable<ElementNSize<G, LenType>> for ElementN<G, LenType>
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
        Ok(ElementN(ElementN_::<G, LenType>::deserialize(buffer)?))
    }
}
