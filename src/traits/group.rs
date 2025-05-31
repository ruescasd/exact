use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;

pub trait CryptoGroup {
    type Element: GroupElement<Scalar = Self::Scalar>;
    type Scalar: GroupScalar;

    fn generator() -> Self::Element;

    fn hash_to_scalar(input_slices: &[&[u8]]) -> Self::Scalar;
}
