use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;
// No need for FSerializable or Size here directly, they are on Element/Scalar

pub trait CryptoGroup {
    const ELEMENT_SERIALIZED_SIZE: usize;
    const SCALAR_SERIALIZED_SIZE: usize;

    type Element: GroupElement<
            { Self::ELEMENT_SERIALIZED_SIZE },
            { Self::SCALAR_SERIALIZED_SIZE },
            Scalar = Self::Scalar,
        >
    where
        [(); Self::ELEMENT_SERIALIZED_SIZE]:,
        [(); Self::SCALAR_SERIALIZED_SIZE]:;
    type Scalar: GroupScalar<{ Self::SCALAR_SERIALIZED_SIZE }>
    where
        [(); Self::SCALAR_SERIALIZED_SIZE]:;
    // Consider adding: + FSerializable + Size + Clone + Debug + PartialEq to Element and Scalar bounds
    // if not already fully enforced by GroupElement/GroupScalar requiring them.
    // GroupElement and GroupScalar already require these, so it's inherited.

    /// Returns the standard generator for this cryptographic group.
    fn generator() -> Self::Element
    where
        [(); Self::ELEMENT_SERIALIZED_SIZE]:,
        [(); Self::SCALAR_SERIALIZED_SIZE]:;

    /// Hashes arbitrary byte slices into a scalar of this group.
    /// This method should encapsulate any group-specific domain separation
    /// or procedures for mapping hash output to a valid scalar.
    fn hash_to_scalar(input_slices: &[&[u8]]) -> Self::Scalar
    where
        [(); Self::SCALAR_SERIALIZED_SIZE]:;

    // Potential future additions, keeping minimal for now:
    // fn group_order_str() -> &'static str; // For informational purposes
    // fn security_level_bits() -> u16;
    // fn new_random_element<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Element;
    // fn new_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
    //     Self::Scalar::random(rng) // Default implementation
    // }
}
