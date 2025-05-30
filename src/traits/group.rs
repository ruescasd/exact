use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;
use hybrid_array::typenum::{Unsigned, NonZero}; // For typenum constraints
use hybrid_array::ArraySize; // For ArraySize constraint

pub trait CryptoGroup {
    // Changed from const usize to associated types
    type ElementSerializedSize: Unsigned + NonZero + ArraySize;
    type ScalarSerializedSize: Unsigned + NonZero + ArraySize;

    // The generic arguments for GroupElement and GroupScalar will change
    // from const usize to type parameters (typenum types).
    // This will require updating GroupElement and GroupScalar trait definitions later.
    // For now, this will likely cause errors, which is expected for this step.
    type Element: GroupElement<Self::ElementSerializedSize, Self::ScalarSerializedSize, Scalar = Self::Scalar>;
    type Scalar: GroupScalar<Self::ScalarSerializedSize>;
    // Where clauses like `[(); Self::ELEMENT_SERIALIZED_SIZE]:,` are no longer needed here
    // as ArraySize on the associated types implies usability.

    /// Returns the standard generator for this cryptographic group.
    fn generator() -> Self::Element;
    // Where clauses for generator's associated types are implicitly handled by ArraySize on Element/Scalar associated types.

    /// Hashes arbitrary byte slices into a scalar of this group.
    /// This method should encapsulate any group-specific domain separation
    /// or procedures for mapping hash output to a valid scalar.
    fn hash_to_scalar(input_slices: &[&[u8]]) -> Self::Scalar;
    // Where clause for Scalar's associated type is implicitly handled by ArraySize.

    // Potential future additions, keeping minimal for now:
    // fn group_order_str() -> &'static str; // For informational purposes
    // fn security_level_bits() -> u16;
    // fn new_random_element<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Element;
    // fn new_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
    //     Self::Scalar::random(rng) // Default implementation
    // }
}
