use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;
use hybrid_array::typenum::{Unsigned, NonZero}; // For typenum constraints
use hybrid_array::ArraySize; // For ArraySize constraint

pub trait CryptoGroup {
    // ElementSerializedSize and ScalarSerializedSize are removed.
    // Size information will come from FSerializable/Size impls on Element and Scalar types.

    // GroupElement and GroupScalar will eventually have no size generic parameters.
    // For now, this change will cause errors as their definitions still expect them.
    // This is an intermediate step.
    type Element: GroupElement<Scalar = Self::Scalar>; // Assuming GroupElement will take Scalar's size, or no size.
                                                       // Let's assume GroupElement will only need its own Scalar type.
                                                       // The size of Element comes from its FSerializable<S> and Size<SizeType=S> impls.
                                                       // The size of Scalar comes from its FSerializable<S> and Size<SizeType=S> impls.
    type Scalar: GroupScalar; // Assuming GroupScalar will have no size generic parameter.

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
