use crate::serialization::{FSerializable, Size};
use crate::traits::scalar::GroupScalar; // To use GroupScalar as a bound
use core::fmt::Debug; // For Debug trait

// Define an error type for operations if needed, or use Result/Option
// For now, FSerializable handles byte conversion errors implicitly via read_bytes

pub trait GroupElement:
    FSerializable + Size + Clone + Debug + PartialEq + Sized // Added Sized
{
    // Associated type for the scalar field of this group element
    type Scalar: GroupScalar;
    // type Error; // Consider defining a common error type later

    // Group operations
    fn identity() -> Self;
    fn add_element(&self, other: &Self) -> Self; // Name to avoid conflict with std::ops::Add if used later
    fn negate_element(&self) -> Self;           // Name to avoid conflict
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;

    // Basepoint multiplication could be a static method here if a "default" basepoint concept
    // is desired at this level, or it can be purely a CryptoGroup concern via generator().
    // fn mul_base(scalar: &Self::Scalar) -> Self; // Example if wanted here
}
