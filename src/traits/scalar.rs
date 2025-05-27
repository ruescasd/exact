use crate::serialization::{FSerializable, Size};
use core::fmt::Debug; // For Debug trait
use rand::RngCore; // For random number generation

// Define an error type for operations like inversion if needed, or use Option
// For now, from_bytes might return a Result or Option, inversion will return Option

pub trait GroupScalar:
    FSerializable + Size + Clone + Debug + PartialEq + Sized // Added Sized for Self in return types
{
    // Error type for operations that can fail, e.g. from_bytes
    // type Error; // Consider defining a common error type later

    // Constants
    fn zero() -> Self;
    fn one() -> Self;

    // Random generation
    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self; // Ensure CryptoRng for security

    // Arithmetic operations
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn negate(&self) -> Self;
    fn invert(&self) -> Option<Self>; // Inversion might fail (e.g., for zero)

    // from_hash method will be specific to the concrete type (e.g. RistrettoScalar)
    // but could be part of a CryptoGroup trait's requirements for its associated Scalar type
    // or a method here if it's truly generic (e.g. from_bytes_mod_order_wide).
    // For now, stick to FSerializable for byte conversions.
}
