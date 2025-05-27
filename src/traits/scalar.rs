use crate::serialization::{FSerializable, Size, Product}; // Added Product
use crate::traits::group::CryptoGroup; // For G: CryptoGroup bound
use core::fmt::Debug; // For Debug trait
use rand::RngCore; // For random number generation

// Define an error type for operations like inversion if needed, or use Option
// For now, from_bytes might return a Result or Option, inversion will return Option

pub trait GroupScalar:
    Size + FSerializable<{Self::SIZE}> + Clone + Debug + PartialEq + Sized // Moved Size first, updated FSerializable
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

// --- Generic ExponentN struct and implementations ---

#[derive(Debug, Clone, PartialEq)] // Assuming G::Scalar is PartialEq
pub struct ExponentN<G: CryptoGroup, const LEN: usize>(pub Product<LEN, G::Scalar>);
// Note: G::Scalar already requires FSerializable, Size, Clone, Debug, PartialEq via GroupScalar

impl<G: CryptoGroup, const LEN: usize> ExponentN<G, LEN> {
    /// Creates a new ExponentN from a Product of group scalars.
    pub fn new(product: Product<LEN, G::Scalar>) -> Self {
        ExponentN(product)
    }
    // Add other methods if ExponentN had them
    // pub fn inner(&self) -> &Product<LEN, G::Scalar> { &self.0 }
}

impl<G: CryptoGroup, const LEN: usize> Size for ExponentN<G, LEN> {
    const SIZE: usize = Product::<LEN, G::Scalar>::SIZE;
}

impl<G: CryptoGroup, const LEN: usize> FSerializable<{Self::SIZE}> for ExponentN<G, LEN> {
    fn read_bytes(bytes: [u8; Self::SIZE]) -> Self {
        ExponentN(Product::<LEN, G::Scalar>::read_bytes(bytes))
    }

    fn write_bytes(&self) -> [u8; Self::SIZE] {
        self.0.write_bytes()
    }
}
