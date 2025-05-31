use crate::serialization::{FSerializable, Product, Size}; // Added Product
use crate::traits::group::CryptoGroup; // For G: CryptoGroup bound
use core::fmt::Debug; // For Debug trait
use rand::RngCore; // For random number generation

// Define an error type for operations like inversion if needed, or use Option
// For now, from_bytes might return a Result or Option, inversion will return Option

/// Represents a scalar in a cryptographic group.
///
/// A type implementing `GroupScalar<SCALAR_SIZE>` must also implement `Size`
/// such that `Size::SIZE` is equal to `SCALAR_SIZE`.
/// This redundancy is to work around limitations with associated consts in traits
/// when used as generic arguments for other traits (e.g., `FSerializable`).
pub trait GroupScalar<const SCALAR_SIZE: usize>:
    Size + FSerializable<SCALAR_SIZE> + Clone + Debug + PartialEq + Sized
where
    [(); SCALAR_SIZE]:,
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

#[derive(Debug)] // Removed Clone, PartialEq
pub struct ExponentN<G: CryptoGroup, const LEN: usize>(pub Product<LEN, G::Scalar>)
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:;
// Note: G::Scalar already requires FSerializable, Size, Clone, Debug, PartialEq via GroupScalar

impl<G: CryptoGroup, const LEN: usize> ExponentN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    /// Creates a new ExponentN from a Product of group scalars.
    pub fn new(product: Product<LEN, G::Scalar>) -> Self {
        ExponentN(product)
    }
    // Add other methods if ExponentN had them
    // pub fn inner(&self) -> &Product<LEN, G::Scalar> { &self.0 }
}

impl<G: CryptoGroup, const LEN: usize> Size for ExponentN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    const SIZE: usize = Product::<LEN, G::Scalar>::SIZE;
}

impl<G: CryptoGroup, const LEN: usize> FSerializable<{ G::SCALAR_SERIALIZED_SIZE * LEN }>
    for ExponentN<G, LEN>
where
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    Product<LEN, G::Scalar>: FSerializable<{ G::SCALAR_SERIALIZED_SIZE * LEN }>,
{
    fn read_bytes(bytes: [u8; G::SCALAR_SERIALIZED_SIZE * LEN]) -> Self {
        ExponentN(Product::<LEN, G::Scalar>::read_bytes(bytes))
    }

    fn write_bytes(&self) -> [u8; G::SCALAR_SERIALIZED_SIZE * LEN] {
        self.0.write_bytes()
    }
}
