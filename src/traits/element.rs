use crate::serialization::{FSerializable, Product, Size}; // Added Product
use crate::traits::group::CryptoGroup; // For G: CryptoGroup bound
use crate::traits::scalar::GroupScalar; // To use GroupScalar as a bound
use core::fmt::Debug; // For Debug trait

// Define an error type for operations if needed, or use Result/Option
// For now, FSerializable handles byte conversion errors implicitly via read_bytes

/// Represents an element in a cryptographic group.
///
/// A type implementing `GroupElement<ELEMENT_SIZE, SCALAR_SIZE>` must also implement `Size`
/// such that `Size::SIZE` is equal to `ELEMENT_SIZE`.
/// This redundancy is to work around limitations with associated consts in traits
/// when used as generic arguments for other traits (e.g., `FSerializable`).
pub trait GroupElement<const ELEMENT_SIZE: usize, const SCALAR_SIZE: usize>:
    Size + FSerializable<ELEMENT_SIZE> + Clone + Debug + PartialEq + Sized
where
    [(); ELEMENT_SIZE]:,
{
    // Associated type for the scalar field of this group element
    type Scalar: GroupScalar<SCALAR_SIZE>;
    // type Error; // Consider defining a common error type later

    // Group operations
    fn identity() -> Self;
    fn add_element(&self, other: &Self) -> Self; // Name to avoid conflict with std::ops::Add if used later
    fn negate_element(&self) -> Self; // Name to avoid conflict
    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self;

    // Basepoint multiplication could be a static method here if a "default" basepoint concept
    // is desired at this level, or it can be purely a CryptoGroup concern via generator().
    // fn mul_base(scalar: &Self::Scalar) -> Self; // Example if wanted here
}

// --- Generic ElementN struct and implementations ---

#[derive(Debug)] // Removed Clone, PartialEq
pub struct ElementN<G: CryptoGroup, const LEN: usize>(pub Product<LEN, G::Element>)
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:;
// Note: G::Element already requires FSerializable, Size, Clone, Debug, PartialEq via GroupElement

impl<G: CryptoGroup, const LEN: usize> ElementN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    /// Creates a new ElementN from a Product of group elements.
    pub fn new(product: Product<LEN, G::Element>) -> Self {
        ElementN(product)
    }
    // Add other methods if ElementN had them, e.g., for accessing the inner Product directly
    // pub fn inner(&self) -> &Product<LEN, G::Element> { &self.0 }
}

impl<G: CryptoGroup, const LEN: usize> Size for ElementN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    const SIZE: usize = Product::<LEN, G::Element>::SIZE;
}

impl<G: CryptoGroup, const LEN: usize> FSerializable<{ G::ELEMENT_SERIALIZED_SIZE * LEN }>
    for ElementN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    Product<LEN, G::Element>: FSerializable<{ G::ELEMENT_SERIALIZED_SIZE * LEN }>,
{
    fn read_bytes(bytes: [u8; G::ELEMENT_SERIALIZED_SIZE * LEN]) -> Self {
        ElementN(Product::<LEN, G::Element>::read_bytes(bytes))
    }

    fn write_bytes(&self) -> [u8; G::ELEMENT_SERIALIZED_SIZE * LEN] {
        self.0.write_bytes()
    }
}
