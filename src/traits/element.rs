use crate::serialization::{FSerializable, Size, Product}; // Added Product
use crate::traits::scalar::GroupScalar; // To use GroupScalar as a bound
use crate::traits::group::CryptoGroup; // For G: CryptoGroup bound
use core::fmt::Debug; // For Debug trait

// Define an error type for operations if needed, or use Result/Option
// For now, FSerializable handles byte conversion errors implicitly via read_bytes

pub trait GroupElement:
    Size + FSerializable<{Self::SIZE}> + Clone + Debug + PartialEq + Sized // Moved Size first, updated FSerializable
    where [(); Self::SIZE]: // Removed braces around Self::SIZE
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

// --- Generic ElementN struct and implementations ---

#[derive(Debug)] // Removed Clone, PartialEq
pub struct ElementN<G: CryptoGroup, const LEN: usize>(pub Product<LEN, G::Element>);
// Note: G::Element already requires FSerializable, Size, Clone, Debug, PartialEq via GroupElement

impl<G: CryptoGroup, const LEN: usize> ElementN<G, LEN> {
    /// Creates a new ElementN from a Product of group elements.
    pub fn new(product: Product<LEN, G::Element>) -> Self {
        ElementN(product)
    }
    // Add other methods if ElementN had them, e.g., for accessing the inner Product directly
    // pub fn inner(&self) -> &Product<LEN, G::Element> { &self.0 }
}

impl<G: CryptoGroup, const LEN: usize> Size for ElementN<G, LEN> {
    const SIZE: usize = Product::<LEN, G::Element>::SIZE;
}

impl<G: CryptoGroup, const LEN: usize> FSerializable<{Self::SIZE}> for ElementN<G, LEN> {
    fn read_bytes(bytes: [u8; Self::SIZE]) -> Self {
        ElementN(Product::<LEN, G::Element>::read_bytes(bytes))
    }

    fn write_bytes(&self) -> [u8; Self::SIZE] {
        self.0.write_bytes()
    }
}
