use crate::groups::ristretto255::scalar::RistrettoScalar; // Path to our new RistrettoScalar
use crate::serialization::{FSerializable, Size};
use crate::traits::element::GroupElement;
use core::fmt::Debug;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity; // Already in scope usually, but good to be explicit if needed

#[derive(Clone, Debug, PartialEq)] // Added PartialEq
pub struct RistrettoElement(pub RistrettoPoint); // Renamed Element to RistrettoElement

impl RistrettoElement {
    /// Creates a new RistrettoElement from a dalek RistrettoPoint.
    pub fn new(point: RistrettoPoint) -> Self {
        RistrettoElement(point)
    }
    // Add any other specific methods from the old Element struct if they are relevant
    // and not covered by GroupElement trait.
}

impl GroupElement<{ Self::SIZE }, { RistrettoScalar::SIZE }> for RistrettoElement {
    type Scalar = RistrettoScalar;

    fn identity() -> Self {
        RistrettoElement(RistrettoPoint::identity()) // RistrettoPoint::default() is identity
    }

    fn add_element(&self, other: &Self) -> Self {
        RistrettoElement(self.0 + other.0)
    }

    fn negate_element(&self) -> Self {
        RistrettoElement(-self.0)
    }

    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self {
        RistrettoElement(self.0 * scalar.0) // scalar.0 to access inner DalekScalar
    }
}

impl Size for RistrettoElement {
    const SIZE: usize = 32; // CompressedRistretto is 32 bytes
}

impl FSerializable<32> for RistrettoElement {
    fn read_bytes(bytes: [u8; 32]) -> Self {
        // Changed Self::SIZE to 32
        // Old Element::parse used CompressedRistretto(bytes).decompress().unwrap()
        // This can panic if bytes are not a valid point.
        // Consider returning Result if robust error handling is added later.
        match CompressedRistretto(bytes).decompress() {
            Some(point) => RistrettoElement(point),
            None => panic!("Failed to decompress RistrettoElement from bytes"), // Or return Result
        }
    }

    fn write_bytes(&self) -> [u8; 32] {
        // Changed Self::SIZE to 32
        self.0.compress().to_bytes()
    }
}
