use crate::groups::ristretto255::scalar::RistrettoScalar;
use crate::serialization_hybrid::{Error as SerError, FSerializable, Size}; // Updated imports
use crate::traits::element::GroupElement;
use core::fmt::Debug;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use hybrid_array::typenum::U32;
use hybrid_array::Array as HybridArray; // Using U32 for size // Using HybridArray

#[derive(Clone, Debug, PartialEq, Eq)] // Added Eq
pub struct RistrettoElement(pub RistrettoPoint);

impl RistrettoElement {
    /// Creates a new RistrettoElement from a dalek RistrettoPoint.
    pub fn new(point: RistrettoPoint) -> Self {
        RistrettoElement(point)
    }
    // Add any other specific methods from the old Element struct if they are relevant
    // and not covered by GroupElement trait.
}

// GroupElement trait is now parameter-less for sizes.
impl GroupElement for RistrettoElement {
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
        RistrettoElement(self.0 * scalar.0)
    }
}

// Implement std::ops traits required by GroupElement supertraits
impl std::ops::Add for RistrettoElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        RistrettoElement(self.0 + rhs.0)
    }
}

impl<'a, 'b> std::ops::Add<&'b RistrettoElement> for &'a RistrettoElement {
    type Output = RistrettoElement;
    fn add(self, rhs: &'b RistrettoElement) -> Self::Output {
        RistrettoElement(self.0 + rhs.0)
    }
}

impl std::ops::Sub for RistrettoElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        RistrettoElement(self.0 - rhs.0)
    }
}

impl<'a, 'b> std::ops::Sub<&'b RistrettoElement> for &'a RistrettoElement {
    type Output = RistrettoElement;
    fn sub(self, rhs: &'b RistrettoElement) -> Self::Output {
        RistrettoElement(self.0 - rhs.0)
    }
}

impl std::ops::Neg for RistrettoElement {
    type Output = Self;
    fn neg(self) -> Self::Output {
        RistrettoElement(-self.0)
    }
}

impl<'a> std::ops::Neg for &'a RistrettoElement {
    type Output = RistrettoElement;
    fn neg(self) -> Self::Output {
        RistrettoElement(-self.0)
    }
}

impl Size for RistrettoElement {
    type SizeType = U32;
}

impl FSerializable<U32> for RistrettoElement {
    fn serialize(&self) -> HybridArray<u8, U32> {
        HybridArray::from(self.0.compress().to_bytes())
    }

    fn deserialize(buffer: HybridArray<u8, U32>) -> Result<Self, SerError> {
        // buffer.0 gives the inner [u8; N] array
        match CompressedRistretto(buffer.0).decompress() {
            Some(point) => Ok(RistrettoElement(point)),
            None => Err(SerError::DeserializationError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*; // RistrettoElement
    use crate::serialization_hybrid::FSerializable;
    use crate::traits::scalar::GroupScalar;
    use hybrid_array::typenum::{Unsigned, U32}; // Added Unsigned // Added GroupScalar for ::one()
                                                // RistrettoElement::identity() and other methods can be used to get instances.

    #[test]
    fn test_ristretto_element_hybrid_serialization() {
        let element = RistrettoElement::identity();

        // Serialize
        let serialized_data = element.serialize();
        assert_eq!(
            serialized_data.as_slice().len(),
            U32::USIZE,
            "Serialized length mismatch"
        );

        // Deserialize
        let deserialized_element =
            RistrettoElement::deserialize(serialized_data).expect("Deserialization failed");

        assert_eq!(
            element, deserialized_element,
            "Original and deserialized elements do not match"
        );

        let scalar_one = RistrettoScalar::one();
        let another_element = element.scalar_mul(&scalar_one);

        let serialized_another = another_element.serialize();
        assert_eq!(serialized_another.len(), U32::USIZE);

        let deserialized_another =
            RistrettoElement::deserialize(serialized_another).expect("Deserialization failed");
        assert_eq!(another_element, deserialized_another);
        assert_eq!(element, another_element);
    }
}
