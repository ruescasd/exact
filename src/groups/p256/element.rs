use crate::groups::p256::scalar::P256Scalar;
use crate::serialization_hybrid::{Error as SerError, FSerializable, Size};
use crate::traits::element::GroupElement;
use core::fmt::{Debug, Display};
use hybrid_array::typenum::U33; // P-256 compressed points are 33 bytes (1 byte for sign + 32 for X coordinate)
use hybrid_array::Array as HybridArray;
use p256::elliptic_curve::group::Group; // For is_identity()
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, ProjectivePoint}; // Removed PublicKey

#[derive(Clone, Copy)] // Added Copy as ProjectivePoint is Copy
pub struct P256Element(pub ProjectivePoint);

impl P256Element {
    pub fn new(point: ProjectivePoint) -> Self {
        P256Element(point)
    }
}

impl GroupElement for P256Element {
    type Scalar = P256Scalar;

    fn identity() -> Self {
        P256Element(ProjectivePoint::IDENTITY)
    }

    fn add_element(&self, other: &Self) -> Self {
        P256Element(self.0 + other.0)
    }

    fn negate_element(&self) -> Self {
        P256Element(-self.0)
    }

    fn scalar_mul(&self, scalar: &Self::Scalar) -> Self {
        P256Element(self.0 * scalar.0)
    }

    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Implement Display and Debug traits
impl Display for P256Element {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0) // Basic debug representation for display
    }
}

impl Debug for P256Element {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("P256Element").field(&self.0).finish()
    }
}

// Implement PartialEq and Eq traits
impl PartialEq for P256Element {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for P256Element {}

// Serialization
impl Size for P256Element {
    type SizeType = U33; // Compressed P-256 points are 33 bytes
}

impl FSerializable<U33> for P256Element {
    fn serialize(&self) -> HybridArray<u8, U33> {
        if self.0.is_identity().into() {
            // Return all zeros for identity to fit U33.
            HybridArray::<u8, U33>::default()
        } else {
            let encoded_point = self.0.to_affine().to_encoded_point(true);
            let bytes = encoded_point.as_bytes();
            // This check is important for non-identity points.
            if bytes.len() != <U33 as typenum::Unsigned>::USIZE {
                panic!(
                    "Non-identity P256Element serialized to unexpected length: got {}, expected {}",
                    bytes.len(),
                    <U33 as typenum::Unsigned>::USIZE
                );
            }
            HybridArray::try_from(bytes).expect("Slice length previously checked")
        }
    }

    fn deserialize(buffer: HybridArray<u8, U33>) -> Result<Self, SerError> {
        // Check for our custom all-zero identity representation
        let mut is_custom_identity = true;
        for &byte in buffer.iter() {
            if byte != 0 {
                is_custom_identity = false;
                break;
            }
        }
        if is_custom_identity {
            return Ok(P256Element(ProjectivePoint::IDENTITY));
        }

        // Otherwise, proceed with standard deserialization
        // Standard SEC1 compressed points (0x02, 0x03) should not be all zeros.
        // A single 0x00 byte is identity, but that would not match U33.
        let encoded_point = EncodedPoint::from_bytes(buffer.as_slice())
            .map_err(|_| SerError::DeserializationError)?;

        let point_option: Option<ProjectivePoint> =
            ProjectivePoint::from_encoded_point(&encoded_point).into();
        if let Some(point) = point_option {
            // Additional check: if standard deserialization of a non-all-zero buffer results in identity,
            // it might indicate an issue if our custom identity (all-zero) was expected for some reason.
            // However, valid compressed points should not be all zeros.
            if is_custom_identity == false && point.is_identity().into() {
                // This case should ideally not happen if a non-all-zero buffer decodes to identity.
                // It implies the buffer might have been, e.g. a single 0x00 byte padded to U33,
                // which our current deserialize logic doesn't explicitly create for identity.
                // For now, we accept what from_encoded_point gives.
            }
            Ok(P256Element(point))
        } else {
            Err(SerError::DeserializationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization_hybrid::FSerializable;
    use crate::traits::scalar::GroupScalar; // For P256Scalar::one()
    use hybrid_array::typenum::{Unsigned, U33};

    #[test]
    fn test_p256_element_hybrid_serialization() {
        let element = P256Element::identity();

        // Serialize
        let serialized_data = element.serialize();
        assert_eq!(
            serialized_data.as_slice().len(),
            U33::USIZE,
            "Serialized length mismatch"
        );

        // Deserialize
        let deserialized_element =
            P256Element::deserialize(serialized_data).expect("Deserialization failed");

        assert_eq!(
            element, deserialized_element,
            "Original and deserialized elements do not match"
        );

        // Test with a non-identity element (e.g., generator * scalar)
        // Requires P256Scalar::one() or a random scalar
        let scalar_one = P256Scalar::one(); // Assuming P256Scalar and ::one() are implemented
        let generator = P256Element(ProjectivePoint::GENERATOR); // Assuming GENERATOR is accessible
        let another_element = generator.scalar_mul(&scalar_one);

        let serialized_another = another_element.serialize();
        assert_eq!(serialized_another.len(), U33::USIZE);

        let deserialized_another =
            P256Element::deserialize(serialized_another).expect("Deserialization failed");
        assert_eq!(another_element, deserialized_another);
    }
}
