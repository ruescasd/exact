use crate::serialization_hybrid::{Error as SerError, FSerializable, Size};
use crate::traits::scalar::GroupScalar;
use core::fmt::{Debug, Display};
// Removed: use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::ScalarPrimitive;
use p256::elliptic_curve::Field; // For Scalar::random
use p256::{Scalar, FieldBytes}; // p256 uses Scalar for its scalar type
use std::ops::Neg; // For self.0.neg()
use hybrid_array::typenum::U32; // P-256 scalars are 32 bytes
use hybrid_array::Array as HybridArray;
use rand::RngCore;
// p256's Scalar does not directly support from_hash like curve25519-dalek's Scalar.
// Hashing to a scalar would typically involve hashing to bytes and then converting those bytes to a scalar,
// possibly using Scalar::from_repr or similar, after ensuring the bytes represent a valid scalar value (e.g., by reduction modulo group order).
// For now, we'll omit a direct from_hash equivalent unless a clear and safe method is identified in p256.

#[derive(Clone, Copy)] // p256::Scalar is Copy
pub struct P256Scalar(pub Scalar);

impl P256Scalar {
    pub fn new(scalar: Scalar) -> Self {
        P256Scalar(scalar)
    }
    // from_hash might require a specific strategy for P-256, e.g. HKDF or custom mapping.
    // This is a placeholder if direct from_hash functionality is added.
    // pub fn from_hash<D: Digest<OutputSize = U32>>(hasher: D) -> Self { ... }
}

impl GroupScalar for P256Scalar {
    fn zero() -> Self {
        P256Scalar(Scalar::ZERO)
    }

    fn one() -> Self {
        P256Scalar(Scalar::ONE)
    }

    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        // p256::Scalar::random takes a R: RngCore + CryptoRng
        P256Scalar(Scalar::random(rng))
    }

    fn add(&self, other: &Self) -> Self {
        P256Scalar(self.0 + other.0)
    }

    fn sub(&self, other: &Self) -> Self {
        P256Scalar(self.0 - other.0)
    }

    fn mul(&self, other: &Self) -> Self {
        P256Scalar(self.0 * other.0)
    }

    fn negate(&self) -> Self {
        P256Scalar(self.0.neg())
    }

    fn invert(&self) -> Option<Self> {
        // p256::Scalar::invert returns a CtOption<Scalar>
        let inverted = self.0.invert();
        if inverted.is_some().unwrap_u8() == 1 {
            Some(P256Scalar(inverted.unwrap()))
        } else {
            None
        }
    }
}

// Implement Display and Debug traits
impl Display for P256Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0) // Basic debug representation
    }
}

impl Debug for P256Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("P256Scalar").field(&self.0).finish()
    }
}

// Implement PartialEq and Eq traits
impl PartialEq for P256Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for P256Scalar {}

// Serialization
impl Size for P256Scalar {
    type SizeType = U32; // P-256 scalars are 32 bytes
}

impl FSerializable<U32> for P256Scalar {
    fn serialize(&self) -> HybridArray<u8, U32> {
        HybridArray::try_from(self.0.to_bytes().as_slice()).expect("Scalar to_bytes is always U32")
    }

    fn deserialize(buffer: HybridArray<u8, U32>) -> Result<Self, SerError> {
        // Scalar::from_repr takes FieldBytes which is GenericArray<u8, Self::ScalarSize>
        // U32 is the ScalarSize for P256
        let field_bytes = FieldBytes::from_slice(buffer.as_slice());
        let scalar_primitive = ScalarPrimitive::from_bytes(field_bytes); //scalar_primitive is CtOption<ScalarPrimitive<Self>>

        if scalar_primitive.is_some().unwrap_u8() == 1 {
             Ok(P256Scalar(scalar_primitive.unwrap().into()))
        } else {
            Err(SerError::DeserializationError)
        }
    }
}

impl Default for P256Scalar {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization_hybrid::FSerializable;
    use crate::utils::rng; 
    use hybrid_array::typenum::{Unsigned, U32};

    #[test]
    fn test_p256_scalar_hybrid_serialization() {
        let mut rng = rng::DefaultRng; // Assuming DefaultRng is compatible
        let scalar = P256Scalar::random(&mut rng);

        // Serialize
        let serialized_data = scalar.serialize();
        assert_eq!(
            serialized_data.as_slice().len(),
            U32::USIZE,
            "Serialized length mismatch"
        );

        // Deserialize
        let deserialized_scalar =
            P256Scalar::deserialize(serialized_data).expect("Deserialization failed");

        assert_eq!(
            scalar, deserialized_scalar,
            "Original and deserialized scalars do not match"
        );

        // Test zero
        let zero_scalar = P256Scalar::zero();
        let serialized_zero = zero_scalar.serialize();
        assert_eq!(serialized_zero.as_slice().len(), U32::USIZE);
        let deserialized_zero =
            P256Scalar::deserialize(serialized_zero).expect("Deserialization failed");
        assert_eq!(zero_scalar, deserialized_zero);

        // Test one
        let one_scalar = P256Scalar::one();
        let serialized_one = one_scalar.serialize();
        assert_eq!(serialized_one.as_slice().len(), U32::USIZE);
        let deserialized_one =
            P256Scalar::deserialize(serialized_one).expect("Deserialization failed");
        assert_eq!(one_scalar, deserialized_one);
    }
}
