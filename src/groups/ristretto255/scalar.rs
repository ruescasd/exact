use crate::serialization_hybrid::{Error as SerError, FSerializable, Size};
use crate::traits::scalar::GroupScalar;
use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use hybrid_array::typenum::U32;
use hybrid_array::Array as HybridArray;
use rand::RngCore;
use sha3::digest::Digest;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RistrettoScalar(pub DalekScalar);

impl RistrettoScalar {
    /// Creates a new RistrettoScalar from a dalek Scalar.
    pub fn new(scalar: DalekScalar) -> Self {
        RistrettoScalar(scalar)
    }

    /// Exposes the from_hash method from the underlying Dalek Scalar type.
    /// Requires the 'digest' feature for curve25519-dalek.
    pub fn from_hash<D: Digest<OutputSize = U64>>(hasher: D) -> Self {
        RistrettoScalar(DalekScalar::from_hash::<D>(hasher))
    }

    // Add any other specific methods from the old Exponent struct if they are relevant
    // and not covered by GroupScalar trait. For now, new() and from_hash() are key.
}

// GroupScalar trait is now parameter-less for size.
// The methods add, sub, mul, negate are now supertraits.
impl GroupScalar for RistrettoScalar {
    fn zero() -> Self {
        RistrettoScalar(DalekScalar::ZERO)
    }

    fn one() -> Self {
        RistrettoScalar(DalekScalar::ONE)
    }

    fn random<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        RistrettoScalar(DalekScalar::random(rng))
    }

    fn add(&self, other: &Self) -> Self {
        RistrettoScalar(self.0 + other.0)
    }

    fn sub(&self, other: &Self) -> Self {
        RistrettoScalar(self.0 - other.0)
    }

    fn mul(&self, other: &Self) -> Self {
        RistrettoScalar(self.0 * other.0)
    }

    fn negate(&self) -> Self {
        RistrettoScalar(-self.0)
    }

    fn invert(&self) -> Option<Self> {
        if self.0 == DalekScalar::ZERO {
            None
        } else {
            Some(RistrettoScalar(self.0.invert()))
        }
    }
}

impl Size for RistrettoScalar {
    type SizeType = U32;
}

impl FSerializable<U32> for RistrettoScalar {
    fn serialize(&self) -> HybridArray<u8, U32> {
        HybridArray::from(self.0.to_bytes())
    }

    fn deserialize(buffer: HybridArray<u8, U32>) -> Result<Self, SerError> {
        // DalekScalar::from_canonical_bytes returns CtOption<DalekScalar>
        // Convert CtOption to Option, then to Result<RistrettoScalar, SerError>
        match DalekScalar::from_canonical_bytes(buffer.0).into() {
            // Use .0 and .into()
            Some(s) => Ok(RistrettoScalar(s)),
            None => Err(SerError::DeserializationError),
        }
    }
}

// Add Default implementation if not already present and needed by GroupScalar or other uses.
// DalekScalar::ZERO can be used for a default.
impl Default for RistrettoScalar {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*; // RistrettoScalar
    use crate::serialization_hybrid::FSerializable;
    use crate::utils::rng;
    use hybrid_array::typenum::{Unsigned, U32}; // Added Unsigned

    #[test]
    fn test_ristretto_scalar_hybrid_serialization() {
        let mut rng = rng::DefaultRng;
        let scalar = RistrettoScalar::random(&mut rng); // Test with a random scalar

        // Serialize
        let serialized_data = scalar.serialize();
        assert_eq!(
            serialized_data.as_slice().len(),
            U32::USIZE,
            "Serialized length mismatch"
        );

        // Deserialize
        let deserialized_scalar =
            RistrettoScalar::deserialize(serialized_data).expect("Deserialization failed");

        assert_eq!(
            scalar, deserialized_scalar,
            "Original and deserialized scalars do not match"
        );

        // Test zero
        let zero_scalar = RistrettoScalar::zero();
        let serialized_zero = zero_scalar.serialize();
        assert_eq!(serialized_zero.as_slice().len(), U32::USIZE);
        let deserialized_zero =
            RistrettoScalar::deserialize(serialized_zero).expect("Deserialization failed");
        assert_eq!(zero_scalar, deserialized_zero);

        // Test one
        let one_scalar = RistrettoScalar::one();
        let serialized_one = one_scalar.serialize();
        assert_eq!(serialized_one.as_slice().len(), U32::USIZE);
        let deserialized_one =
            RistrettoScalar::deserialize(serialized_one).expect("Deserialization failed");
        assert_eq!(one_scalar, deserialized_one);
    }
}
