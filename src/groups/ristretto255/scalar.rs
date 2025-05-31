use crate::serialization::{FSerializable, Size};
use crate::traits::scalar::GroupScalar;
use curve25519_dalek::digest::generic_array::typenum::U64; // Added import
use curve25519_dalek::scalar::Scalar as DalekScalar;
use rand::RngCore;
use sha3::digest::Digest; // Changed path // For random generation

#[derive(Clone, Debug, PartialEq)] // Added PartialEq
pub struct RistrettoScalar(pub DalekScalar); // Renamed Exponent to RistrettoScalar

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

impl GroupScalar<{ Self::SIZE }> for RistrettoScalar {
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
        // Dalek Scalar invert returns the original scalar if it's zero,
        // which is not what we want for an Option. It should be None for zero.
        if self.0 == DalekScalar::ZERO {
            None
        } else {
            Some(RistrettoScalar(self.0.invert()))
        }
    }
}

impl Size for RistrettoScalar {
    const SIZE: usize = 32; // Dalek Scalar is 32 bytes
}

impl FSerializable<32> for RistrettoScalar {
    fn read_bytes(bytes: [u8; 32]) -> Self {
        // Changed Self::SIZE to 32
        // The old Exponent::parse used Scalar::from_canonical_bytes(bytes).unwrap()
        // This is a good place to ensure robust error handling if from_canonical_bytes can fail.
        // For now, maintaining unwrap to match, but this could be a point of refinement.
        match DalekScalar::from_canonical_bytes(bytes).into() {
            Some(s) => RistrettoScalar(s),
            None => panic!("Failed to parse RistrettoScalar from canonical bytes"), // Or return Result
        }
    }

    fn write_bytes(&self) -> [u8; 32] {
        // Changed Self::SIZE to 32
        self.0.to_bytes()
    }
}
