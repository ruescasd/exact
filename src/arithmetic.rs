use curve25519_dalek::{Scalar, ristretto::{CompressedRistretto, RistrettoPoint}};
use crate::serialization::{Size, FSerializable};

#[derive(Debug, Clone)]
pub struct Exponent(pub Scalar);
impl Exponent {
    pub fn new(scalar: Scalar) -> Self {
        Exponent(scalar)
    }
}
impl Size for Exponent {
    const SIZE: usize = 32; // Scalar is 32 bytes
}
impl FSerializable<{ Exponent::SIZE }> for Exponent {
    fn parse(bytes: [u8; Exponent::SIZE]) -> Self {
        let scalar = Scalar::from_canonical_bytes(bytes).unwrap();
        Exponent::new(scalar)
    }
    fn write(&self) -> [u8; Exponent::SIZE] {
        self.0.to_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct Element(pub RistrettoPoint);
impl Element {
    pub fn new(point: RistrettoPoint) -> Self {
        Element(point)
    }
}

impl Size for Element {
    const SIZE: usize = 32; // RistrettoPoint is 32 bytes
}

impl FSerializable<{ Element::SIZE }> for Element {
    fn parse(bytes: [u8; Element::SIZE]) -> Self {
        let point = CompressedRistretto(bytes).decompress().unwrap();
        Element::new(point)
    }
    fn write(&self) -> [u8; Element::SIZE] {
        self.0.compress().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*; // To access Element, Exponent from arithmetic.rs
    use curve25519_dalek::{{Scalar, ristretto::RistrettoPoint}}; // For test setup
    use rand; // For random generation in tests

    #[test]
    fn test_element() {
        let scalar = Scalar::random(&mut rand::thread_rng());
        let point = RistrettoPoint::mul_base(&scalar);
        let element = Element::new(point);

        // Serialize and deserialize
        let bytes = element.write();
        let parsed_element = Element::parse(bytes);

        // Check if the original and parsed elements are equal
        assert_eq!(element.0.compress(), parsed_element.0.compress());
    }

    #[test]
    fn test_exponent() {
        let scalar = Scalar::random(&mut rand::thread_rng());
        let exponent = Exponent::new(scalar);

        // Serialize and deserialize
        let bytes = exponent.write();
        let parsed_exponent = Exponent::parse(bytes);

        // Check if the original and parsed exponents are equal
        assert_eq!(exponent.0, parsed_exponent.0);
    }
}
