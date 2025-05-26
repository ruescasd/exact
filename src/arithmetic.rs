use curve25519_dalek::{Scalar, ristretto::{CompressedRistretto, RistrettoPoint}};
use crate::serialization::{Size, FSerializable, Product}; // Product is already here

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
    fn read_bytes(bytes: [u8; Exponent::SIZE]) -> Self {
        let scalar = Scalar::from_canonical_bytes(bytes).unwrap();
        Exponent::new(scalar)
    }
    fn write_bytes(&self) -> [u8; Exponent::SIZE] {
        self.0.to_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct Element(pub RistrettoPoint); // Element is defined in this file
impl Element {
    pub fn new(point: RistrettoPoint) -> Self {
        Element(point)
    }
}

impl Size for Element {
    const SIZE: usize = 32; // RistrettoPoint is 32 bytes
}

impl FSerializable<{ Element::SIZE }> for Element {
    fn read_bytes(bytes: [u8; Element::SIZE]) -> Self {
        let point = CompressedRistretto(bytes).decompress().unwrap();
        Element::new(point)
    }
    fn write_bytes(&self) -> [u8; Element::SIZE] {
        self.0.compress().to_bytes()
    }
}

// A product of Exponents
type ExponentN_<const LEN: usize> = Product<LEN, Exponent>;

#[derive(Debug)]
pub struct ExponentN<const LEN: usize>(pub ExponentN_<LEN>);

impl<const LEN: usize> ExponentN<LEN> {
    // No new method for now
}

impl<const LEN: usize> Size for ExponentN<LEN> {
    const SIZE: usize = ExponentN_::<LEN>::SIZE;
}

impl<const LEN: usize> FSerializable<{ Self::SIZE }> for ExponentN<LEN> 
where
    Product<LEN, Exponent>: FSerializable<{ Self::SIZE }>,
{
    fn read_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let product: Product<LEN, Exponent> = Product::read_bytes(bytes);
        ExponentN(product)
    }
    fn write_bytes(&self) -> [u8; Self::SIZE] {
        self.0.write_bytes()
    }
}

// === Appending ElementN definitions below ===

// A product of Elements
type ElementN_<const LEN: usize> = Product<LEN, Element>;

#[derive(Debug)]
pub struct ElementN<const LEN: usize>(pub ElementN_<LEN>); // Made pub

impl<const LEN: usize> ElementN<LEN> {
    pub fn new(list: [Element; LEN]) -> Self { // Made pub
        ElementN(Product(list))
    }
    // Note: encrypt method is NOT moved here
}

impl<const LEN: usize> Size for ElementN<LEN> {
    const SIZE: usize = ElementN_::<LEN>::SIZE;
}

impl<const LEN: usize> FSerializable<{ Self::SIZE }> for ElementN<LEN> 
where Product<LEN, Element>: FSerializable<{ Self::SIZE }> 
{
     fn read_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let list: Product<LEN, Element> = Product::read_bytes(bytes);
        ElementN(list)
    }
    fn write_bytes(&self) -> [u8; Self::SIZE] {
        self.0.write_bytes()
    }
}


#[cfg(test)]
mod tests {
    use super::*; // To access Element, Exponent, ExponentN, ElementN from arithmetic.rs
    use curve25519_dalek::{{Scalar, ristretto::RistrettoPoint}}; // For test setup for existing tests
    use rand; // For random generation in tests
    use std::array; // For std::array::from_fn

    #[test]
    fn test_element() {
        let scalar = Scalar::random(&mut rand::thread_rng());
        let point = RistrettoPoint::mul_base(&scalar);
        let element = Element::new(point);

        // Serialize and deserialize
        let bytes = element.write_bytes();
        let parsed_element = Element::read_bytes(bytes);

        // Check if the original and parsed elements are equal
        assert_eq!(element.0.compress(), parsed_element.0.compress());
    }

    #[test]
    fn test_exponent() {
        let scalar = Scalar::random(&mut rand::thread_rng());
        let exponent = Exponent::new(scalar);

        // Serialize and deserialize
        let bytes = exponent.write_bytes();
        let parsed_exponent = Exponent::read_bytes(bytes);

        // Check if the original and parsed exponents are equal
        assert_eq!(exponent.0, parsed_exponent.0);
    }

    #[test]
    fn test_exponent_n_serialization() {
        const LEN: usize = 3;
        let exponents_array: [Exponent; LEN] = std::array::from_fn(|_| {
            Exponent::new(Scalar::random(&mut rand::thread_rng()))
        });
        let exponents_n = ExponentN(Product(exponents_array.clone())); // Clone for later comparison

        let bytes = exponents_n.write_bytes();
        assert_eq!(bytes.len(), ExponentN::<LEN>::SIZE);

        let parsed_exponents_n = ExponentN::<LEN>::read_bytes(bytes);

        for i in 0..LEN {
            assert_eq!(exponents_n.0.0[i].0, parsed_exponents_n.0.0[i].0);
        }
    }
}
