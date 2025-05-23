use crate::size::{Pair, Parseable, Size};
use curve25519_dalek::{
    Scalar,
    ristretto::{CompressedRistretto, RistrettoPoint},
};

#[derive(Debug, Clone)]
struct Exponent(Scalar);
impl Exponent {
    fn new(scalar: Scalar) -> Self {
        Exponent(scalar)
    }
}
impl Size for Exponent {
    const SIZE: usize = 32; // Scalar is 32 bytes
}
impl Parseable<{ Exponent::SIZE }> for Exponent {
    fn parse(bytes: [u8; Exponent::SIZE]) -> Self {
        let scalar = Scalar::from_canonical_bytes(bytes).unwrap();
        Exponent::new(scalar)
    }
    fn write(&self) -> [u8; Exponent::SIZE] {
        self.0.to_bytes()
    }
}

#[derive(Debug, Clone)]
struct Element(RistrettoPoint);
impl Element {
    fn new(point: RistrettoPoint) -> Self {
        Element(point)
    }
}

impl Size for Element {
    const SIZE: usize = 32; // RistrettoPoint is 32 bytes
}

impl Parseable<{ Element::SIZE }> for Element {
    fn parse(bytes: [u8; Element::SIZE]) -> Self {
        let point = CompressedRistretto(bytes).decompress().unwrap();
        Element::new(point)
    }
    fn write(&self) -> [u8; Element::SIZE] {
        self.0.compress().to_bytes()
    }
}

struct ElGamal(Pair<Element, Element>);
impl ElGamal {
    fn new(a: Element, b: Element) -> Self {
        ElGamal(Pair { a, b })
    }

    fn parse(bytes: [u8; 64]) -> Self {
        let pair = Pair::parse(bytes);
        ElGamal(pair)
    }

    fn write(&self) -> [u8; 64] {
        self.0.write()
    }

    fn gr(&self) -> Element {
        self.0.a.clone()
    }

    fn mhr(&self) -> Element {
        self.0.b.clone()
    }
}

struct KeyPair(Pair<Element, Exponent>);
impl KeyPair {
    fn new() -> Self {
        let secret = Scalar::random(&mut rand::thread_rng());
        let pair = Pair {
            a: Element::new(RistrettoPoint::mul_base(&secret)),
            b: Exponent::new(secret),
        };
        KeyPair(pair)
    }

    fn parse(bytes: [u8; 64]) -> Self {
        let pair = Pair::parse(bytes);
        KeyPair(pair)
    }

    fn write(&self) -> [u8; 64] {
        self.0.write()
    }

    fn encrypt(&self, message: &Element) -> ElGamal {
        let r = Scalar::random(&mut rand::thread_rng());
        let gr = RistrettoPoint::mul_base(&r);
        let mhr = message.0 + (self.pkey().0 * r);

        ElGamal::new(Element(gr), Element(mhr))
    }

    fn decrypt(&self, elgamal: &ElGamal) -> Element {
        let factor = elgamal.0.a.0 * self.skey().0;
        let decrypted = elgamal.0.b.0 - factor;
        Element(decrypted)
    }

    fn pkey(&self) -> Element {
        self.0.a.clone()
    }

    fn skey(&self) -> Exponent {
        self.0.b.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;

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

    #[test]
    fn test_keypair() {
        let keypair = KeyPair::new();

        // Serialize and deserialize
        let bytes = keypair.write();
        let parsed_keypair = KeyPair::parse(bytes);

        // Check if the original and parsed keypairs are equal
        assert_eq!(keypair.pkey().0, parsed_keypair.pkey().0);
        assert_eq!(keypair.skey().0, parsed_keypair.skey().0);
    }

    #[test]
    fn test_elgamal() {
        let keypair = KeyPair::new();
        let message = Element::new(RistrettoPoint::random(&mut rand::thread_rng()));

        // Encrypt the message
        let elgamal = keypair.encrypt(&message);

        // Serialize and deserialize
        let bytes = elgamal.write();
        let parsed_elgamal = ElGamal::parse(bytes);

        let decrypted_message = keypair.decrypt(&parsed_elgamal);
        // Check if the original and decrypted messages are equal
        assert_eq!(message.0, decrypted_message.0);
    }
}
