use crate::size::{Product, Pair, Parseable, Size};
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

type ElGamal_ = Pair<Element, Element>;
struct ElGamal(ElGamal_);
impl ElGamal {
    fn new(gr: Element, mhr: Element) -> Self {
        ElGamal(Pair { fst: gr, snd: mhr })
    }

    fn gr(&self) -> Element {
        self.0.fst.clone()
    }

    fn mhr(&self) -> Element {
        self.0.snd.clone()
    }
}
impl Size for ElGamal {
    const SIZE: usize = ElGamal_::SIZE;
}
impl Parseable<{ ElGamal::SIZE }> for ElGamal {
    fn parse(bytes: [u8; ElGamal::SIZE]) -> Self {
        let pair = Pair::parse(bytes);
        ElGamal(pair)
    }
    fn write(&self) -> [u8; ElGamal::SIZE] {
        self.0.write()
    }
}

type KeyPair_ = Pair<Element, Exponent>;
struct KeyPair(KeyPair_);
impl KeyPair {
    fn new() -> Self {
        let secret = Scalar::random(&mut rand::thread_rng());
        let pair = Pair {
            fst: Element::new(RistrettoPoint::mul_base(&secret)),
            snd: Exponent::new(secret),
        };
        KeyPair(pair)
    }

    fn encrypt(&self, message: &Element) -> ElGamal {
        let r = Scalar::random(&mut rand::thread_rng());
        let gr = RistrettoPoint::mul_base(&r);
        let mhr = message.0 + (self.pkey().0 * r);

        ElGamal::new(Element(gr), Element(mhr))
    }

    fn decrypt(&self, elgamal: &ElGamal) -> Element {
        let factor = elgamal.0.fst.0 * self.skey().0;
        let decrypted = elgamal.0.snd.0 - factor;
        Element(decrypted)
    }

    fn pkey(&self) -> Element {
        self.0.fst.clone()
    }

    fn skey(&self) -> Exponent {
        self.0.snd.clone()
    }
}
impl Size for KeyPair {
    const SIZE: usize = KeyPair_::SIZE;
}
impl Parseable<{ KeyPair::SIZE }> for KeyPair {
    fn parse(bytes: [u8; KeyPair::SIZE]) -> Self {
        let pair = Pair::parse(bytes);
        KeyPair(pair)
    }
    fn write(&self) -> [u8; KeyPair::SIZE] {
        self.0.write()
    }
}

// A product of ciphertexts
type EGProductN_<const LEN: usize> = Product<LEN, ElGamal>;

struct EGProductN<const LEN: usize>(pub EGProductN_<LEN>);
impl<const LEN: usize> EGProductN<LEN> {
    fn new(list: [ElGamal; LEN]) -> Self {
        EGProductN(Product(list))
    }
}
impl<const LEN: usize> Size for EGProductN<LEN> {
    const SIZE: usize = EGProductN_::<LEN>::SIZE;
}
impl<const LEN: usize> Parseable<{ Self::SIZE }> for EGProductN<LEN> 
where Product<LEN, ElGamal>: Parseable<{ Self::SIZE }> 
{
     fn parse(bytes: [u8; Self::SIZE]) -> Self {
        let list: Product<LEN, ElGamal> = Product::parse(bytes);
        EGProductN(list)
    }
    fn write(&self) -> [u8; Self::SIZE] {
        self.0.write()
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

    #[test]
    fn test_eg_product() {
        let keypair = KeyPair::new();
        let message1 = Element::new(RistrettoPoint::random(&mut rand::thread_rng()));
        let message2 = Element::new(RistrettoPoint::random(&mut rand::thread_rng()));
        let message3 = Element::new(RistrettoPoint::random(&mut rand::thread_rng()));

        // Encrypt the messages
        let elgamal1 = keypair.encrypt(&message1);
        let elgamal2 = keypair.encrypt(&message2);
        let elgamal3 = keypair.encrypt(&message3);

        // Creates an elgamal product of size 3 (EGProductN<3>)
        let product3 = EGProductN::new([elgamal1, elgamal2, elgamal3]);

        // Serialization is type contrained to 192 bytes (EGProductN::<3>::SIZE)
        let bytes = product3.write();
        let parsed_product3 = EGProductN::parse(bytes);

        let decrypted_message1 = keypair.decrypt(&parsed_product3.0.0[0]);
        let decrypted_message2 = keypair.decrypt(&parsed_product3.0.0[1]);
        let decrypted_message3 = keypair.decrypt(&parsed_product3.0.0[2]);
        
        // Check if the original and decrypted messages are equal
        assert_eq!(message1.0, decrypted_message1.0);
        assert_eq!(message2.0, decrypted_message2.0);
        assert_eq!(message3.0, decrypted_message3.0);
    }
}