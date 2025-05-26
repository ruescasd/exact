use crate::serialization::{Product, Pair, FSerializable, Size};
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
struct Element(RistrettoPoint);
impl Element {
    fn new(point: RistrettoPoint) -> Self {
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

    fn decrypt(&self, skey: &Exponent) -> Element {
        let factor = self.gr().0 * skey.0;
        let decrypted = self.mhr().0 - factor;
        Element(decrypted)
    }
}
impl Size for ElGamal {
    const SIZE: usize = ElGamal_::SIZE;
}
impl FSerializable<{ ElGamal::SIZE }> for ElGamal {
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
        // let factor = elgamal.0.fst.0 * self.skey().0;
        // let decrypted = elgamal.0.snd.0 - factor;
        // Element(decrypted)
        elgamal.decrypt(&self.skey())
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
impl FSerializable<{ KeyPair::SIZE }> for KeyPair {
    fn parse(bytes: [u8; KeyPair::SIZE]) -> Self {
        let pair = Pair::parse(bytes);
        KeyPair(pair)
    }
    fn write(&self) -> [u8; KeyPair::SIZE] {
        self.0.write()
    }
}

// A product of Elements
type ElementN_<const LEN: usize> = Product<LEN, Element>; // Example for 3 elements
struct ElementN<const LEN: usize>(pub ElementN_<LEN>);
impl<const LEN: usize> ElementN<LEN> {
    fn new(list: [Element; LEN]) -> Self {
        ElementN(Product(list))
    }
}
impl<const LEN: usize> Size for ElementN<LEN> {
    const SIZE: usize = ElementN_::<LEN>::SIZE;
}
impl<const LEN: usize> FSerializable<{ Self::SIZE }> for ElementN<LEN> 
where Product<LEN, Element>: FSerializable<{ Self::SIZE }> 
{
     fn parse(bytes: [u8; Self::SIZE]) -> Self {
        let list: Product<LEN, Element> = Product::parse(bytes);
        ElementN(list)
    }
    fn write(&self) -> [u8; Self::SIZE] {
        self.0.write()
    }
}
impl<const LEN: usize> ElementN<LEN> {
    pub fn encrypt(&self, keypair: &KeyPair) -> ElGamalN<LEN> {
        let eg = self.0.map(|element| keypair.encrypt(&element));
        ElGamalN(eg)
    }
}

// A product of ciphertexts
type ElGamalN_<const LEN: usize> = Product<LEN, ElGamal>;

struct ElGamalN<const LEN: usize>(pub ElGamalN_<LEN>);
impl<const LEN: usize> ElGamalN<LEN> {
    fn new(list: [ElGamal; LEN]) -> Self {
        ElGamalN(Product(list))
    }
}
impl<const LEN: usize> Size for ElGamalN<LEN> {
    const SIZE: usize = ElGamalN_::<LEN>::SIZE;
}
impl<const LEN: usize> FSerializable<{ Self::SIZE }> for ElGamalN<LEN> 
where Product<LEN, ElGamal>: FSerializable<{ Self::SIZE }> 
{
     fn parse(bytes: [u8; Self::SIZE]) -> Self {
        let list: Product<LEN, ElGamal> = Product::parse(bytes);
        ElGamalN(list)
    }
    fn write(&self) -> [u8; Self::SIZE] {
        self.0.write()
    }
}
impl<const LEN: usize> ElGamalN<LEN> {
    pub fn decrypt(&self, keypair: &KeyPair) -> ElementN<LEN> {
        let p = self.0.map(|elgamal| keypair.decrypt(&elgamal));
        ElementN(p)
    }
}

#[cfg(test)]
mod tests {
    use std::array;

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

    impl Size for bool {
        const SIZE: usize = 1;
    }

    #[test]
    fn test_eg_product() {
        let keypair = KeyPair::new();
        
        // [Element; 3]
        let messages: [Element; 3] = array::from_fn(|_| {
            Element::new(RistrettoPoint::random(&mut rand::thread_rng()))
        });

        // ElementN<3>
        let messages = ElementN::new(messages);

        // ElGamalN<3>
        let egs = messages.encrypt(&keypair);

        // [u8; 192] = [u8; 32 * 3 * 2]
        let bytes = egs.write();
        // ElGamalN<3>
        let parsed_egs = ElGamalN::parse(bytes);

        // ElementN<3>
        let decrypted: ElementN<3> = parsed_egs.decrypt(&keypair);

        // Product<3, bool>
        // Check if each decrypted message matches the original message
        let ok = decrypted.0.zip_with(&messages.0, |decrypted, original| {
            decrypted.0 == original.0
        });

        assert!(ok.0.iter().all(|x| *x), "All elements should match");

        let keypair = KeyPair::new();

        let decrypted: ElementN<3> = parsed_egs.decrypt(&keypair);

        // Product<3, bool>
        // Check if each decrypted message matches the original message
        let ok = decrypted.0.zip_with(&messages.0, |decrypted, original| {
            decrypted.0 == original.0
        });

        assert!(ok.0.iter().all(|x| !*x), "No elements should match");

        
    }
}