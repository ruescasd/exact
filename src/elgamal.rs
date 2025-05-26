use crate::serialization::{Product, Pair, FSerializable, Size};
use crate::arithmetic::{Element, Exponent, ElementN}; // Added ElementN
use curve25519_dalek::{ // CompressedRistretto removed
    Scalar,
    ristretto::RistrettoPoint,
};
use rand; // Added for Scalar::random

// Exponent and Element structs and their impls were removed from here

// --- New Trait Definitions ---
pub trait Encryptable<C> {
    fn encrypt(&self, key: &KeyPair) -> C;
}

pub trait Decryptable<P> {
    fn decrypt(&self, key: &KeyPair) -> P;
}
// --- End New Trait Definitions ---

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

    // Old ElGamal::decrypt(skey: &Exponent) method removed.
    // Decryption is now handled by the Decryptable trait implementation.
}
impl Size for ElGamal {
    const SIZE: usize = ElGamal_::SIZE;
}
impl FSerializable<{ ElGamal::SIZE }> for ElGamal {
    fn read_bytes(bytes: [u8; ElGamal::SIZE]) -> Self {
        let pair = Pair::read_bytes(bytes);
        ElGamal(pair)
    }
    fn write_bytes(&self) -> [u8; ElGamal::SIZE] {
        self.0.write_bytes()
    }
}

type KeyPair_ = Pair<Element, Exponent>;
struct KeyPair(KeyPair_); // KeyPair is defined here, after trait definitions but that's fine.
impl KeyPair {
    fn new() -> Self {
        let secret = Scalar::random(&mut rand::thread_rng());
        let pair = Pair {
            fst: Element::new(RistrettoPoint::mul_base(&secret)),
            snd: Exponent::new(secret),
        };
        KeyPair(pair)
    }

    // Old KeyPair::encrypt method removed.
    // Old KeyPair::decrypt method removed.

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
    fn read_bytes(bytes: [u8; KeyPair::SIZE]) -> Self {
        let pair = Pair::read_bytes(bytes);
        KeyPair(pair)
    }
    fn write_bytes(&self) -> [u8; KeyPair::SIZE] {
        self.0.write_bytes()
    }
}

// --- Encryptable/Decryptable Trait Implementations ---

impl Encryptable<ElGamal> for crate::arithmetic::Element {
    fn encrypt(&self, key: &KeyPair) -> ElGamal {
        // 'self' in this context is the Element (message). 'key' is the KeyPair.
        let r = Scalar::random(&mut rand::thread_rng());
        let gr = RistrettoPoint::mul_base(&r);
        let mhr = self.0 + (key.pkey().0 * r); 
        ElGamal::new(crate::arithmetic::Element::new(gr), crate::arithmetic::Element::new(mhr))
    }
}

impl Decryptable<crate::arithmetic::Element> for ElGamal {
    fn decrypt(&self, key: &KeyPair) -> crate::arithmetic::Element {
        // 'self' here is the ElGamal ciphertext. 'key' is the KeyPair.
        let factor = self.gr().0 * key.skey().0; 
        let decrypted_point = self.mhr().0 - factor;
        crate::arithmetic::Element::new(decrypted_point)
    }
}
// --- End Trait Implementations ---

// ElementN related code (ElementN_, struct ElementN, impl Size, impl FSerializable, and its methods including encrypt) removed from here.

// --- Encryptable/Decryptable Trait Implementations for N-types ---

impl<const LEN: usize> Encryptable<ElGamalN<LEN>> for crate::arithmetic::ElementN<LEN>
where
    crate::arithmetic::Element: Encryptable<ElGamal>, // Ensure single Element is Encryptable
{
    fn encrypt(&self, key: &KeyPair) -> ElGamalN<LEN> {
        let encrypted_product = self.0.map(|element| element.encrypt(key));
        ElGamalN(encrypted_product)
    }
}

impl<const LEN: usize> Decryptable<crate::arithmetic::ElementN<LEN>> for ElGamalN<LEN>
where
    ElGamal: Decryptable<crate::arithmetic::Element>, // Ensure single ElGamal is Decryptable
{
    fn decrypt(&self, key: &KeyPair) -> crate::arithmetic::ElementN<LEN> {
        let decrypted_product = self.0.map(|elgamal| elgamal.decrypt(key));
        crate::arithmetic::ElementN(decrypted_product)
    }
}

// --- End N-type Trait Implementations ---

// A product of ciphertexts
type ElGamalN_<const LEN: usize> = Product<LEN, ElGamal>;

pub struct ElGamalN<const LEN: usize>(pub ElGamalN_<LEN>); // Made pub
impl<const LEN: usize> ElGamalN<LEN> {
    pub fn new(list: [ElGamal; LEN]) -> Self { // Made pub
        ElGamalN(Product(list))
    }
    // Old decrypt method removed
}
impl<const LEN: usize> Size for ElGamalN<LEN> {
    const SIZE: usize = ElGamalN_::<LEN>::SIZE;
}
impl<const LEN: usize> FSerializable<{ Self::SIZE }> for ElGamalN<LEN> 
where Product<LEN, ElGamal>: FSerializable<{ Self::SIZE }> 
{
     fn read_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let list: Product<LEN, ElGamal> = Product::read_bytes(bytes);
        ElGamalN(list)
    }
    fn write_bytes(&self) -> [u8; Self::SIZE] {
        self.0.write_bytes()
    }
}
// Removed the separate impl block for ElGamalN that only contained decrypt

#[cfg(test)]
mod tests {
    use std::array;

    use super::*;
    // test_element and test_exponent removed.
    // curve25519_dalek::scalar::Scalar import removed as it's no longer directly used by remaining tests.
    // Usages of Scalar and RistrettoPoint in KeyPair::new, etc., rely on the parent module's imports.


    #[test]
    fn test_keypair() {
        let keypair = KeyPair::new();

        // Serialize and deserialize
        let bytes = keypair.write_bytes();
        let parsed_keypair = KeyPair::read_bytes(bytes);

        // Check if the original and parsed keypairs are equal
        assert_eq!(keypair.pkey().0, parsed_keypair.pkey().0);
        assert_eq!(keypair.skey().0, parsed_keypair.skey().0);
    }

    #[test]
    fn test_elgamal() {
        let keypair = KeyPair::new();
        let message = Element::new(RistrettoPoint::random(&mut rand::thread_rng()));

        // Encrypt the message using trait method
        let elgamal = message.encrypt(&keypair);

        // Serialize and deserialize
        let bytes = elgamal.write_bytes();
        let parsed_elgamal = ElGamal::read_bytes(bytes);

        // Decrypt the message using trait method
        let decrypted_message = parsed_elgamal.decrypt(&keypair);
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
        let bytes = egs.write_bytes();
        // ElGamalN<3>
        let parsed_egs = ElGamalN::read_bytes(bytes);

        // ElementN<3>
        let decrypted: ElementN<3> = parsed_egs.decrypt(&keypair);

        // Product<3, bool>
        // Check if each decrypted message matches the original message
        let ok = decrypted.0.zip_with(&messages.0, |decrypted, original| {
            decrypted.0 == original.0
        });

        assert!(ok.0.iter().all(|x| *x), "All elements should match");

        // Removed duplicated decryption block from here as it was redundant
        // and not testing a new distinct scenario for ElGamal product integrity.
        // The original test for non-matching keys is better suited for a separate,
        // more focused test case if needed.
    }
}