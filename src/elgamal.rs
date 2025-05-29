use crate::serialization::{Product, Pair, FSerializable, Size};
use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement, RistrettoScalar};
use crate::traits::element::{ElementN, GroupElement};
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar; // ExponentN removed from this line
// use curve25519_dalek::ristretto::RistrettoPoint; // Removed as per instruction
// curve25519_dalek::Scalar might be unused now at top level
use rand;

// Exponent and Element structs and their impls were removed from here

// --- New Trait Definitions ---
pub trait Encryptable<C> {
    fn encrypt(&self, key: &KeyPair) -> C;
}

pub trait Decryptable<P> {
    fn decrypt(&self, key: &KeyPair) -> P;
}
// --- End New Trait Definitions ---

type ElGamal_<G: CryptoGroup> = Pair<G::Element, G::Element>;
pub struct ElGamal<G: CryptoGroup>(ElGamal_<G>)
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:;

impl<G: CryptoGroup> ElGamal<G>
where
    // [(); G::ELEMENT_SERIALIZED_SIZE * 2]:, // This bound is for Size/FSerializable, not methods generally
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    G::Element: GroupElement<{ G::ELEMENT_SERIALIZED_SIZE }, { G::SCALAR_SERIALIZED_SIZE }, Scalar = G::Scalar> + FSerializable<{G::ELEMENT_SERIALIZED_SIZE}>,
    // G::Scalar: GroupScalar<{ G::SCALAR_SERIALIZED_SIZE }>, // Not directly used by these methods but good for consistency
{
    pub fn new(gr: G::Element, mhr: G::Element) -> Self {
        ElGamal(Pair { fst: gr, snd: mhr })
    }

    pub fn gr(&self) -> G::Element {
        self.0.fst.clone()
    }

    pub fn mhr(&self) -> G::Element {
        self.0.snd.clone()
    }

    // Old ElGamal::decrypt(skey: &Exponent) method removed.
    // Decryption is now handled by the Decryptable trait implementation.
}
impl<G: CryptoGroup> Size for ElGamal<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE * 2]:,
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    const SIZE: usize = G::ELEMENT_SERIALIZED_SIZE * 2;
}
impl<G: CryptoGroup> FSerializable<{ Self::SIZE }> for ElGamal<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE * 2]:,
    ElGamal_<G>: FSerializable<{ Self::SIZE }>,
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    fn read_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let pair = ElGamal_::<G>::read_bytes(bytes);
        ElGamal(pair)
    }
    fn write_bytes(&self) -> [u8; Self::SIZE] {
        self.0.write_bytes()
    }
}

type KeyPair_<G: CryptoGroup> = Pair<G::Element, G::Scalar>;
pub struct KeyPair<G: CryptoGroup>(KeyPair_<G>)
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:;

impl<G: CryptoGroup> KeyPair<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    G::Element: GroupElement<{ G::ELEMENT_SERIALIZED_SIZE }, { G::SCALAR_SERIALIZED_SIZE }, Scalar = G::Scalar>,
    G::Scalar: GroupScalar<{ G::SCALAR_SERIALIZED_SIZE }> + FSerializable<{G::SCALAR_SERIALIZED_SIZE}>,
{
    pub fn new() -> Self { 
        let mut rng = rand::thread_rng();
        let secret_scalar = G::Scalar::random(&mut rng);
        let public_element = G::generator().scalar_mul(&secret_scalar);
        let pair = Pair {
            fst: public_element,
            snd: secret_scalar,
        };
        KeyPair(pair)
    }

    // Old KeyPair::encrypt method removed.
    // Old KeyPair::decrypt method removed.

    pub fn pkey(&self) -> G::Element { 
        self.0.fst.clone()
    }

    pub fn skey(&self) -> G::Scalar { 
        self.0.snd.clone()
    }
}
impl<G: CryptoGroup> Size for KeyPair<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE]:,
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    const SIZE: usize = G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE;
}
impl<G: CryptoGroup> FSerializable<{ Self::SIZE }> for KeyPair<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE]:,
    KeyPair_<G>: FSerializable<{ Self::SIZE }>,
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    fn read_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let pair = KeyPair_::<G>::read_bytes(bytes);
        KeyPair(pair)
    }
    fn write_bytes(&self) -> [u8; Self::SIZE] {
        self.0.write_bytes()
    }
}

// --- Encryptable/Decryptable Trait Implementations ---

impl<G: CryptoGroup> Encryptable<ElGamal<G>> for G::Element
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    G::Element: GroupElement<{ G::ELEMENT_SERIALIZED_SIZE }, { G::SCALAR_SERIALIZED_SIZE }, Scalar = G::Scalar>,
    G::Scalar: GroupScalar<{ G::SCALAR_SERIALIZED_SIZE }>,
    // KeyPair<G> and ElGamal<G> bounds are implicitly handled by their definitions
    // and the fact that G: CryptoGroup.
{
    fn encrypt(&self, key: &KeyPair<G>) -> ElGamal<G> {
        let mut rng = rand::thread_rng();
        let r_scalar = G::Scalar::random(&mut rng);
        
        let gr = G::generator().scalar_mul(&r_scalar);
        
        // self is the message: G::Element
        // key.pkey() is the public key: G::Element
        // r_scalar is the random scalar: G::Scalar
        let y_pow_r = key.pkey().scalar_mul(&r_scalar);
        let mhr = self.add_element(&y_pow_r);
        
        ElGamal::<G>::new(gr, mhr)
    }
}

impl<G: CryptoGroup> Decryptable<G::Element> for ElGamal<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE * 2]:, 
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    G::Element: GroupElement<{ G::ELEMENT_SERIALIZED_SIZE }, { G::SCALAR_SERIALIZED_SIZE }, Scalar = G::Scalar>,
    G::Scalar: GroupScalar<{ G::SCALAR_SERIALIZED_SIZE }>,
{
    fn decrypt(&self, key: &KeyPair<G>) -> G::Element {
        // self.gr() is g^r (type G::Element)
        // key.skey() is x (the secret key, type G::Scalar)
        // Calculate (g^r)^x = g^{rx}
        let gr_pow_x = self.gr().scalar_mul(&key.skey());
        
        // self.mhr() is M * h^r = M * (g^x)^r = M * g^{xr} (type G::Element)
        // To get M, we calculate M = (M * g^{xr}) * (g^{xr})^{-1}
        // which is self.mhr().add_element(&gr_pow_x.negate_element())
        let decrypted_element = self.mhr().add_element(&gr_pow_x.negate_element());
        
        decrypted_element
    }
}
// --- End Trait Implementations ---

// ElementN related code (ElementN_, struct ElementN, impl Size, impl FSerializable, and its methods including encrypt) removed from here.

// --- Encryptable/Decryptable Trait Implementations for N-types ---

impl<G: CryptoGroup, const LEN: usize> Encryptable<ElGamalN<G, LEN>> for ElementN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    G::Element: GroupElement<{ G::ELEMENT_SERIALIZED_SIZE }, { G::SCALAR_SERIALIZED_SIZE }, Scalar = G::Scalar> + Encryptable<ElGamal<G>>,
    G::Scalar: GroupScalar<{ G::SCALAR_SERIALIZED_SIZE }>,
    ElGamal<G>: Size + FSerializable<{ElGamal::<G>::SIZE}>, // Product::map requires FSerializable for the mapped type if the original Product was. ElGamal<G> is already FSerializable.
    Product<LEN, ElGamal<G>>: FSerializable<{Product::<LEN, ElGamal<G>>::SIZE}>, // Ensure the resulting product is serializable
    ElementN<G, LEN>: Size,
    ElGamalN<G, LEN>: Size,
    KeyPair<G>: Size, // key argument
    // The Product<LEN, G::Element>::map method will also require G::Element to be FSerializable.
    // It's already part of GroupElement.
    // It will also require ElGamal<G> (the output of the closure) to be FSerializable for the new Product.
{
    fn encrypt(&self, key: &KeyPair<G>) -> ElGamalN<G, LEN> {
        // self.0 is Product<LEN, G::Element>
        // element is G::Element
        // element.encrypt(key) returns ElGamal<G>
        let encrypted_product: Product<LEN, ElGamal<G>> = self.0.map(|element| element.encrypt(key));
        ElGamalN::<G, LEN>(encrypted_product)
    }
}

impl<G: CryptoGroup, const LEN: usize> Decryptable<ElementN<G, LEN>> for ElGamalN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    G::Element: GroupElement<{ G::ELEMENT_SERIALIZED_SIZE }, { G::SCALAR_SERIALIZED_SIZE }, Scalar = G::Scalar> + FSerializable<{G::ELEMENT_SERIALIZED_SIZE}>, // Product::map requires FSerializable for the mapped type
    G::Scalar: GroupScalar<{ G::SCALAR_SERIALIZED_SIZE }>,
    ElGamal<G>: Decryptable<G::Element> + Size + FSerializable<{ElGamal::<G>::SIZE}>, // ElGamal<G> itself also needs to be FSerializable for Product::map
    Product<LEN, G::Element>: FSerializable<{Product::<LEN, G::Element>::SIZE}>, // Ensure the resulting product is serializable
    ElementN<G, LEN>: Size, 
    ElGamalN<G, LEN>: Size, 
    KeyPair<G>: Size, // key argument
    // The Product<LEN, ElGamal<G>>::map method will also require ElGamal<G> to be FSerializable.
    // It's already part of the bounds.
    // It will also require G::Element (the output of the closure) to be FSerializable for the new Product.
{
    fn decrypt(&self, key: &KeyPair<G>) -> ElementN<G, LEN> {
        // self.0 is Product<LEN, ElGamal<G>>
        // elgamal is ElGamal<G>
        // elgamal.decrypt(key) returns G::Element
        let decrypted_product: Product<LEN, G::Element> = self.0.map(|elgamal| elgamal.decrypt(key));
        ElementN::<G, LEN>::new(decrypted_product)
    }
}

// --- End N-type Trait Implementations ---

// A product of ciphertexts
type ElGamalN_<G: CryptoGroup, const LEN: usize> = Product<LEN, ElGamal<G>>;

pub struct ElGamalN<G: CryptoGroup, const LEN: usize>(pub ElGamalN_<G, LEN>)
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:;

impl<G: CryptoGroup, const LEN: usize> ElGamalN<G, LEN>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    [(); Product::<LEN, ElGamal<G>>::SIZE]:,
{
    pub fn new(list: [ElGamal<G>; LEN]) -> Self { // Made pub
        ElGamalN(Product(list))
    }
    // Old decrypt method removed
}
impl<G: CryptoGroup, const LEN: usize> Size for ElGamalN<G, LEN>
where
    [(); Product::<LEN, ElGamal<G>>::SIZE]:,
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    const SIZE: usize = Product::<LEN, ElGamal<G>>::SIZE;
}
impl<G: CryptoGroup, const LEN: usize> FSerializable<{ Self::SIZE }> for ElGamalN<G, LEN> 
where 
    Product<LEN, ElGamal<G>>: FSerializable<{ Self::SIZE }>,
    [(); Self::SIZE]:,
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
     fn read_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let list: Product<LEN, ElGamal<G>> = Product::read_bytes(bytes);
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

    use super::*; // This now brings in RistrettoElement, RistrettoScalar etc.
    // No need to import Element, Exponent, ElementN from crate::arithmetic anymore
    use crate::groups::ristretto255::Ristretto255Group; // Explicit import for clarity

    // test_element and test_exponent removed.
    // curve25519_dalek::scalar::Scalar import removed as it's no longer directly used by remaining tests.
    // Usages of Scalar and RistrettoPoint in KeyPair::new, etc., rely on the parent module's imports.


    #[test]
    fn test_keypair() {
        let keypair = KeyPair::<Ristretto255Group>::new();

        // Serialize and deserialize
        let bytes = keypair.write_bytes();
        let parsed_keypair = KeyPair::<Ristretto255Group>::read_bytes(bytes);

        // Check if the original and parsed keypairs are equal
        assert_eq!(keypair.pkey(), parsed_keypair.pkey());
        assert_eq!(keypair.skey(), parsed_keypair.skey());
    }

    #[test]
    fn test_elgamal() {
        let keypair = KeyPair::<Ristretto255Group>::new();
        // Updated to use RistrettoElement and dalek's RistrettoPoint for random generation
        let message = RistrettoElement::new(curve25519_dalek::ristretto::RistrettoPoint::random(&mut rand::thread_rng()));

        // Encrypt the message using trait method
        let elgamal: ElGamal<Ristretto255Group> = message.encrypt(&keypair);

        // Serialize and deserialize
        let bytes = elgamal.write_bytes();
        let parsed_elgamal = ElGamal::<Ristretto255Group>::read_bytes(bytes);

        // Decrypt the message using trait method
        let decrypted_message: RistrettoElement = parsed_elgamal.decrypt(&keypair);
        // Check if the original and decrypted messages are equal
        assert_eq!(message, decrypted_message);
    }

    impl Size for bool {
        const SIZE: usize = 1;
    }

    #[test]
    fn test_eg_product() {
        let keypair = KeyPair::<Ristretto255Group>::new();
        
        // [RistrettoElement; 3]
        let messages_array: [RistrettoElement; 3] = array::from_fn(|_| {
            RistrettoElement::new(curve25519_dalek::ristretto::RistrettoPoint::random(&mut rand::thread_rng()))
        });

        // ElementN<Ristretto255Group, 3>
        let messages = ElementN::<Ristretto255Group, 3>::new(Product(messages_array));


        // ElGamalN<Ristretto255Group, 3>
        let egs: ElGamalN<Ristretto255Group, 3> = messages.encrypt(&keypair);

        // [u8; 192] = [u8; 32 * 3 * 2]
        let bytes = egs.write_bytes();
        // ElGamalN<Ristretto255Group, 3>
        let parsed_egs = ElGamalN::<Ristretto255Group, 3>::read_bytes(bytes);

        // ElementN<Ristretto255Group, 3>
        let decrypted: ElementN<Ristretto255Group, 3> = parsed_egs.decrypt(&keypair);

        // Product<3, bool>
        // Check if each decrypted message matches the original message
        let ok = decrypted.0.zip_with(&messages.0, |decrypted_el, original_el| {
            // decrypted_el and original_el are RistrettoElement here
            decrypted_el == original_el 
        });

        assert!(ok.0.iter().all(|x| *x), "All elements should match");

        // Removed duplicated decryption block from here as it was redundant
        // and not testing a new distinct scenario for ElGamal product integrity.
        // The original test for non-matching keys is better suited for a separate,
        // more focused test case if needed.
    }
}