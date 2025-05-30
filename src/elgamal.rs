use crate::serialization_hybrid::{
    Error as SerHyError, FSerializable, Product, Pair, Size,
};
use crate::traits::element::{ElementN, GroupElement};
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use hybrid_array::typenum::{Sum, Prod, Unsigned, NonZero}; // Assuming U<N> will come from specific type defs
use hybrid_array::{Array, ArraySize};
use core::ops::{Add as CoreAdd, Mul as CoreMul}; // For typenum arithmetic bounds
use rand;

// --- New Trait Definitions ---
// These traits might need to be moved or adapted if G::ElementSerializedSize etc. are no longer available.
// For now, we assume G::Element and G::Scalar implement Size and FSerializable with their own SizeType.
pub trait Encryptable<G: CryptoGroup, C> {
    fn encrypt(&self, key: &KeyPair<G>) -> C;
}

pub trait Decryptable<G: CryptoGroup, P> {
    fn decrypt(&self, key: &KeyPair<G>) -> P;
}
// --- End New Trait Definitions ---

#[derive(Debug, Clone)]
pub struct KeyPair<G: CryptoGroup>
{
    pub sk: G::Scalar,
    pub pk: G::Element,
}

impl<G: CryptoGroup> KeyPair<G>
{
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let sk = G::Scalar::random(&mut rng);
        let pk = G::generator().scalar_mul(&sk);
        KeyPair { sk, pk }
    }

    pub fn pkey(&self) -> &G::Element {
        &self.pk
    }

    pub fn skey(&self) -> &G::Scalar {
        &self.sk
    }
}

impl<G: CryptoGroup> Size for KeyPair<G>
where
    G::Element: Size + Clone,
    G::Scalar: Size + Clone,
    <G::Element as Size>::SizeType: CoreAdd<<G::Scalar as Size>::SizeType>,
    Sum<<G::Element as Size>::SizeType, <G::Scalar as Size>::SizeType>: Unsigned + NonZero + ArraySize,
{
    type SizeType = Sum<<G::Element as Size>::SizeType, <G::Scalar as Size>::SizeType>;
}

impl<G: CryptoGroup> FSerializable<Sum<<G::Element as Size>::SizeType, <G::Scalar as Size>::SizeType>> for KeyPair<G>
where
    G::Element: Size + FSerializable<<G::Element as Size>::SizeType> + Clone,
    G::Scalar: Size + FSerializable<<G::Scalar as Size>::SizeType> + Clone,
    <G::Element as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreAdd<<G::Scalar as Size>::SizeType>, // Removed incorrect Sub bound
    <G::Scalar as Size>::SizeType: Unsigned + NonZero + ArraySize,
    Sum<<G::Element as Size>::SizeType, <G::Scalar as Size>::SizeType>: NonZero + ArraySize
                                     + core::ops::Sub<<G::Element as Size>::SizeType, Output = <G::Scalar as Size>::SizeType>
                                     + core::ops::Sub<<G::Scalar as Size>::SizeType, Output = <G::Element as Size>::SizeType>, // Added for symmetry, Product uses split specific to A then B
{
    // Signature should use the explicit Sum type, not Self::SizeType
    fn serialize(&self) -> Array<u8, Sum<<G::Element as Size>::SizeType, <G::Scalar as Size>::SizeType>> {
        let product = Pair(self.pk.clone(), self.sk.clone());
        product.serialize()
    }

    // Signature should use the explicit Sum type
    fn deserialize(buffer: Array<u8, Sum<<G::Element as Size>::SizeType, <G::Scalar as Size>::SizeType>>) -> Result<Self, SerHyError> {
        let product = Pair::<G::Element, G::Scalar>::deserialize(buffer)?;
        Ok(KeyPair { pk: product.0, sk: product.1 })
    }
}


// ElGamal Ciphertext: c1 (Element), c2 (Element)
// Old: ElGamal(Pair<G::Element, G::Element>)
#[derive(Debug, Clone)]
pub struct ElGamal<G: CryptoGroup>
{
    pub c1: G::Element, // g^r
    pub c2: G::Element, // m * h^r
}

impl<G: CryptoGroup> ElGamal<G>
{
    pub fn new(c1: G::Element, c2: G::Element) -> Self {
        ElGamal { c1, c2 }
    }

    pub fn gr(&self) -> &G::Element { // Assuming c1 is g^r
        &self.c1
    }

    pub fn mhr(&self) -> &G::Element { // Assuming c2 is m*h^r
        &self.c2
    }
}

impl<G: CryptoGroup> Size for ElGamal<G>
where
    G::Element: Size + Clone,
    <G::Element as Size>::SizeType: CoreAdd<<G::Element as Size>::SizeType>, // For Sum
    Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>: NonZero + ArraySize,
{
    // Two elements of the same type.
    type SizeType = Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>;
}

impl<G: CryptoGroup> FSerializable<Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>> for ElGamal<G>
where
    G::Element: Size + FSerializable<<G::Element as Size>::SizeType> + Clone,
    <G::Element as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreAdd<<G::Element as Size>::SizeType>, // Removed incorrect Sub bound
    Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>: NonZero + ArraySize
                                     + core::ops::Sub<<G::Element as Size>::SizeType, Output = <G::Element as Size>::SizeType>,
{
    // Signature should use the explicit Sum type
    fn serialize(&self) -> Array<u8, Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>> {
        let product = Pair(self.c1.clone(), self.c2.clone());
        product.serialize()
    }

    // Signature should use the explicit Sum type
    fn deserialize(buffer: Array<u8, Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>>) -> Result<Self, SerHyError> {
        let product = Pair::<G::Element, G::Element>::deserialize(buffer)?;
        Ok(ElGamal { c1: product.0, c2: product.1 })
    }
}

impl<G: CryptoGroup> Default for ElGamal<G>
where G::Element: Default + Clone
{
    fn default() -> Self {
        Self {
            c1: G::Element::default(),
            c2: G::Element::default(),
        }
    }
}

// --- Encryptable/Decryptable Trait Implementations ---

impl<G: CryptoGroup> Encryptable<G, ElGamal<G>> for G::Element
where
    G::Element: GroupElement<Scalar = G::Scalar> + Size + FSerializable<<G::Element as Size>::SizeType>,
    G::Scalar: GroupScalar + Size + FSerializable<<G::Scalar as Size>::SizeType> + Clone + Default,
    // Added Default to G::Scalar for KeyPair::new if it relies on Scalar::default via some path.
    // ElGamal<G> needs G::Element to be Clone, Eq, PartialEq (handled by its struct def)
    // KeyPair<G> needs G::Element and G::Scalar to be Clone, Eq, PartialEq (handled by its struct def)
{
    fn encrypt(&self, key: &KeyPair<G>) -> ElGamal<G> {
        let mut rng = rand::thread_rng();
        let r_scalar = G::Scalar::random(&mut rng);
        let gr = G::generator().scalar_mul(&r_scalar);
        let y_pow_r = key.pk.scalar_mul(&r_scalar); // Use key.pk
        let mhr = self.add_element(&y_pow_r);
        ElGamal::<G>::new(gr, mhr)
    }
}

impl<G: CryptoGroup> Decryptable<G, G::Element> for ElGamal<G>
where
    G::Element: GroupElement<Scalar = G::Scalar> + Size + FSerializable<<G::Element as Size>::SizeType>,
    G::Scalar: GroupScalar + Size + FSerializable<<G::Scalar as Size>::SizeType> + Clone,
{
    fn decrypt(&self, key: &KeyPair<G>) -> G::Element {
        let gr_pow_x = self.c1.scalar_mul(&key.sk); // Use self.c1 and key.sk
        let decrypted_element = self.c2.add_element(&gr_pow_x.negate_element()); // Use self.c2
        decrypted_element
    }
}
// --- End Trait Implementations ---


// --- ElGamalN (Ciphertext for multiple elements) ---
#[derive(Debug)]
pub struct ElGamalN<G, LenType>(pub Product<ElGamal<G>, LenType>)
where
    G: CryptoGroup,
    ElGamal<G>: Size, // For Repeated<...>
    LenType: ArraySize;

impl<G, LenType> ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: Clone + Size + FSerializable<<G::Element as Size>::SizeType> + GroupElement<Scalar = G::Scalar> + Clone + Default,
    G::Scalar: Clone + Size + FSerializable<<G::Scalar as Size>::SizeType> + GroupScalar + Clone + Default,
    ElGamal<G>: Size + FSerializable<<ElGamal<G> as Size>::SizeType> + Clone + Default,
    LenType: NonZero + ArraySize,
    // Bounds for Size of ElGamal<G>
    <G::Element as Size>::SizeType: CoreAdd<<G::Element as Size>::SizeType>,
    Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>: Unsigned + NonZero + ArraySize,
    // Bounds for FSerializable of ElGamalN
    <ElGamal<G> as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<<ElGamal<G> as Size>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    pub fn new(ciphertexts: Product<ElGamal<G>, LenType>) -> Self {
        ElGamalN(ciphertexts)
    }
}

impl<G, LenType> Size for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: Size + Clone, // For ElGamal<G>
    ElGamal<G>: Size + Clone,
    <ElGamal<G> as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    LenType: Unsigned + NonZero + ArraySize,
    Prod<<ElGamal<G> as Size>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    type SizeType = Prod<<ElGamal<G> as Size>::SizeType, LenType>;
}

impl<G, LenType> FSerializable<Prod<<ElGamal<G> as Size>::SizeType, LenType>> for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: Size + FSerializable<<G::Element as Size>::SizeType> + GroupElement<Scalar = G::Scalar> + Clone + Default,
    G::Scalar: Size + FSerializable<<G::Scalar as Size>::SizeType> + GroupScalar + Clone + Default,
    ElGamal<G>: Size + FSerializable<<ElGamal<G> as Size>::SizeType> + Clone + Default,
    LenType: Unsigned + NonZero + ArraySize,
    <ElGamal<G> as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<<ElGamal<G> as Size>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    // Signature should use the explicit Prod type
    fn serialize(&self) -> Array<u8, Prod<<ElGamal<G> as Size>::SizeType, LenType>> {
        self.0.serialize()
    }

    // Signature should use the explicit Prod type
    fn deserialize(buffer: Array<u8, Prod<<ElGamal<G> as Size>::SizeType, LenType>>) -> Result<Self, SerHyError> {
        Ok(ElGamalN(Product::deserialize(buffer)?))
    }
}


// --- Encryptable/Decryptable Trait Implementations for N-types ---
impl<G, LenType> Encryptable<G, ElGamalN<G, LenType>> for ElementN<G, LenType>
where
    G: CryptoGroup,
    G::Element: GroupElement<Scalar = G::Scalar> + Size + FSerializable<<G::Element as Size>::SizeType> + Clone + Default,
    G::Scalar: GroupScalar + Size + FSerializable<<G::Scalar as Size>::SizeType> + Clone + Default,
    ElGamal<G>: Size + FSerializable<<ElGamal<G> as Size>::SizeType> + Clone + Default,
    LenType: NonZero + ArraySize,
    // Bounds from ElementN struct definition
    <G::Element as Size>::SizeType: NonZero + ArraySize + CoreMul<LenType> + CoreAdd<<G::Element as Size>::SizeType>, // Added CoreAdd here
    Prod<<G::Element as Size>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
    // Bounds for Size of ElGamal<G> (needed for Array<ElGamal<G>, LenType>::default() and its FSerializable)
    Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>: Unsigned + NonZero + ArraySize,
    // Bounds for FSerializable of ElGamalN / Repeated<ElGamal<G>, LenType>
    <ElGamal<G> as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>, // This is Sum<G::E::ST, G::E::ST>: CoreMul<LenType>
    Prod<<ElGamal<G> as Size>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    fn encrypt(&self, key: &KeyPair<G>) -> ElGamalN<G, LenType> {
        let mut encrypted_elements_array = Array::<ElGamal<G>, LenType>::default();
        for i in 0..LenType::USIZE {
            // self.0 is Repeated<G::Element, LenType>, self.0.0 is Array<G::Element, LenType>
            let element = self.0.0.as_slice()[i].clone();
            encrypted_elements_array.as_mut_slice()[i] = element.encrypt(key);
        }
        ElGamalN::new(Product(encrypted_elements_array))
    }
}

impl<G, LenType> Decryptable<G, ElementN<G, LenType>> for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: GroupElement<Scalar = G::Scalar> + Size + FSerializable<<G::Element as Size>::SizeType> + Default,
    G::Scalar: GroupScalar + Size + FSerializable<<G::Scalar as Size>::SizeType> + Clone,
    ElGamal<G>: Size + FSerializable<<ElGamal<G> as Size>::SizeType> + Clone,
    LenType: Unsigned + NonZero + ArraySize,
    // Bounds for G::Element::SizeType (from ElementN and for ElGamal<G>)
    <G::Element as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType> + CoreAdd<<G::Element as Size>::SizeType>, // Added CoreAdd and ensured CoreMul
    Prod<<G::Element as Size>::SizeType, LenType>: Unsigned + NonZero + ArraySize, // For ElementN FSer
    // Bounds for Size of ElGamal<G>
    // Sum<<G::Element as Size>::SizeType, <G::Element as Size>::SizeType>: Unsigned + NonZero + ArraySize,
    // Bounds for FSerializable of ElGamalN / Repeated<ElGamal<G>, LenType>
    // <ElGamal<G> as Size>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>, // This is Sum<G::E::ST, G::E::ST>: CoreMul<LenType>
    // Prod<<ElGamal<G> as Size>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    fn decrypt(&self, key: &KeyPair<G>) -> ElementN<G, LenType> {
        let mut decrypted_elements_array = Array::<G::Element, LenType>::default();
        for i in 0..LenType::USIZE {
            let elgamal_cipher = self.0.0.as_slice()[i].clone();
            decrypted_elements_array.as_mut_slice()[i] = elgamal_cipher.decrypt(key);
        }
        ElementN::<G, LenType>::new(Product(decrypted_elements_array))
    }
}

// --- End N-type Trait Implementations ---

#[cfg(test)]
mod tests {
    use std::array;
    use super::*;
    use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement};
    use hybrid_array::typenum::U3; // For LEN = 3 tests

    #[test]
    fn test_keypair_hybrid_serialization() {
        let keypair = KeyPair::<Ristretto255Group>::new();
        let serialized = keypair.serialize();
        let deserialized = KeyPair::<Ristretto255Group>::deserialize(serialized).unwrap();
        assert_eq!(keypair.pk, deserialized.pk);
        assert_eq!(keypair.sk, deserialized.sk);
    }

    #[test]
    fn test_elgamal_hybrid_serialization_and_decryption() {
        let keypair = KeyPair::<Ristretto255Group>::new();
        let message = RistrettoElement::new(curve25519_dalek::ristretto::RistrettoPoint::random(
            &mut rand::thread_rng(),
        ));

        let ciphertext: ElGamal<Ristretto255Group> = message.encrypt(&keypair);
        let serialized_ct = ciphertext.serialize();
        let deserialized_ct = ElGamal::<Ristretto255Group>::deserialize(serialized_ct).unwrap();

        assert_eq!(ciphertext.c1, deserialized_ct.c1);
        assert_eq!(ciphertext.c2, deserialized_ct.c2);

        let decrypted_message: RistrettoElement = deserialized_ct.decrypt(&keypair);
        assert_eq!(message, decrypted_message);
    }

    // Removed: impl Size for bool { ... } as it's not used and from old system.

    #[test]
    fn test_elgamal_n_hybrid_serialization_and_decryption() {
        let keypair = KeyPair::<Ristretto255Group>::new();

        let messages_array: [RistrettoElement; U3::USIZE] = array::from_fn(|_| {
            RistrettoElement::new(curve25519_dalek::ristretto::RistrettoPoint::random(
                &mut rand::thread_rng(),
            ))
        });
        let elements_repeated = Product(Array::<RistrettoElement, U3>::from(messages_array.clone()));
        let messages_n = ElementN::<Ristretto255Group, U3>::new(elements_repeated);

        let encrypted_n: ElGamalN<Ristretto255Group, U3> = messages_n.encrypt(&keypair);

        let serialized_en = encrypted_n.serialize();
        let deserialized_en = ElGamalN::<Ristretto255Group, U3>::deserialize(serialized_en).unwrap();

        let decrypted_n: ElementN<Ristretto255Group, U3> = deserialized_en.decrypt(&keypair);

        // Compare original messages with decrypted messages
        for i in 0..U3::USIZE {
            assert_eq!(messages_n.0.0.as_slice()[i], decrypted_n.0.0.as_slice()[i]);
        }
    }
}
