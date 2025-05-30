use crate::serialization_hybrid::{
    Error as SerHyError, FSerializable, Product, Repeated, Size as SerHySize,
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
// For now, we assume G::Element and G::Scalar implement SerHySize and FSerializable with their own SizeType.
pub trait Encryptable<G: CryptoGroup, C> {
    fn encrypt(&self, key: &KeyPair<G>) -> C;
}

pub trait Decryptable<G: CryptoGroup, P> {
    fn decrypt(&self, key: &KeyPair<G>) -> P;
}
// --- End New Trait Definitions ---

// KeyPair: sk (Scalar), pk (Element)
// Old: KeyPair(Pair<G::Element, G::Scalar>)
#[derive(Debug, Clone, PartialEq, Eq)] // Assuming G::Element and G::Scalar are Clone, PartialEq, Eq
pub struct KeyPair<G: CryptoGroup>
where
    G::Element: Clone + PartialEq + Eq, // Adding bounds here for derive
    G::Scalar: Clone + PartialEq + Eq,
{
    pub sk: G::Scalar,
    pub pk: G::Element,
}

impl<G: CryptoGroup> KeyPair<G>
where
    G::Element: Clone + PartialEq + Eq,
    G::Scalar: Clone + PartialEq + Eq,
{
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let sk = G::Scalar::random(&mut rng);
        let pk = G::generator().scalar_mul(&sk);
        KeyPair { sk, pk }
    }

    pub fn pkey(&self) -> G::Element {
        self.pk.clone()
    }

    pub fn skey(&self) -> G::Scalar {
        self.sk.clone()
    }
}

impl<G: CryptoGroup> SerHySize for KeyPair<G>
where
    G::Element: SerHySize + Clone + PartialEq + Eq,
    G::Scalar: SerHySize + Clone + PartialEq + Eq,
    <G::Element as SerHySize>::SizeType: CoreAdd<<G::Scalar as SerHySize>::SizeType>,
    Sum<<G::Element as SerHySize>::SizeType, <G::Scalar as SerHySize>::SizeType>: Unsigned + NonZero + ArraySize,
{
    type SizeType = Sum<<G::Element as SerHySize>::SizeType, <G::Scalar as SerHySize>::SizeType>;
}

impl<G: CryptoGroup> FSerializable<Sum<<G::Element as SerHySize>::SizeType, <G::Scalar as SerHySize>::SizeType>> for KeyPair<G>
where
    G::Element: SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    G::Scalar: SerHySize + FSerializable<<G::Scalar as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    <G::Element as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreAdd<<G::Scalar as SerHySize>::SizeType>, // Removed incorrect Sub bound
    <G::Scalar as SerHySize>::SizeType: Unsigned + NonZero + ArraySize,
    Sum<<G::Element as SerHySize>::SizeType, <G::Scalar as SerHySize>::SizeType>: Unsigned + NonZero + ArraySize
                                     + core::ops::Sub<<G::Element as SerHySize>::SizeType, Output = <G::Scalar as SerHySize>::SizeType>
                                     + core::ops::Sub<<G::Scalar as SerHySize>::SizeType, Output = <G::Element as SerHySize>::SizeType>, // Added for symmetry, Product uses split specific to A then B
{
    // Signature should use the explicit Sum type, not Self::SizeType
    fn serialize(&self) -> Array<u8, Sum<<G::Element as SerHySize>::SizeType, <G::Scalar as SerHySize>::SizeType>> {
        let product = Product(self.pk.clone(), self.sk.clone());
        product.serialize()
    }

    // Signature should use the explicit Sum type
    fn deserialize(buffer: Array<u8, Sum<<G::Element as SerHySize>::SizeType, <G::Scalar as SerHySize>::SizeType>>) -> Result<Self, SerHyError> {
        let product = Product::<G::Element, G::Scalar>::deserialize(buffer)?;
        Ok(KeyPair { pk: product.0, sk: product.1 })
    }
}


// ElGamal Ciphertext: c1 (Element), c2 (Element)
// Old: ElGamal(Pair<G::Element, G::Element>)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamal<G: CryptoGroup>
where G::Element: Clone + PartialEq + Eq
{
    pub c1: G::Element, // g^r
    pub c2: G::Element, // m * h^r
}

impl<G: CryptoGroup> ElGamal<G>
where G::Element: Clone + PartialEq + Eq
{
    pub fn new(c1: G::Element, c2: G::Element) -> Self {
        ElGamal { c1, c2 }
    }

    pub fn gr(&self) -> G::Element { // Assuming c1 is g^r
        self.c1.clone()
    }

    pub fn mhr(&self) -> G::Element { // Assuming c2 is m*h^r
        self.c2.clone()
    }
}

impl<G: CryptoGroup> SerHySize for ElGamal<G>
where
    G::Element: SerHySize + Clone + PartialEq + Eq,
    <G::Element as SerHySize>::SizeType: CoreAdd<<G::Element as SerHySize>::SizeType>, // For Sum
    Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>: Unsigned + NonZero + ArraySize,
{
    // Two elements of the same type.
    type SizeType = Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>;
    // Alternative using Prod if we want to be more explicit about repetition of same type:
    // type SizeType = Prod<<G::Element as SerHySize>::SizeType, typenum::U2>;
    // This would require G::Element::SizeType: CoreMul<U2> and Prod<...> bound. Sum is simpler.
}

impl<G: CryptoGroup> FSerializable<Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>> for ElGamal<G>
where
    G::Element: SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    <G::Element as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreAdd<<G::Element as SerHySize>::SizeType>, // Removed incorrect Sub bound
    Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>: Unsigned + NonZero + ArraySize
                                     + core::ops::Sub<<G::Element as SerHySize>::SizeType, Output = <G::Element as SerHySize>::SizeType>,
{
    // Signature should use the explicit Sum type
    fn serialize(&self) -> Array<u8, Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>> {
        let product = Product(self.c1.clone(), self.c2.clone());
        product.serialize()
    }

    // Signature should use the explicit Sum type
    fn deserialize(buffer: Array<u8, Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>>) -> Result<Self, SerHyError> {
        let product = Product::<G::Element, G::Element>::deserialize(buffer)?;
        Ok(ElGamal { c1: product.0, c2: product.1 })
    }
}

impl<G: CryptoGroup> Default for ElGamal<G>
where G::Element: Default + Clone + PartialEq + Eq // Ensure G::Element is Default
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
    G::Element: GroupElement<Scalar = G::Scalar> + Clone + SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + Eq + PartialEq,
    G::Scalar: GroupScalar + SerHySize + FSerializable<<G::Scalar as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
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
    G::Element: GroupElement<Scalar = G::Scalar> + Clone + SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + Eq + PartialEq,
    G::Scalar: GroupScalar + SerHySize + FSerializable<<G::Scalar as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
{
    fn decrypt(&self, key: &KeyPair<G>) -> G::Element {
        let gr_pow_x = self.c1.scalar_mul(&key.sk); // Use self.c1 and key.sk
        let decrypted_element = self.c2.add_element(&gr_pow_x.negate_element()); // Use self.c2
        decrypted_element
    }
}
// --- End Trait Implementations ---


// --- ElGamalN (Ciphertext for multiple elements) ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalN<G, LenType>(pub Repeated<ElGamal<G>, LenType>)
where
    G: CryptoGroup,
    G::Element: Clone + PartialEq + Eq, // For ElGamal<G>
    ElGamal<G>: Clone + PartialEq + Eq + SerHySize, // For Repeated<...>
    LenType: ArraySize;

impl<G, LenType> ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + GroupElement<Scalar = G::Scalar> + Clone + Default + Eq + PartialEq,
    G::Scalar: SerHySize + FSerializable<<G::Scalar as SerHySize>::SizeType> + GroupScalar + Clone + Default + Eq + PartialEq,
    ElGamal<G>: SerHySize + FSerializable<<ElGamal<G> as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    LenType: Unsigned + NonZero + ArraySize,
    // Bounds for SerHySize of ElGamal<G>
    <G::Element as SerHySize>::SizeType: CoreAdd<<G::Element as SerHySize>::SizeType>,
    Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>: Unsigned + NonZero + ArraySize,
    // Bounds for FSerializable of ElGamalN
    <ElGamal<G> as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    pub fn new(ciphertexts: Repeated<ElGamal<G>, LenType>) -> Self {
        ElGamalN(ciphertexts)
    }
}

impl<G, LenType> SerHySize for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: SerHySize + Clone + PartialEq + Eq, // For ElGamal<G>
    ElGamal<G>: SerHySize + Clone + PartialEq + Eq,
    <ElGamal<G> as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    LenType: Unsigned + NonZero + ArraySize,
    Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    type SizeType = Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>;
}

impl<G, LenType> FSerializable<Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>> for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + GroupElement<Scalar = G::Scalar> + Clone + Default + Eq + PartialEq,
    G::Scalar: SerHySize + FSerializable<<G::Scalar as SerHySize>::SizeType> + GroupScalar + Clone + Default + Eq + PartialEq,
    ElGamal<G>: SerHySize + FSerializable<<ElGamal<G> as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    LenType: Unsigned + NonZero + ArraySize,
    <ElGamal<G> as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>,
    Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    // Signature should use the explicit Prod type
    fn serialize(&self) -> Array<u8, Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>> {
        self.0.serialize()
    }

    // Signature should use the explicit Prod type
    fn deserialize(buffer: Array<u8, Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>>) -> Result<Self, SerHyError> {
        Ok(ElGamalN(Repeated::deserialize(buffer)?))
    }
}


// --- Encryptable/Decryptable Trait Implementations for N-types ---
impl<G, LenType> Encryptable<G, ElGamalN<G, LenType>> for ElementN<G, LenType>
where
    G: CryptoGroup,
    G::Element: GroupElement<Scalar = G::Scalar> + SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    G::Scalar: GroupScalar + SerHySize + FSerializable<<G::Scalar as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    ElGamal<G>: SerHySize + FSerializable<<ElGamal<G> as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    LenType: Unsigned + NonZero + ArraySize,
    // Bounds from ElementN struct definition
    <G::Element as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType> + CoreAdd<<G::Element as SerHySize>::SizeType>, // Added CoreAdd here
    Prod<<G::Element as SerHySize>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
    // Bounds for SerHySize of ElGamal<G> (needed for Array<ElGamal<G>, LenType>::default() and its FSerializable)
    Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>: Unsigned + NonZero + ArraySize,
    // Bounds for FSerializable of ElGamalN / Repeated<ElGamal<G>, LenType>
    <ElGamal<G> as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>, // This is Sum<G::E::ST, G::E::ST>: CoreMul<LenType>
    Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    fn encrypt(&self, key: &KeyPair<G>) -> ElGamalN<G, LenType> {
        let mut encrypted_elements_array = Array::<ElGamal<G>, LenType>::default();
        for i in 0..LenType::USIZE {
            // self.0 is Repeated<G::Element, LenType>, self.0.0 is Array<G::Element, LenType>
            let element = self.0.0.as_slice()[i].clone();
            encrypted_elements_array.as_mut_slice()[i] = element.encrypt(key);
        }
        ElGamalN::new(Repeated(encrypted_elements_array))
    }
}

impl<G, LenType> Decryptable<G, ElementN<G, LenType>> for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    G::Element: GroupElement<Scalar = G::Scalar> + SerHySize + FSerializable<<G::Element as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    G::Scalar: GroupScalar + SerHySize + FSerializable<<G::Scalar as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    ElGamal<G>: SerHySize + FSerializable<<ElGamal<G> as SerHySize>::SizeType> + Clone + Default + Eq + PartialEq,
    LenType: Unsigned + NonZero + ArraySize,
    // Bounds for G::Element::SizeType (from ElementN and for ElGamal<G>)
    <G::Element as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType> + CoreAdd<<G::Element as SerHySize>::SizeType>, // Added CoreAdd and ensured CoreMul
    Prod<<G::Element as SerHySize>::SizeType, LenType>: Unsigned + NonZero + ArraySize, // For ElementN FSer
    // Bounds for SerHySize of ElGamal<G>
    Sum<<G::Element as SerHySize>::SizeType, <G::Element as SerHySize>::SizeType>: Unsigned + NonZero + ArraySize,
    // Bounds for FSerializable of ElGamalN / Repeated<ElGamal<G>, LenType>
    <ElGamal<G> as SerHySize>::SizeType: Unsigned + NonZero + ArraySize + CoreMul<LenType>, // This is Sum<G::E::ST, G::E::ST>: CoreMul<LenType>
    Prod<<ElGamal<G> as SerHySize>::SizeType, LenType>: Unsigned + NonZero + ArraySize,
{
    fn decrypt(&self, key: &KeyPair<G>) -> ElementN<G, LenType> {
        let mut decrypted_elements_array = Array::<G::Element, LenType>::default();
        for i in 0..LenType::USIZE {
            let elgamal_cipher = self.0.0.as_slice()[i].clone();
            decrypted_elements_array.as_mut_slice()[i] = elgamal_cipher.decrypt(key);
        }
        ElementN::<G, LenType>::new(Repeated(decrypted_elements_array))
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
        let elements_repeated = Repeated(Array::<RistrettoElement, U3>::from(messages_array.clone()));
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
