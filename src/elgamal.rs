use crate::serialization_hybrid::{Error as SerHyError, FSerializable, Pair, Product, Size};
use crate::traits::element::{ElementN, GroupElement};
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::utils::rng;
use core::ops::Mul as CoreMul;
use hybrid_array::typenum::Prod;
use hybrid_array::{Array, ArraySize};

pub trait Encryptable<G: CryptoGroup, C> {
    fn encrypt(&self, key: &KeyPair<G>) -> C;
}

pub trait Decryptable<G: CryptoGroup, P> {
    fn decrypt(&self, key: &KeyPair<G>) -> P;
}
// --- End New Trait Definitions ---

#[derive(Debug, Clone)]
pub struct KeyPair<G: CryptoGroup>(pub Pair<G::Scalar, G::Element>);

impl<G: CryptoGroup> KeyPair<G> {
    pub fn new() -> Self {
        let mut rng = rng::DefaultRng;
        let sk = G::Scalar::random(&mut rng);
        let pk = G::generator().scalar_mul(&sk);
        KeyPair(Pair(sk, pk))
    }

    pub fn pkey(&self) -> &G::Element {
        &(self.0).1
    }

    pub fn skey(&self) -> &G::Scalar {
        &(self.0).0
    }
}

type KeyPairSize<G> =
    <Pair<<G as CryptoGroup>::Scalar, <G as CryptoGroup>::Element> as Size>::SizeType;
impl<G: CryptoGroup> Size for KeyPair<G>
where
    Pair<G::Scalar, G::Element>: Size,
{
    type SizeType = KeyPairSize<G>;
}

impl<G: CryptoGroup> FSerializable<KeyPairSize<G>> for KeyPair<G>
where
    Pair<G::Scalar, G::Element>: Size,
    Pair<G::Scalar, G::Element>: FSerializable<KeyPairSize<G>>,
{
    fn serialize(&self) -> Array<u8, KeyPairSize<G>> {
        self.0.serialize()
    }

    fn deserialize(buffer: Array<u8, KeyPairSize<G>>) -> Result<Self, SerHyError> {
        let product = Pair::<G::Scalar, G::Element>::deserialize(buffer)?;
        Ok(KeyPair(product))
    }
}

// FIXME: elgamal really should be a product
// type ElGamal_<G> = Product<<G as CryptoGroup>::Element, U2>;
// type ElGamalSize2<G> = <ElGamal_<G> as Size>::SizeType;

#[derive(Debug, Clone)]
pub struct ElGamal<G: CryptoGroup>(pub Pair<G::Element, G::Element>);

impl<G: CryptoGroup> ElGamal<G> {
    pub fn new(gr: G::Element, mhr: G::Element) -> Self {
        ElGamal(Pair(gr, mhr))
    }

    pub fn gr(&self) -> &G::Element {
        &(self.0).0
    }

    pub fn mhr(&self) -> &G::Element {
        &(self.0).1
    }
}

type ElGamalSize<G> =
    <Pair<<G as CryptoGroup>::Element, <G as CryptoGroup>::Element> as Size>::SizeType;
impl<G: CryptoGroup> Size for ElGamal<G>
where
    Pair<G::Element, G::Element>: Size,
{
    type SizeType = ElGamalSize<G>;
}

impl<G: CryptoGroup> FSerializable<ElGamalSize<G>> for ElGamal<G>
where
    Pair<G::Element, G::Element>: Size,
    Pair<G::Element, G::Element>: FSerializable<ElGamalSize<G>>,
{
    fn serialize(&self) -> Array<u8, ElGamalSize<G>> {
        self.0.serialize()
    }

    fn deserialize(buffer: Array<u8, ElGamalSize<G>>) -> Result<Self, SerHyError> {
        let product = Pair::<G::Element, G::Element>::deserialize(buffer)?;
        Ok(ElGamal(product))
    }
}

// --- Encryptable/Decryptable Trait Implementations ---

impl<G: CryptoGroup> Encryptable<G, ElGamal<G>> for G::Element {
    fn encrypt(&self, key: &KeyPair<G>) -> ElGamal<G> {
        let mut rng = rng::DefaultRng;
        let r_scalar = G::Scalar::random(&mut rng);
        let gr = G::generator().scalar_mul(&r_scalar);
        let y_pow_r = key.pkey().scalar_mul(&r_scalar); // Use key.pkey()
        let mhr = self.add_element(&y_pow_r);
        ElGamal::<G>::new(gr, mhr)
    }
}

impl<G: CryptoGroup> Decryptable<G, G::Element> for ElGamal<G> {
    fn decrypt(&self, key: &KeyPair<G>) -> G::Element {
        let gr_pow_x = self.gr().scalar_mul(key.skey()); // Use self.gr() and key.skey()
        let decrypted_element = self.mhr().add_element(&gr_pow_x.negate_element()); // Use self.mhr()
        decrypted_element
    }
}
// --- End Trait Implementations ---

// --- ElGamalN (Ciphertext for multiple elements) ---

type ElGamalN_<G, LenType> = Product<ElGamal<G>, LenType>;
type ElGamalNSize<G, LenType> = <ElGamalN_<G, LenType> as Size>::SizeType;

pub struct ElGamalN<G, LenType>(pub Product<ElGamal<G>, LenType>)
where
    G: CryptoGroup,
    LenType: ArraySize;

impl<G, LenType> ElGamalN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
{
    pub fn new(ciphertexts: Product<ElGamal<G>, LenType>) -> Self {
        ElGamalN(ciphertexts)
    }
}

impl<G, LenType> Size for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    ElGamal<G>: Size,
    <ElGamal<G> as Size>::SizeType: CoreMul<LenType>,
    Prod<<ElGamal<G> as Size>::SizeType, LenType>: ArraySize,
{
    type SizeType = Prod<<ElGamal<G> as Size>::SizeType, LenType>;
}

impl<G, LenType> FSerializable<Prod<<ElGamal<G> as Size>::SizeType, LenType>>
    for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    ElGamal<G>: Size + FSerializable<<ElGamal<G> as Size>::SizeType>,
    <ElGamal<G> as Size>::SizeType: CoreMul<LenType>,
    Prod<<ElGamal<G> as Size>::SizeType, LenType>: ArraySize,
{
    fn serialize(&self) -> Array<u8, Prod<<ElGamal<G> as Size>::SizeType, LenType>> {
        self.0.serialize()
    }

    fn deserialize(
        buffer: Array<u8, Prod<<ElGamal<G> as Size>::SizeType, LenType>>,
    ) -> Result<Self, SerHyError> {
        Ok(ElGamalN(Product::deserialize(buffer)?))
    }
}

// --- Encryptable/Decryptable Trait Implementations for N-types ---
impl<G, LenType> Encryptable<G, ElGamalN<G, LenType>> for ElementN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    G::Element: Clone + Size,
    G::Scalar: Clone + Size,
{
    fn encrypt(&self, key: &KeyPair<G>) -> ElGamalN<G, LenType> {
        let encrypted = self.0.map(|element| element.encrypt(key));

        ElGamalN::new(encrypted)
        
    }
}

impl<G, LenType> Decryptable<G, ElementN<G, LenType>> for ElGamalN<G, LenType>
where
    G: CryptoGroup,
    LenType: ArraySize,
    ElGamal<G>: Clone,
{
    fn decrypt(&self, key: &KeyPair<G>) -> ElementN<G, LenType> {
        let decrypted = self.0 .0.clone().map(|ciphertext| ciphertext.decrypt(key));
        ElementN::<G, LenType>::new(Product(decrypted))
    }
}

// --- End N-type Trait Implementations ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::RistrettoScalar;
    use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement};
    use hybrid_array::typenum::Unsigned;
    use hybrid_array::typenum::{U2, U3};
    use std::array;

    #[test]
    fn test_keypair_hybrid_serialization() {
        let keypair = KeyPair::<Ristretto255Group>::new();
        let serialized = keypair.serialize();
        let deserialized = KeyPair::<Ristretto255Group>::deserialize(serialized).unwrap();
        assert_eq!(keypair.pkey(), deserialized.pkey());
        assert_eq!(keypair.skey(), deserialized.skey());
    }

    #[test]
    fn test_elgamal_hybrid_serialization_and_decryption() {
        let keypair = KeyPair::<Ristretto255Group>::new();
        let message = RistrettoElement::new(curve25519_dalek::ristretto::RistrettoPoint::random(
            &mut rng::DefaultRng,
        ));

        let ciphertext: ElGamal<Ristretto255Group> = message.encrypt(&keypair);
        let serialized_ct = ciphertext.serialize();
        let deserialized_ct = ElGamal::<Ristretto255Group>::deserialize(serialized_ct).unwrap();

        assert_eq!(ciphertext.gr(), deserialized_ct.gr());
        assert_eq!(ciphertext.mhr(), deserialized_ct.mhr());

        let decrypted_message: RistrettoElement = deserialized_ct.decrypt(&keypair);
        assert_eq!(message, decrypted_message);
    }

    #[test]
    fn test_elgamal_n_hybrid_serialization_and_decryption() {
        let keypair = KeyPair::<Ristretto255Group>::new();

        let messages_array: [RistrettoElement; U3::USIZE] = array::from_fn(|_| {
            RistrettoElement::new(curve25519_dalek::ristretto::RistrettoPoint::random(
                &mut rng::DefaultRng,
            ))
        });
        let elements_3 =
            Product(Array::<RistrettoElement, U3>::from(messages_array.clone()));
        let messages_n = ElementN::<Ristretto255Group, U3>::new(elements_3);

        let encrypted_n: ElGamalN<Ristretto255Group, U3> = messages_n.encrypt(&keypair);

        let serialized_en = encrypted_n.serialize();
        let deserialized_en =
            ElGamalN::<Ristretto255Group, U3>::deserialize(serialized_en).unwrap();

        let decrypted_n: ElementN<Ristretto255Group, U3> = deserialized_en.decrypt(&keypair);

        for i in 0..U3::USIZE {
            assert_eq!(
                messages_array[i],
                decrypted_n.0 .0.as_slice()[i]
            );
        }
    }

    #[test]
    fn test_elgamal_product_encryption() {
        let keypair = KeyPair::<Ristretto255Group>::new();

        let messages_array: [RistrettoElement; U3::USIZE] = array::from_fn(|_| {
            RistrettoElement::new(curve25519_dalek::ristretto::RistrettoPoint::random(
                &mut rng::DefaultRng,
            ))
        });
        let elements_3 =
            Product(Array::<RistrettoElement, U3>::from(messages_array.clone()));
        
        // encrypt using product operations

        let messages = elements_3.map(|e| {
            Product::<RistrettoElement, U2>(Array::from([RistrettoElement::identity(), e.clone()]))
        });

        let rs: Array<Product<RistrettoScalar, U2>, U3> = Array::from_fn(|_| {
            let mut rng = rng::DefaultRng;
            let r = RistrettoScalar::random(&mut rng);
            Product::<RistrettoScalar, U2>::uniform(&r)
        });
        let rs = Product(rs);
        
        let g = Ristretto255Group::generator();
        let gh = Product::<RistrettoElement, U2>(Array::from([g, keypair.pkey().clone()]));
        let ghs: Product<Product<RistrettoElement, U2>, U3> = Product::uniform(&gh);
        let raised = ghs.scalar_mul(&rs);

        let ms = raised.add_element(&messages);

        let egs = ms.map(|e| ElGamal::<Ristretto255Group>::new(e.0[0].clone(), e.0[1].clone()));
        let egs = ElGamalN(egs);

        // decrypt normally
        
        let decrypted_n: ElementN<Ristretto255Group, U3> = egs.decrypt(&keypair);

        for i in 0..U3::USIZE {
            assert_eq!(
                messages_array[i],
                decrypted_n.0 .0.as_slice()[i]
            );
        }
    }
}
