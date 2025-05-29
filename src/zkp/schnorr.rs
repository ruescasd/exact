use crate::serialization::{FSerializable, Pair, Size};
use crate::traits::element::GroupElement;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar; // Not directly used in Proof struct, but good for context // Not directly used in Proof struct, but good for context

// Imports for the prove function (and verify)
use rand::thread_rng; // For prove

// Internal structure for Proof, using Pair
// type Proof_<G: CryptoGroup> = Pair<G::Element, G::Scalar>; // Original comment, can be kept or removed

/// Represents a Schnorr proof of knowledge of an exponent.
/// Contains a commitment 't' (an Element) and a response 's' (an Exponent).
#[derive(Debug)]
pub struct Proof<G: CryptoGroup>(Pair<G::Element, G::Scalar>)
where
    // Simplified where clause matching KeyPair<G>
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:;

impl<G: CryptoGroup> Proof<G>
where
    // Simplified where clause matching KeyPair<G>
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    /// Constructs a new Proof from its constituent parts.
    pub fn new(t: G::Element, s: G::Scalar) -> Self {
        Proof(Pair { fst: t, snd: s })
    }

    /// Returns the commitment 't' of the proof.
    pub fn commitment(&self) -> G::Element {
        self.0.fst.clone()
    }

    /// Returns the response 's' of the proof.
    pub fn response(&self) -> G::Scalar {
        self.0.snd.clone()
    }
}

// Update Size for Proof<G> to match KeyPair<G> pattern
impl<G: CryptoGroup> Size for Proof<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    const SIZE: usize = G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE;
}

// Update FSerializable for Proof<G> to match KeyPair<G> pattern
impl<G: CryptoGroup> FSerializable<{ G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE }>
    for Proof<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
    Pair<G::Element, G::Scalar>:
        FSerializable<{ G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE }>,
{
    fn read_bytes(bytes: [u8; G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE]) -> Self {
        let pair = Pair::<G::Element, G::Scalar>::read_bytes(bytes);
        Proof(pair)
    }
    fn write_bytes(&self) -> [u8; G::ELEMENT_SERIALIZED_SIZE + G::SCALAR_SERIALIZED_SIZE] {
        self.0.write_bytes()
    }
}

pub fn prove<G: CryptoGroup>(secret_x: &G::Scalar, public_y: &G::Element) -> Proof<G>
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    let mut rng = thread_rng();
    let v_scalar = G::Scalar::random(&mut rng);

    let t_element = G::generator().scalar_mul(&v_scalar);

    let g_bytes = G::generator().write_bytes();
    let y_bytes = public_y.write_bytes();
    let t_bytes = t_element.write_bytes();

    let c_scalar = G::hash_to_scalar(&[g_bytes.as_ref(), y_bytes.as_ref(), t_bytes.as_ref()]);

    let s_scalar = v_scalar.add(&c_scalar.mul(secret_x));

    Proof::<G>::new(t_element, s_scalar)
}

pub fn verify<G: CryptoGroup>(public_y: &G::Element, proof: &Proof<G>) -> bool
where
    [(); G::ELEMENT_SERIALIZED_SIZE]:,
    [(); G::SCALAR_SERIALIZED_SIZE]:,
{
    let t_element = proof.commitment();
    let s_scalar = proof.response();

    let g_bytes = G::generator().write_bytes();
    let y_bytes = public_y.write_bytes();
    let t_bytes = t_element.write_bytes();

    let c_scalar = G::hash_to_scalar(&[g_bytes.as_ref(), y_bytes.as_ref(), t_bytes.as_ref()]);

    let g_s = G::generator().scalar_mul(&s_scalar);
    let y_c = public_y.scalar_mul(&c_scalar);
    let t_plus_y_c = t_element.add_element(&y_c);

    g_s == t_plus_y_c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement, RistrettoScalar};
    use crate::serialization::{FSerializable, Size};
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar as DalekScalar;
    use rand::thread_rng;

    #[test]
    fn test_schnorr_proof_valid() {
        let mut rng = thread_rng();
        let secret_x_dalek = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek);

        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove::<Ristretto255Group>(&secret_x, &public_y);
        assert!(
            verify::<Ristretto255Group>(&public_y, &proof),
            "Verification of a valid proof should succeed"
        );
    }

    #[test]
    fn test_schnorr_proof_serialization() {
        let mut rng = thread_rng();
        let secret_x_dalek = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek);
        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove::<Ristretto255Group>(&secret_x, &public_y);

        let proof_bytes = proof.write_bytes();
        assert_eq!(proof_bytes.len(), Proof::<Ristretto255Group>::SIZE);

        let parsed_proof = Proof::<Ristretto255Group>::read_bytes(proof_bytes);

        assert!(
            verify::<Ristretto255Group>(&public_y, &parsed_proof),
            "Verification of a parsed valid proof should succeed"
        );
        assert_eq!(
            proof.commitment().write_bytes(),
            parsed_proof.commitment().write_bytes()
        );
        assert_eq!(
            proof.response().write_bytes(),
            parsed_proof.response().write_bytes()
        );
    }

    #[test]
    fn test_schnorr_proof_invalid_tampered_s() {
        let mut rng = thread_rng();
        let secret_x_dalek = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek);

        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove::<Ristretto255Group>(&secret_x, &public_y);

        let original_s_dalek = proof.response().0;
        let tampered_s_dalek = original_s_dalek + DalekScalar::ONE;
        let tampered_s_ristretto = RistrettoScalar::new(tampered_s_dalek);

        let tampered_proof =
            Proof::<Ristretto255Group>::new(proof.commitment(), tampered_s_ristretto);

        assert!(
            !verify::<Ristretto255Group>(&public_y, &tampered_proof),
            "Verification of a proof with tampered 's' should fail"
        );
    }
}
