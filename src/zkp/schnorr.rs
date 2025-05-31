use crate::serialization_hybrid::{self, FSerializable, Size};
use crate::traits::element::GroupElement;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;

use crate::utils::rng;

#[derive(Debug)]
pub struct Proof<G: CryptoGroup>(serialization_hybrid::Pair<G::Element, G::Scalar>);

impl<G: CryptoGroup> Proof<G> {
    /// Constructs a new Proof from its constituent parts.
    pub fn new(t: G::Element, s: G::Scalar) -> Self {
        Proof(serialization_hybrid::Pair(t, s))
    }

    /// Returns the commitment 't' of the proof.
    pub fn commitment(&self) -> &G::Element {
        &self.0.0
    }

    /// Returns the response 's' of the proof.
    pub fn response(&self) -> &G::Scalar {
        &self.0.1
    }
}

type SchnorrProof_<G> = serialization_hybrid::Pair<<G as CryptoGroup>::Element, <G as CryptoGroup>::Scalar>;
type SchnorrProofSize<G> = <SchnorrProof_<G> as Size>::SizeType;

impl<G: CryptoGroup> Size for Proof<G>
where
    SchnorrProof_<G>: Size,
{
    type SizeType = SchnorrProofSize<G>;
}

impl<G: CryptoGroup> FSerializable<SchnorrProofSize<G>> for Proof<G>
where
    SchnorrProof_<G>: Size,
    SchnorrProof_<G>: FSerializable<SchnorrProofSize<G>>,
{
    fn serialize(&self) -> hybrid_array::Array<u8, SchnorrProofSize<G>> {
        self.0.serialize()
    }

    fn deserialize(
        bytes: hybrid_array::Array<u8, SchnorrProofSize<G>>,
    ) -> Result<Self, crate::serialization_hybrid::Error> {
        let pair = SchnorrProof_::<G>::deserialize(bytes);
        Ok(Proof(pair?))
    }
}

pub fn prove<G: CryptoGroup>(secret_x: &G::Scalar, public_y: &G::Element) -> Proof<G>
where
    G::Element: Size + FSerializable<<G::Element as Size>::SizeType> + Clone,
    G::Scalar: Clone,
{
    let mut rng = rng::OsRng;
    let v_scalar = G::Scalar::random(&mut rng);

    let t_element = G::generator().scalar_mul(&v_scalar);

    let g_bytes = G::generator().serialize();
    let y_bytes = public_y.serialize();
    let t_bytes = t_element.serialize();

    let c_scalar = G::hash_to_scalar(&[g_bytes.as_slice(), y_bytes.as_slice(), t_bytes.as_slice()]);

    let s_scalar = v_scalar.add(&c_scalar.mul(secret_x));

    Proof::<G>::new(t_element, s_scalar)
}

pub fn verify<G: CryptoGroup>(public_y: &G::Element, proof: &Proof<G>) -> bool
where
    G::Element: Size + FSerializable<<G::Element as Size>::SizeType> + PartialEq + Clone,
    G::Scalar: Clone,
{
    let t_element = proof.commitment();
    let s_scalar = proof.response();

    let g_bytes = G::generator().serialize();
    let y_bytes = public_y.serialize();
    let t_bytes = t_element.serialize();

    let c_scalar = G::hash_to_scalar(&[g_bytes.as_slice(), y_bytes.as_slice(), t_bytes.as_slice()]);

    let g_s = G::generator().scalar_mul(&s_scalar);
    let y_c = public_y.scalar_mul(&c_scalar);
    let t_plus_y_c = t_element.add_element(&y_c);

    g_s == t_plus_y_c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement, RistrettoScalar};
    use hybrid_array::typenum::Unsigned;
    use crate::serialization_hybrid::FSerializable;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar as DalekScalar;
    use crate::utils::rng;

    #[test]
    fn test_schnorr_proof_valid() {
        let mut rng = rng::OsRng;
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
        let mut rng = rng::OsRng;
        let secret_x_dalek = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek);
        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove::<Ristretto255Group>(&secret_x, &public_y);

        let proof_bytes = proof.serialize();
        assert_eq!(proof_bytes.len(), <Proof::<Ristretto255Group> as Size>::SizeType::to_usize());

        let parsed_proof_result = Proof::<Ristretto255Group>::deserialize(proof_bytes);
        assert!(parsed_proof_result.is_ok());
        let parsed_proof = parsed_proof_result.unwrap();

        assert!(
            verify::<Ristretto255Group>(&public_y, &parsed_proof),
            "Verification of a parsed valid proof should succeed"
        );
        
        assert_eq!(proof.commitment(), parsed_proof.commitment());
        assert_eq!(proof.response(), parsed_proof.response());
    }

    #[test]
    fn test_schnorr_proof_invalid_tampered_s() {
        let mut rng = rng::OsRng;
        let secret_x_dalek = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek);

        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove::<Ristretto255Group>(&secret_x, &public_y);

        let original_s_dalek = proof.response().0;
        let tampered_s_dalek = original_s_dalek + DalekScalar::ONE;
        let tampered_s_ristretto = RistrettoScalar::new(tampered_s_dalek);

        let tampered_proof =
            Proof::<Ristretto255Group>::new(proof.commitment().clone(), tampered_s_ristretto);

        assert!(
            !verify::<Ristretto255Group>(&public_y, &tampered_proof),
            "Verification of a proof with tampered 's' should fail"
        );
    }
}
