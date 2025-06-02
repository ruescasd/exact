use crate::serialization_hybrid::{FSerializable, Pair, Product, Size};
use hybrid_array::typenum::{U2};
use hybrid_array::{Array};
use crate::traits::element::GroupElement;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::utils::rng;

#[derive(Debug)]
pub struct CPProof<G: CryptoGroup>(Pair<Product<G::Element, U2>, G::Scalar>);

impl<G: CryptoGroup> CPProof<G>
{
    pub fn new(c1: G::Element, c2: G::Element, response: G::Scalar) -> Self {
        CPProof(Pair(Product(Array([c1, c2])), response))
    }

    pub fn commitments(&self) -> &Array<G::Element, U2> {
        &self.0.0.0
    }

    pub fn response(&self) -> &G::Scalar {
        &self.0.1
    }
}

pub fn prove<G: CryptoGroup>(
    secret_x: &G::Scalar,
    g1: &G::Element,
    g2: &G::Element,
    public_y1: &G::Element,
    public_y2: &G::Element,
) -> CPProof<G>
where 
      G::Element: Size,
      G::Element: FSerializable<<G::Element as Size>::SizeType>,
{
    let mut rng = rng::DefaultRng;
    let v_scalar = G::Scalar::random(&mut rng);
    let t1_element = g1.scalar_mul(&v_scalar);
    let t2_element = g2.scalar_mul(&v_scalar);
    let g1_bytes = g1.serialize();
    let g2_bytes = g2.serialize();
    let y1_bytes = public_y1.serialize();
    let y2_bytes = public_y2.serialize();
    let t1_bytes = t1_element.serialize();
    let t2_bytes = t2_element.serialize();
    let c_scalar = G::hash_to_scalar(&[
        g1_bytes.as_ref(),
        g2_bytes.as_ref(),
        y1_bytes.as_ref(),
        y2_bytes.as_ref(),
        t1_bytes.as_ref(),
        t2_bytes.as_ref(),
    ]);
    let cx_scalar = c_scalar.mul(secret_x);
    let s_scalar = v_scalar.add(&cx_scalar);
    CPProof::<G>::new(t1_element, t2_element, s_scalar)
}

pub fn verify<G: CryptoGroup>(
    g1: &G::Element,
    g2: &G::Element,
    public_y1: &G::Element,
    public_y2: &G::Element,
    proof: &CPProof<G>,
) -> bool
      where 
      G::Element: Size + Eq + PartialEq,
      G::Element: FSerializable<<G::Element as Size>::SizeType>,
{
    let commitments = proof.commitments();
    let s_scalar = proof.response();
    let g1_bytes = g1.serialize();
    let g2_bytes = g2.serialize();
    let y1_bytes = public_y1.serialize();
    let y2_bytes = public_y2.serialize();
    let t1_bytes = commitments[0].serialize();
    let t2_bytes = commitments[1].serialize();
    let c_scalar = G::hash_to_scalar(&[
        g1_bytes.as_ref(),
        g2_bytes.as_ref(),
        y1_bytes.as_ref(),
        y2_bytes.as_ref(),
        t1_bytes.as_ref(),
        t2_bytes.as_ref(),
    ]);
    let g1_s = g1.scalar_mul(&s_scalar);
    let y1_c = public_y1.scalar_mul(&c_scalar);
    let t1_y1_c = commitments[0].add_element(&y1_c);
    let check1 = g1_s == t1_y1_c;
    let g2_s = g2.scalar_mul(&s_scalar);
    let y2_c = public_y2.scalar_mul(&c_scalar);
    let t2_y2_c = commitments[1].add_element(&y2_c);
    let check2 = g2_s == t2_y2_c;
    check1 && check2
}

type CommitmentProduct<G> = Product<<G as CryptoGroup>::Element, U2>;
type CPProof_<G> = Pair<CommitmentProduct<G>, <G as CryptoGroup>::Scalar>;
type CPProofSize<G> = <CPProof_<G> as Size>::SizeType;

impl<G: CryptoGroup> Size for CPProof<G> 
where CPProof_<G>: Size {
    type SizeType = CPProofSize<G>;
}

impl<G: CryptoGroup> FSerializable<CPProofSize<G>> for CPProof<G>
where 
    CPProof_<G>: Size,
    CPProof_<G>: FSerializable<CPProofSize<G>>,
{
    fn serialize(&self) -> Array<u8, CPProofSize<G>> {
        self.0.serialize()
    }

    fn deserialize(
        bytes: Array<u8, CPProofSize<G>>,
    ) -> Result<Self, crate::serialization_hybrid::Error> {
        let pair = CPProof_::<G>::deserialize(bytes);

        Ok(CPProof(pair?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement, RistrettoScalar};
    use hybrid_array::typenum::Unsigned;
    use curve25519_dalek::constants as dalek_constants;
    use curve25519_dalek::scalar::Scalar as DalekScalar;
    use crate::utils::rng;

    fn get_basepoint_g() -> RistrettoElement {
        RistrettoElement::new(dalek_constants::RISTRETTO_BASEPOINT_POINT)
    }

    #[test]
    fn test_chaum_pedersen_proof_valid() {
        let mut rng = rng::DefaultRng;
        let secret_x_dalek_scalar = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);
        let g1 = get_basepoint_g();
        let g2 = get_basepoint_g();
        let public_y1 = g1.scalar_mul(&secret_x);
        let public_y2 = g2.scalar_mul(&secret_x);
        let proof = prove::<Ristretto255Group>(&secret_x, &g1, &g2, &public_y1, &public_y2);
        assert!(
            verify::<Ristretto255Group>(&g1, &g2, &public_y1, &public_y2, &proof),
            "Verification of a valid Chaum-Pedersen proof should succeed"
        );
    }

    #[test]
    fn test_chaum_pedersen_proof_serialization() {
        let mut rng = rng::DefaultRng;
        let secret_x_dalek_scalar = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);
        let g1 = get_basepoint_g();
        let g2 = get_basepoint_g();
        let public_y1 = g1.scalar_mul(&secret_x);
        let public_y2 = g2.scalar_mul(&secret_x);
        let proof = prove::<Ristretto255Group>(&secret_x, &g1, &g2, &public_y1, &public_y2);        
        let proof_bytes = proof.serialize();

        assert_eq!(proof_bytes.len(), <CPProof::<Ristretto255Group> as Size>::SizeType::to_usize());
        
        let parsed_proof = CPProof::<Ristretto255Group>::deserialize(proof_bytes).unwrap();
        assert!(
            verify::<Ristretto255Group>(&g1, &g2, &public_y1, &public_y2, &parsed_proof),
            "Verification of a parsed valid Chaum-Pedersen proof should succeed"
        );
        let original_commitments = proof.commitments();
        let parsed_commitments = parsed_proof.commitments();
        assert_eq!(
            original_commitments[0].serialize(),
            parsed_commitments[0].serialize(),
            "t1 should match"
        );
        assert_eq!(
            original_commitments[1].serialize(),
            parsed_commitments[1].serialize(),
            "t2 should match"
        );
        assert_eq!(
            proof.response().serialize(),
            parsed_proof.response().serialize(),
            "s should match"
        );
    }

    #[test]
    fn test_chaum_pedersen_proof_invalid_tampered_response() {
        let mut rng = rng::DefaultRng;
        let secret_x_dalek_scalar = DalekScalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);
        let g1 = get_basepoint_g();
        let g2 = get_basepoint_g();
        let public_y1 = g1.scalar_mul(&secret_x);
        let public_y2 = g2.scalar_mul(&secret_x);
        let proof = prove::<Ristretto255Group>(&secret_x, &g1, &g2, &public_y1, &public_y2);
        let original_s_dalek = proof.response().0;
        let tampered_s_dalek_scalar = original_s_dalek + DalekScalar::ONE;
        let tampered_s_ristretto_scalar = RistrettoScalar::new(tampered_s_dalek_scalar);
        let tampered_proof =
            CPProof::<Ristretto255Group>::new(proof.commitments().0[0].clone(), proof.commitments().0[1].clone(), tampered_s_ristretto_scalar);
        assert!(
            !verify::<Ristretto255Group>(&g1, &g2, &public_y1, &public_y2, &tampered_proof),
            "Verification of a Chaum-Pedersen proof with a tampered response 's' should fail"
        );
    }
}
