use crate::groups::ristretto255::{RistrettoElement, RistrettoScalar};
use crate::serialization::{Pair, Product, Size, FSerializable};

// Imports for the prove function
use curve25519_dalek::scalar::Scalar; // Dalek's Scalar for raw scalar ops
use curve25519_dalek::ristretto::RistrettoPoint; // Dalek's RistrettoPoint for raw point ops
use rand::thread_rng;
use sha3::{Digest, Sha3_512};

/// Represents a Chaum-Pedersen proof of equality of discrete logarithms.
/// Internal structure: Pair(Product([t1, t2]), s)
/// t1, t2 are commitments (RistrettoElements)
/// s is the response (RistrettoScalar)
#[derive(Debug)]
pub struct CPProof(Pair<Product<2, RistrettoElement>, RistrettoScalar>);

impl CPProof {
    /// Constructs a new CPProof from its constituent parts.
    pub fn new(commitments: [RistrettoElement; 2], response: RistrettoScalar) -> Self {
        CPProof(Pair {
            fst: Product(commitments),
            snd: response,
        })
    }

    /// Returns the two commitments [t1, t2] of the proof.
    pub fn commitments(&self) -> [RistrettoElement; 2] {
        self.0.fst.0.clone()
    }

    /// Returns the response 's' of the proof.
    pub fn response(&self) -> RistrettoScalar {
        self.0.snd.clone()
    }
}

impl Size for CPProof {
    const SIZE: usize = Pair::<Product<2, RistrettoElement>, RistrettoScalar>::SIZE;
}

impl FSerializable<{ CPProof::SIZE }> for CPProof {
    fn read_bytes(bytes: [u8; CPProof::SIZE]) -> Self {
        CPProof(Pair::<Product<2, RistrettoElement>, RistrettoScalar>::read_bytes(bytes))
    }

    fn write_bytes(&self) -> [u8; CPProof::SIZE] {
        self.0.write_bytes()
    }
}

pub fn prove(
    secret_x: &RistrettoScalar,
    g1: &RistrettoElement,
    g2: &RistrettoElement,
    public_y1: &RistrettoElement,
    public_y2: &RistrettoElement,
) -> CPProof {
    let mut rng = thread_rng();
    let v_dalek_scalar = Scalar::random(&mut rng); // Random Dalek scalar for nonce v

    // Commitments
    // t1 = g1^v
    let t1_point = g1.0 * v_dalek_scalar; // g1.0 is RistrettoPoint
    let t1_element = RistrettoElement::new(t1_point);
    // t2 = g2^v
    let t2_point = g2.0 * v_dalek_scalar; // g2.0 is RistrettoPoint
    let t2_element = RistrettoElement::new(t2_point);

    // Challenge c = H(g1, g2, y1, y2, t1, t2)
    let mut hasher = Sha3_512::new();
    hasher.update(g1.write_bytes());
    hasher.update(g2.write_bytes());
    hasher.update(public_y1.write_bytes());
    hasher.update(public_y2.write_bytes());
    hasher.update(t1_element.write_bytes());
    hasher.update(t2_element.write_bytes());
    
    let c_dalek_scalar = Scalar::from_hash::<Sha3_512>(hasher);

    // Response s = v + c*x
    let s_dalek_scalar = v_dalek_scalar + c_dalek_scalar * secret_x.0; // secret_x.0 is Dalek Scalar
    let s_ristretto_scalar = RistrettoScalar::new(s_dalek_scalar);

    CPProof::new([t1_element, t2_element], s_ristretto_scalar)
}

pub fn verify(
    g1: &RistrettoElement,
    g2: &RistrettoElement,
    public_y1: &RistrettoElement,
    public_y2: &RistrettoElement,
    proof: &CPProof,
) -> bool {
    let commitments = proof.commitments();
    let t1_element = commitments[0].clone();
    let t2_element = commitments[1].clone();
    let s_ristretto_scalar = proof.response();

    // Recompute challenge c = H(g1, g2, y1, y2, t1, t2)
    let mut hasher = Sha3_512::new();
    hasher.update(g1.write_bytes());
    hasher.update(g2.write_bytes());
    hasher.update(public_y1.write_bytes());
    hasher.update(public_y2.write_bytes());
    hasher.update(t1_element.write_bytes());
    hasher.update(t2_element.write_bytes());

    let c_dalek_scalar = Scalar::from_hash::<Sha3_512>(hasher);

    // Check conditions:
    // 1. g1^s == t1 * y1^c  =>  g1.0 * s.0 == t1.0 + y1.0 * c
    let check1_lhs = g1.0 * s_ristretto_scalar.0; // s_ristretto_scalar.0 is Dalek Scalar
    let y1_c = public_y1.0 * c_dalek_scalar;    // public_y1.0 is RistrettoPoint
    let check1_rhs = t1_element.0 + y1_c; // t1_element.0 is RistrettoPoint
    
    let check1 = check1_lhs == check1_rhs;

    // 2. g2^s == t2 * y2^c  =>  g2.0 * s.0 == t2.0 + y2.0 * c
    let check2_lhs = g2.0 * s_ristretto_scalar.0;
    let y2_c = public_y2.0 * c_dalek_scalar;
    let check2_rhs = t2_element.0 + y2_c;

    let check2 = check2_lhs == check2_rhs;

    check1 && check2
}

#[cfg(test)]
mod tests {
    use super::*; // To access CPProof, prove, verify
    use crate::groups::ristretto255::{RistrettoElement, RistrettoScalar}; // Updated import
    use crate::serialization::{FSerializable, Size};
    use curve25519_dalek::scalar::Scalar; // Still needed for direct Dalek Scalar ops
    use curve25519_dalek::constants as dalek_constants; 
    use rand::thread_rng;

    // Helper to get a basepoint Element if not using a passed-in G
    fn get_basepoint_g() -> RistrettoElement { // Updated return type
        // RistrettoPoint is not directly imported in tests, use dalek_constants or full path.
        // Element::new is now RistrettoElement::new
        RistrettoElement::new(dalek_constants::RISTRETTO_BASEPOINT_POINT)
    }

    #[test]
    fn test_chaum_pedersen_proof_valid() {
        let mut rng = thread_rng();
        let secret_x_dalek_scalar = Scalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);

        let g1 = get_basepoint_g();
        let g2 = get_basepoint_g(); 

        let public_y1_point = g1.0 * secret_x_dalek_scalar;
        let public_y1 = RistrettoElement::new(public_y1_point);
        let public_y2_point = g2.0 * secret_x_dalek_scalar;
        let public_y2 = RistrettoElement::new(public_y2_point);

        let proof = prove(&secret_x, &g1, &g2, &public_y1, &public_y2);
        assert!(
            verify(&g1, &g2, &public_y1, &public_y2, &proof),
            "Verification of a valid Chaum-Pedersen proof should succeed"
        );
    }

    #[test]
    fn test_chaum_pedersen_proof_serialization() {
        let mut rng = thread_rng();
        let secret_x_dalek_scalar = Scalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);

        let g1 = get_basepoint_g();
        let g2 = get_basepoint_g();

        let public_y1 = RistrettoElement::new(g1.0 * secret_x_dalek_scalar);
        let public_y2 = RistrettoElement::new(g2.0 * secret_x_dalek_scalar);

        let proof = prove(&secret_x, &g1, &g2, &public_y1, &public_y2);
        
        let proof_bytes = proof.write_bytes();
        assert_eq!(proof_bytes.len(), CPProof::SIZE);

        let parsed_proof = CPProof::read_bytes(proof_bytes);
        
        assert!(
            verify(&g1, &g2, &public_y1, &public_y2, &parsed_proof),
            "Verification of a parsed valid Chaum-Pedersen proof should succeed"
        );
        
        let original_commitments = proof.commitments();
        let parsed_commitments = parsed_proof.commitments();
        assert_eq!(original_commitments[0].write_bytes(), parsed_commitments[0].write_bytes(), "t1 should match");
        assert_eq!(original_commitments[1].write_bytes(), parsed_commitments[1].write_bytes(), "t2 should match");
        assert_eq!(proof.response().write_bytes(), parsed_proof.response().write_bytes(), "s should match");
    }

    #[test]
    fn test_chaum_pedersen_proof_invalid_tampered_response() {
        let mut rng = thread_rng();
        let secret_x_dalek_scalar = Scalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);

        let g1 = get_basepoint_g();
        let g2 = get_basepoint_g();

        let public_y1 = RistrettoElement::new(g1.0 * secret_x_dalek_scalar);
        let public_y2 = RistrettoElement::new(g2.0 * secret_x_dalek_scalar);

        let proof = prove(&secret_x, &g1, &g2, &public_y1, &public_y2);

        let original_s_scalar = proof.response().0; 
        let tampered_s_dalek_scalar = original_s_scalar + Scalar::ONE;
        let tampered_s_ristretto_scalar = RistrettoScalar::new(tampered_s_dalek_scalar);
        
        let tampered_proof = CPProof::new(proof.commitments(), tampered_s_ristretto_scalar);

        assert!(
            !verify(&g1, &g2, &public_y1, &public_y2, &tampered_proof),
            "Verification of a Chaum-Pedersen proof with a tampered response 's' should fail"
        );
    }
}
