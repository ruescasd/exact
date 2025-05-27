use crate::groups::ristretto255::{RistrettoElement, RistrettoScalar};
use crate::serialization::{Pair, Size, FSerializable};

// Imports for the prove function (and verify)
// Note: curve25519_dalek::Scalar and RistrettoPoint are still used directly in prove/verify logic
// and in tests for direct scalar/point operations.
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants as dalek_constants;
use rand::thread_rng; // For prove
use sha3::{Digest, Sha3_512}; // Changed Sha512 to Sha3_512


// Internal structure for Proof, using Pair
type Proof_ = Pair<RistrettoElement, RistrettoScalar>;

/// Represents a Schnorr proof of knowledge of an exponent.
/// Contains a commitment 't' (an Element) and a response 's' (an Exponent).
#[derive(Debug)]
pub struct Proof(Proof_);

impl Proof {
    /// Constructs a new Proof from its constituent parts.
    pub fn new(t: RistrettoElement, s: RistrettoScalar) -> Self {
        Proof(Pair { fst: t, snd: s })
    }

    /// Returns the commitment 't' of the proof.
    pub fn commitment(&self) -> RistrettoElement {
        self.0.fst.clone()
    }

    /// Returns the response 's' of the proof.
    pub fn response(&self) -> RistrettoScalar {
        self.0.snd.clone()
    }
}

impl Size for Proof {
    const SIZE: usize = Proof_::SIZE;
}

impl FSerializable<{ Proof::SIZE }> for Proof {
    fn read_bytes(bytes: [u8; Proof::SIZE]) -> Self {
        Proof(Pair::read_bytes(bytes))
    }

    fn write_bytes(&self) -> [u8; Proof::SIZE] {
        self.0.write_bytes()
    }
}

pub fn prove(secret_x: &RistrettoScalar, public_y: &RistrettoElement) -> Proof {
    let mut rng = thread_rng();
    let v_scalar = Scalar::random(&mut rng); // This is a Dalek Scalar

    // t = G^v
    let t_point = RistrettoPoint::mul_base(&v_scalar); // Dalek RistrettoPoint
    let t_element = RistrettoElement::new(t_point);

    // Challenge c = H(G_bytes, Y_bytes, t_bytes)
    let mut hasher = Sha3_512::new();
    hasher.update(dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()); // G
    hasher.update(public_y.write_bytes()); // Y (RistrettoElement)
    hasher.update(t_element.write_bytes()); // t (RistrettoElement)
    
    let c_scalar = Scalar::from_hash::<Sha3_512>(hasher); // Dalek Scalar

    // Response s = v + c*x
    // secret_x.0 is the inner Dalek Scalar from RistrettoScalar
    let s_dalek_scalar = v_scalar + c_scalar * secret_x.0; 
    let s_ristretto_scalar = RistrettoScalar::new(s_dalek_scalar);

    Proof::new(t_element, s_ristretto_scalar)
}

pub fn verify(public_y: &RistrettoElement, proof: &Proof) -> bool {
    let t_element = proof.commitment(); // RistrettoElement
    let s_ristretto_scalar = proof.response(); // RistrettoScalar

    // Recompute challenge c = H(G_bytes, Y_bytes, t_bytes)
    let mut hasher = Sha3_512::new();
    hasher.update(dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()); // G
    hasher.update(public_y.write_bytes()); // Y (RistrettoElement)
    hasher.update(t_element.write_bytes()); // t (RistrettoElement)
    
    let c_scalar = Scalar::from_hash::<Sha3_512>(hasher); // Dalek Scalar

    // Check: G^s == t + Y^c
    // LHS: G^s
    // s_ristretto_scalar.0 is the inner Dalek Scalar
    let g_s = RistrettoPoint::mul_base(&s_ristretto_scalar.0); 

    // RHS: t + Y^c
    // public_y.0 is RistrettoPoint from RistrettoElement
    // t_element.0 is RistrettoPoint from RistrettoElement
    let y_c = public_y.0 * c_scalar;
    let t_plus_y_c = t_element.0 + y_c;

    g_s == t_plus_y_c
}

#[cfg(test)]
mod tests {
    use super::*; // To access Proof, prove, verify
    use crate::groups::ristretto255::{RistrettoElement, RistrettoScalar}; // Updated import
    use crate::serialization::{FSerializable, Size}; 
    use curve25519_dalek::scalar::Scalar; // Still needed for direct Dalek Scalar ops in tests
    use curve25519_dalek::ristretto::RistrettoPoint; // Still needed for direct Dalek Point ops in tests
    use rand::thread_rng;

    #[test]
    fn test_schnorr_proof_valid() {
        let mut rng = thread_rng();
        let secret_x_dalek_scalar = Scalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);
        
        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek_scalar);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove(&secret_x, &public_y);
        assert!(verify(&public_y, &proof), "Verification of a valid proof should succeed");
    }

    #[test]
    fn test_schnorr_proof_serialization() {
        let mut rng = thread_rng();
        let secret_x_dalek_scalar = Scalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);
        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek_scalar);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove(&secret_x, &public_y);
        
        let proof_bytes = proof.write_bytes();
        assert_eq!(proof_bytes.len(), Proof::SIZE);

        let parsed_proof = Proof::read_bytes(proof_bytes);
        
        assert!(verify(&public_y, &parsed_proof), "Verification of a parsed valid proof should succeed");
        assert_eq!(proof.commitment().write_bytes(), parsed_proof.commitment().write_bytes());
        assert_eq!(proof.response().write_bytes(), parsed_proof.response().write_bytes());
    }

    #[test]
    fn test_schnorr_proof_invalid_tampered_s() {
        let mut rng = thread_rng();
        let secret_x_dalek_scalar = Scalar::random(&mut rng);
        let secret_x = RistrettoScalar::new(secret_x_dalek_scalar);
        
        let public_y_point = RistrettoPoint::mul_base(&secret_x_dalek_scalar);
        let public_y = RistrettoElement::new(public_y_point);

        let proof = prove(&secret_x, &public_y);

        let original_s_scalar = proof.response().0; 
        let tampered_s_dalek_scalar = original_s_scalar + Scalar::ONE; 
        let tampered_s_ristretto_scalar = RistrettoScalar::new(tampered_s_dalek_scalar);
        
        let tampered_proof = Proof::new(proof.commitment(), tampered_s_ristretto_scalar);

        assert!(!verify(&public_y, &tampered_proof), "Verification of a proof with tampered 's' should fail");
    }
}
