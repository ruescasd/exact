use crate::arithmetic::{Element, Exponent};
use crate::serialization::{Pair, Size, FSerializable};

// Imports for the prove function (and verify)
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants as dalek_constants;
use rand::thread_rng; // For prove
use sha3::{Digest, Sha512};


// Internal structure for Proof, using Pair
type Proof_ = Pair<Element, Exponent>;

/// Represents a Schnorr proof of knowledge of an exponent.
/// Contains a commitment 't' (an Element) and a response 's' (an Exponent).
#[derive(Debug)]
pub struct Proof(Proof_);

impl Proof {
    /// Constructs a new Proof from its constituent parts.
    pub fn new(t: Element, s: Exponent) -> Self {
        Proof(Pair { fst: t, snd: s })
    }

    /// Returns the commitment 't' of the proof.
    pub fn t(&self) -> Element {
        self.0.fst.clone()
    }

    /// Returns the response 's' of the proof.
    pub fn s(&self) -> Exponent {
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

pub fn prove(secret_x: &Exponent, public_y: &Element) -> Proof {
    let mut rng = thread_rng();
    let v_scalar = Scalar::random(&mut rng);

    // t = G^v
    let t_point = RistrettoPoint::mul_base(&v_scalar);
    let t_element = Element::new(t_point);

    // Challenge c = H(G_bytes, Y_bytes, t_bytes)
    let mut hasher = Sha512::new();
    hasher.update(dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()); // G
    hasher.update(public_y.write_bytes()); // Y
    hasher.update(t_element.write_bytes()); // t
    
    let hash_output = hasher.finalize();
    let c_scalar = Scalar::from_hash::<Sha512>(hash_output);

    // Response s = v + c*x
    let s_scalar = v_scalar + c_scalar * secret_x.0; // secret_x.0 to access inner Scalar
    let s_exponent = Exponent::new(s_scalar);

    Proof::new(t_element, s_exponent)
}

pub fn verify(public_y: &Element, proof: &Proof) -> bool {
    let t_element = proof.t();
    let s_exponent = proof.s();

    // Recompute challenge c = H(G_bytes, Y_bytes, t_bytes)
    let mut hasher = Sha512::new();
    hasher.update(dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes()); // G
    hasher.update(public_y.write_bytes()); // Y
    hasher.update(t_element.write_bytes()); // t
    
    let hash_output = hasher.finalize();
    let c_scalar = Scalar::from_hash::<Sha512>(hash_output);

    // Check: G^s == t + Y^c
    // LHS: G^s
    let g_s = RistrettoPoint::mul_base(&s_exponent.0); // s_exponent.0 to access inner Scalar

    // RHS: t + Y^c
    // Y^c is public_y.0 * c_scalar
    // t is t_element.0
    let y_c = public_y.0 * c_scalar;
    let t_plus_y_c = t_element.0 + y_c;

    g_s == t_plus_y_c
}

#[cfg(test)]
mod tests {
    use super::*; // To access Proof, prove, verify
    use crate::arithmetic::{Element, Exponent}; // For constructing test data
    use crate::serialization::{FSerializable, Size}; // For serialization tests
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::thread_rng;

    #[test]
    fn test_schnorr_proof_valid() {
        let mut rng = thread_rng();
        let secret_x_scalar = Scalar::random(&mut rng);
        let secret_x = Exponent::new(secret_x_scalar);
        
        let public_y_point = RistrettoPoint::mul_base(&secret_x_scalar);
        let public_y = Element::new(public_y_point);

        let proof = prove(&secret_x, &public_y);
        assert!(verify(&public_y, &proof), "Verification of a valid proof should succeed");
    }

    #[test]
    fn test_schnorr_proof_serialization() {
        let mut rng = thread_rng();
        let secret_x_scalar = Scalar::random(&mut rng);
        let secret_x = Exponent::new(secret_x_scalar);
        let public_y_point = RistrettoPoint::mul_base(&secret_x_scalar);
        let public_y = Element::new(public_y_point);

        let proof = prove(&secret_x, &public_y);
        
        let proof_bytes = proof.write_bytes();
        assert_eq!(proof_bytes.len(), Proof::SIZE);

        let parsed_proof = Proof::read_bytes(proof_bytes);
        
        // Verify that the parsed proof is also valid
        assert!(verify(&public_y, &parsed_proof), "Verification of a parsed valid proof should succeed");
        // Optionally, compare fields if Proof derives PartialEq (it doesn't currently)
        // For now, re-verification is a good check.
        assert_eq!(proof.t().write_bytes(), parsed_proof.t().write_bytes());
        assert_eq!(proof.s().write_bytes(), parsed_proof.s().write_bytes());
    }

    #[test]
    fn test_schnorr_proof_invalid_tampered_s() {
        let mut rng = thread_rng();
        let secret_x_scalar = Scalar::random(&mut rng);
        let secret_x = Exponent::new(secret_x_scalar);
        
        let public_y_point = RistrettoPoint::mul_base(&secret_x_scalar);
        let public_y = Element::new(public_y_point);

        let proof = prove(&secret_x, &public_y);

        // Tamper with s
        let original_s_scalar = proof.s().0; // Access inner Scalar
        let tampered_s_scalar = original_s_scalar + Scalar::ONE; // Add one to make it different
        let tampered_s_exponent = Exponent::new(tampered_s_scalar);
        
        let tampered_proof = Proof::new(proof.t(), tampered_s_exponent);

        assert!(!verify(&public_y, &tampered_proof), "Verification of a proof with tampered 's' should fail");
    }
}
