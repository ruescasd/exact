pub mod element;
pub mod scalar;

pub use element::P256Element;
pub use scalar::P256Scalar;
use sha3::digest::generic_array::GenericArray;

use crate::traits::group::CryptoGroup;
use crate::utils;

use p256::{ProjectivePoint, Scalar as P256ScalarInternal, FieldBytes};
use p256::elliptic_curve::Field; // For P256ScalarInternal::random
use p256::elliptic_curve::ScalarPrimitive; // For converting bytes to scalar
use sha3::Digest;
use typenum::U32;
// use sha2::{Sha256, Digest}; // Using SHA-256 for hashing to scalar, as an example. P256 often uses SHA-256.

/// Marker struct for the P-256 group implementation.
#[derive(Debug, Clone)]
pub struct P256Group;

impl CryptoGroup for P256Group {
    type Element = P256Element;
    type Scalar = P256Scalar;

    fn generator() -> Self::Element {
        P256Element::new(ProjectivePoint::GENERATOR)
    }

    fn hash_to_scalar(input_slices: &[&[u8]]) -> Self::Scalar {
        // Using SHA-256 for hashing, then reducing modulo the group order.
        // This is a common way to produce a scalar from arbitrary data.
        // Note: p256 crate's Scalar::from_bytes_mod_order or similar should be used.
        // The `p256` crate's `Scalar` might not have a direct `from_hash` or `from_bytes_mod_order`
        // that takes a generic hasher. We'll hash to bytes first, then construct the scalar.

        let mut hasher = utils::hash::new_256_hasher();
        utils::hash::update_hasher_with_slices(&mut hasher, input_slices);
        let result: GenericArray<u8, U32> = hasher.finalize(); // This is GenericArray<u8, U32> for Sha256

        // Convert the hash output (FieldBytes) to P256ScalarInternal (p256::Scalar)
        // Convert the hash output (GenericArray from Sha256) to FieldBytes, then to ScalarPrimitive, then to Scalar
        let field_bytes = FieldBytes::from_slice(result.as_slice()); // result is GenericArray<u8, U32>
        // ScalarPrimitive::from_bytes returns CtOption, so unwrap (or handle error)
        // .into() converts ScalarPrimitive to Scalar (P256ScalarInternal)
        // This approach ensures the bytes are interpreted correctly as a scalar.
        let ct_scalar_primitive = ScalarPrimitive::from_bytes(field_bytes);
        let option_scalar_primitive: Option<ScalarPrimitive<p256::NistP256>> = ct_scalar_primitive.into(); // Convert CtOption to Option
        
        let scalar_primitive = option_scalar_primitive
            .ok_or("Failed to convert hash to scalar primitive (CtOption was None)") // Or handle more gracefully
            .unwrap(); // Panics on error
        let scalar_internal: P256ScalarInternal = scalar_primitive.into();
        
        P256Scalar::new(scalar_internal)
    }

    fn random_element() -> Self::Element {
        // There isn't a direct ProjectivePoint::random() in `p256` like in `curve25519-dalek`.
        // A common way is to generate a random scalar and multiply by the generator.
        let mut rng = utils::rng::DefaultRng;
        let random_scalar_internal = P256ScalarInternal::random(&mut rng);
        P256Element::new(ProjectivePoint::GENERATOR * random_scalar_internal)
    }

    fn random_exponent() -> Self::Scalar {
        let mut rng = utils::rng::DefaultRng;
        let random_scalar_internal = P256ScalarInternal::random(&mut rng);
        P256Scalar::new(random_scalar_internal)
    }
}

#[cfg(test)]
mod tests;
