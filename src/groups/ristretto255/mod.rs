pub mod element;
pub mod scalar;

pub use element::RistrettoElement;
pub use scalar::RistrettoScalar;

use crate::traits::group::CryptoGroup;

use crate::utils;

use curve25519_dalek::constants as dalek_constants;
use sha3::Sha3_512; // Added for RistrettoScalar::from_hash

/// Marker struct for the Ristretto255 group implementation.
#[derive(Debug, Clone)]
pub struct Ristretto255Group;

impl CryptoGroup for Ristretto255Group {
    // ElementSerializedSize and ScalarSerializedSize associated types are removed from CryptoGroup trait
    // Their definitions are removed from this impl block.

    type Element = RistrettoElement;
    type Scalar = RistrettoScalar;

    fn generator() -> Self::Element {
        RistrettoElement::new(dalek_constants::RISTRETTO_BASEPOINT_POINT)
    }

    fn hash_to_scalar(input_slices: &[&[u8]]) -> Self::Scalar {
        let mut hasher = utils::hash::new_default_hasher(); // Uses Sha3_512 by default
        utils::hash::update_hasher_with_slices(&mut hasher, input_slices);
        // RistrettoScalar::from_hash needs the concrete Digest type.
        // new_default_hasher() returns Sha3_512.
        RistrettoScalar::from_hash::<Sha3_512>(hasher)
    }
}
