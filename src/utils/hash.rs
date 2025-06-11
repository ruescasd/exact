use sha3::{Digest, Sha3_512, Sha3_256}; // Or your chosen default digest algorithm

/// Returns a new hasher instance of the library's default digest algorithm.
pub fn new_default_hasher() -> Sha3_512 {
    Sha3_512::new()
}

/// Used by p256:hash_to_scalar
pub fn new_256_hasher() -> Sha3_256 {
    Sha3_256::new()
}

/// Updates a given hasher with multiple byte slices.
/// This is a convenience function to avoid repeated `hasher.update()` calls.
pub fn update_hasher_with_slices(hasher: &mut impl Digest, data_slices: &[&[u8]]) {
    for slice in data_slices {
        hasher.update(slice);
    }
}
