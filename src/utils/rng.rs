//! Centralized random number generation utilities.

// Re-exports `rand::rngs::OsRng` as the default cryptographically secure random number
// generator (CSPRNG) for this library.
//
// All cryptographic operations requiring randomness should default to using this
// unless a specific RNG instance is explicitly passed (for testing or other reasons).
pub use rand::rngs::OsRng; // Changed from thread_rng

// We could also add a wrapper function if more complex default setup was ever needed:
// use rand::{CryptoRng, RngCore};
// pub fn default_csprng() -> impl RngCore + CryptoRng {
//     OsRng
// }
