/// Re-exports `rand::thread_rng` as the default cryptographically secure random number
/// generator (CSPRNG) for this library.
///
/// All cryptographic operations requiring randomness should default to using this
/// unless a specific RNG instance is explicitly passed (for testing or other reasons).
pub use rand::thread_rng;

// We could also add a wrapper function if more complex default setup was ever needed:
// use rand::{CryptoRng, RngCore};
// pub fn default_csprng() -> impl RngCore + CryptoRng {
//     thread_rng()
// }
