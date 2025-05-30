// #![feature(generic_const_exprs)]
// #![feature(adt_const_params)]
// #![feature(generic_arg_infer)]
// #![feature(min_generic_const_args)]
// #![feature(inherent_associated_types)]
#![allow(incomplete_features)] // This might be okay to keep, or remove if it causes issues.
#![allow(dead_code)]

// Core Abstractions & Utilities
// pub mod serialization; // Commented out due to generic_const_exprs errors
pub mod serialization_hybrid;
pub mod traits; // Uncommented
pub mod utils; // Keep utils for now, may be needed by serialization_hybrid or be independent

// Concrete Implementations & Schemes
// pub mod elgamal; // Commented out due to generic_const_exprs errors
// pub mod groups; // Commented out due to dependency on traits/serialization
// pub mod zkp; // Commented out due to generic_const_exprs errors

// pub mod arithmetic; // Correctly remains removed/commented
