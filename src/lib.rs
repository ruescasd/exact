#![feature(generic_const_exprs)]
#![feature(adt_const_params)]
#![feature(generic_arg_infer)]
// #![feature(min_generic_const_args)]
// #![feature(inherent_associated_types)]
#![allow(incomplete_features)]
#![allow(dead_code)]

// Core Abstractions & Utilities
pub mod serialization; // Was already pub
pub mod traits;
pub mod utils;

// Concrete Implementations & Schemes
pub mod elgamal; // Changed from private to pub
pub mod groups;
pub mod zkp; // Was already pub

// pub mod arithmetic; // Correctly remains removed/commented
