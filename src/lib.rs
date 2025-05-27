#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![allow(dead_code)]

// Core Abstractions & Utilities
pub mod traits;
pub mod serialization; // Was already pub
pub mod utils;

// Concrete Implementations & Schemes
pub mod groups;
pub mod elgamal; // Changed from private to pub
pub mod zkp; // Was already pub

// pub mod arithmetic; // Correctly remains removed/commented
