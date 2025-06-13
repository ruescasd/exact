#![allow(dead_code)]

pub mod serialization_hybrid;
pub mod traits;
pub mod utils;

pub mod elgamal;
pub mod groups;
pub mod zkp;

pub use zkp::bit::benchmark_prove;


mod macro_test;