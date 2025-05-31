#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![allow(dead_code)]

pub mod arithmetic;
mod elgamal; // elgamal remains private for now as per current structure, might need to be pub later
pub mod serialization; // Made public
pub mod zkp;
