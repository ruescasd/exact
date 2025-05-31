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
pub mod elgamal; // Uncommented
pub mod groups; // Uncommented
pub mod zkp;

// pub mod arithmetic; // Correctly remains removed/commented


use hybrid_array::{ArraySize, typenum::{Prod, U2, U32}};
use core::ops::{Mul as CoreMul};

pub trait MySize {
    type SizeType: ArraySize;
}

#[derive(Debug)]
pub struct MyProduct<T, NLen: ArraySize>(core::marker::PhantomData<(T, NLen)>);

impl<T, NLen> MySize for MyProduct<T, NLen>
where
    T: MySize,
    NLen: ArraySize,
    T::SizeType: CoreMul<NLen>,
    Prod<T::SizeType, NLen>: ArraySize,
{
    type SizeType = Prod<T::SizeType, NLen>;
}

#[derive(Debug)]
pub struct MockItem;
impl MySize for MockItem {
    type SizeType = U32;
}

#[derive(Debug)]
pub struct TestProof(MyProduct<MockItem, U2>);

impl MySize for TestProof
where
    U32: CoreMul<U2>,
    Prod<U32, U2>: ArraySize,
    MyProduct<MockItem, U2>: MySize<SizeType = Prod<U32, U2>>,
{
    type SizeType = <MyProduct<MockItem, U2> as MySize>::SizeType;
}

fn main() {
    let _size: <TestProof as MySize>::SizeType;
    println!("MRE: TestProof size resolution attempted.");
}