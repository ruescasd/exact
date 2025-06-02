#![allow(dead_code)]

pub mod serialization_hybrid;
pub mod traits; 
pub mod utils;

pub mod elgamal;pub mod groups;
pub mod zkp;

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