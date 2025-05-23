// #![feature(adt_const_params)] // Not strictly needed for usize, but good if types were const params

pub trait Size {
    const SIZE: usize;
}

pub trait Parseable<const LEN: usize>: Sized {
    fn parse(bytes: [u8; LEN]) -> Self;
    fn write(&self) -> [u8; LEN];
}

pub struct Pa<T1, T2>
where
    T1: Size,
    T2: Size,
{
    pub a: T1,
    pub b: T2,
}
impl<T1, T2> Size for Pa<T1, T2>
where
    T1: Size,
    T2: Size,
{
    // const SIZE: usize = T1::SIZE + T2::SIZE;
    const SIZE: usize = T1::SIZE + T2::SIZE;
}

#[derive(Debug)]
pub struct Pair<T1, T2>
where
    T1: Size,
    T2: Size,
    // [(); T1::SIZE + T2::SIZE]: Sized,
{
    pub a: T1,
    pub b: T2,
}

impl<T1, T2> Size for Pair<T1, T2>
where
    T1: Size,
    T2: Size,
    // [(); T1::SIZE + T2::SIZE]: Sized,
{
    const SIZE: usize = T1::SIZE + T2::SIZE;
}

// Pair<T1, T2> is Parseable with the length T1::SIZE + T2::SIZE
impl<T1, T2> Parseable<{ T1::SIZE + T2::SIZE }> for Pair<T1, T2>
where
    // T1 and T2 must be Size (to get their ::SIZE for the const generic arg above)
    // and also Parseable with their respective sizes.
    T1: Size + Parseable<{ T1::SIZE }>,
    T2: Size + Parseable<{ T2::SIZE }>,
    // This bound is CRITICAL: it ensures that {T1::SIZE + T2::SIZE}
    // is a valid const expression for an array length/const generic argument.
    [(); T1::SIZE + T2::SIZE]: Sized,
    // These bounds are needed for split_at and try_into to work with fixed array types.
    [(); T1::SIZE]: Sized,
    [(); T2::SIZE]: Sized,
{
    // The trait's LEN parameter is {T1::SIZE + T2::SIZE} for this impl.
    fn parse(bytes: [u8; T1::SIZE + T2::SIZE]) -> Self {
        let (bytes_t1, rest) = bytes.split_at(T1::SIZE);
        let (bytes_t2, _ /*empty_if_correct*/) = rest.split_at(T2::SIZE);

        // Call parse for T1, which expects [u8; T1::SIZE]
        let field1_val = T1::parse(bytes_t1.try_into().expect("slice1 wrong len"));
        // Call parse for T2, which expects [u8; T2::SIZE]
        let field2_val = T2::parse(bytes_t2.try_into().expect("slice2 wrong len"));

        Pair {
            a: field1_val,
            b: field2_val,
        }
    }

    fn write(&self) -> [u8; T1::SIZE + T2::SIZE] {
        let mut bytes = [0u8; T1::SIZE + T2::SIZE];
        let (bytes_t1, rest) = bytes.split_at_mut(T1::SIZE);
        let (bytes_t2, _ /*empty_if_correct*/) = rest.split_at_mut(T2::SIZE);

        bytes_t1.copy_from_slice(&self.a.write());
        bytes_t2.copy_from_slice(&self.b.write());

        bytes
    }
}
