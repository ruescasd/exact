// #![feature(adt_const_params)] // Not strictly needed for usize, but good if types were const params

pub trait Size {
    const SIZE: usize;
}

pub trait FSerializable<const LEN: usize>: Sized {
    fn parse(bytes: [u8; LEN]) -> Self;
    fn write(&self) -> [u8; LEN];
}

pub struct Product<const LEN: usize, T: Size>(pub [T; LEN]);
impl<const LEN: usize, T: Size + FSerializable<{ T::SIZE }>> FSerializable<{ T::SIZE * LEN} > for Product<LEN, T> 
{
    fn parse(bytes: [u8; T::SIZE * LEN]) -> Self {
        // Convert to array by mapping chunks directly to T
        let arr: [T; LEN] = std::array::from_fn(|i| {
            let start = i * T::SIZE;
            let end = start + T::SIZE;
            let chunk = bytes[start..end].try_into().unwrap();
            T::parse(chunk)
        });
        Product(arr)
    }

    fn write(&self) -> [u8; T::SIZE * LEN] {
        let mut bytes = [0u8; T::SIZE * LEN];
        for i in 0..LEN {
            let start = i * T::SIZE;
            let end = start + T::SIZE;
            bytes[start..end].copy_from_slice(&self.0[i].write());
        }
        bytes
    }
}
impl<const LEN: usize, T: Size> Size for Product<LEN, T>
{
    const SIZE: usize = LEN * T::SIZE;
}
impl<const LEN: usize, T: Size> Product<LEN, T> {
    pub fn zip_with<U, F>(&self, other: &Product<LEN, T>, mut f: F) -> Product<LEN, U>
    where
        U: Size, // The resulting element type U must also be Size constrained
        F: FnMut(&T, &T) -> U, // The combining function
    {
        // We need to create an array [U; LEN].
        // std::array::from_fn is a convenient way to initialize an array
        // by calling a function for each index. (Requires Rust 1.63+)
        let result_array = std::array::from_fn(|i| {
            // Access elements from self.0 and other.0 at index i
            // and apply the combining function f
            f(&self.0[i], &other.0[i])
        });
        Product(result_array)
    }

    pub fn map<U, F>(&self, mut f: F) -> Product<LEN, U>
    where
        U: Size, // The resulting element type U must also be Size constrained
        F: FnMut(&T) -> U, // The mapping function
    {
        // We need to create an array [U; LEN].
        let result_array = std::array::from_fn(|i| f(&self.0[i]));
        
        Product(result_array)
    }
}

#[derive(Debug)]
pub struct Pair<T1, T2>
where
    T1: Size,
    T2: Size,
{
    pub fst: T1,
    pub snd: T2,
}

impl<T1, T2> Size for Pair<T1, T2>
where
    T1: Size,
    T2: Size,
{
    const SIZE: usize = T1::SIZE + T2::SIZE;
}

// Pair<T1, T2> is FSerializable with the length T1::SIZE + T2::SIZE
impl<T1, T2> FSerializable<{ T1::SIZE + T2::SIZE }> for Pair<T1, T2>
where
    T1: Size + FSerializable<{ T1::SIZE }>,
    T2: Size + FSerializable<{ T2::SIZE }>,
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
            fst: field1_val,
            snd: field2_val,
        }
    }

    fn write(&self) -> [u8; T1::SIZE + T2::SIZE] {
        let mut bytes = [0u8; T1::SIZE + T2::SIZE];
        let (bytes_t1, rest) = bytes.split_at_mut(T1::SIZE);
        let (bytes_t2, _ /*empty_if_correct*/) = rest.split_at_mut(T2::SIZE);

        bytes_t1.copy_from_slice(&self.fst.write());
        bytes_t2.copy_from_slice(&self.snd.write());

        bytes
    }
}
