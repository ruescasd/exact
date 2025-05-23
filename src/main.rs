#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![allow(dead_code)]
// #![feature(adt_const_params)] // Not strictly needed for usize, but good if types were const params

// --- MySized Trait (unchanged) ---
trait Size {
    const SIZE: usize;
}

// --- REVISED Parseable Trait: Generic directly over the const size ---
trait Parseable<const LEN: usize>: Sized {
    fn parse(bytes: [u8; LEN]) -> Self;
}

// --- Leaf Types ---
#[derive(Debug)]
struct TypeFixedU16;
impl Size for TypeFixedU16 { const SIZE: usize = 2; }

// TypeFixedU16 is Parseable with its own SIZE
impl Parseable<{TypeFixedU16::SIZE}> for TypeFixedU16 {
    fn parse(bytes: [u8; TypeFixedU16::SIZE]) -> Self { // LEN = TypeFixedU16::SIZE
        println!("Parsing TypeFixedU16 (size {}) from bytes: {:?}", TypeFixedU16::SIZE, bytes);
        TypeFixedU16
    }
}

#[derive(Debug)]
struct TypeFixedU32;
impl Size for TypeFixedU32 { const SIZE: usize = 4; }

// TypeFixedU32 is Parseable with its own SIZE
impl Parseable<{TypeFixedU32::SIZE}> for TypeFixedU32 {
    fn parse(bytes: [u8; TypeFixedU32::SIZE]) -> Self { // LEN = TypeFixedU32::SIZE
        println!("Parsing TypeFixedU32 (size {}) from bytes: {:?}", TypeFixedU32::SIZE, bytes);
        TypeFixedU32
    }
}

// --- Pair structure (MySized impl unchanged) ---
#[derive(Debug)]
struct Pair<T1, T2>
where
    T1: Size,
    T2: Size,
    [(); T1::SIZE + T2::SIZE]: Sized,
{
    _a: T1,
    _b: T2,
}

impl<T1, T2> Size for Pair<T1, T2>
where
    T1: Size,
    T2: Size,
    [(); T1::SIZE + T2::SIZE]: Sized,
{
    const SIZE: usize = T1::SIZE + T2::SIZE;
}

// --- REVISED Parseable impl for Pair: Uses direct const generic for size ---
// Pair<T1, T2> is Parseable with the length T1::SIZE + T2::SIZE
impl<T1, T2> Parseable<{T1::SIZE + T2::SIZE}> for Pair<T1, T2>
where
    // T1 and T2 must be MySized (to get their ::SIZE for the const generic arg above)
    // and also Parseable with their respective sizes.
    T1: Size + Parseable<{T1::SIZE}>,
    T2: Size + Parseable<{T2::SIZE}>,

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
        let (bytes_t2, _/*empty_if_correct*/) = rest.split_at(T2::SIZE);

        // Call parse for T1, which expects [u8; T1::SIZE]
        let field1_val = T1::parse(bytes_t1.try_into().expect("slice1 wrong len"));
        // Call parse for T2, which expects [u8; T2::SIZE]
        let field2_val = T2::parse(bytes_t2.try_into().expect("slice2 wrong len"));

        Pair {
            _a: field1_val,
            _b: field2_val,
        }
    }
}

fn main() {
    type MyPair = Pair<TypeFixedU16, TypeFixedU32>;
    
    type MyTriple = Pair<TypeFixedU16, Pair<TypeFixedU16, TypeFixedU32>>;

    println!("TypeFixedU16::SIZE = {}", TypeFixedU16::SIZE);
    println!("TypeFixedU32::SIZE = {}", TypeFixedU32::SIZE);
    println!("Pair<TypeFixedU16, TypeFixedU32>::SIZE = {}", MyPair::SIZE);

    assert_eq!(MyPair::SIZE, 6);

    // The size for parsing is now directly Pair::SIZE, which is T1::SIZE + T2::SIZE
    let data_bytes: [u8; MyPair::SIZE] = [0x01, 0x00, 0x0A, 0x00, 0x00, 0x00];

    // This will find the `impl Parseable<{MyPair::SIZE}> for MyPair`
    let parsed_pair: MyPair = MyPair::parse(data_bytes);

    fn consume_pair(_p: Pair<TypeFixedU16, TypeFixedU32>) {}
    consume_pair(parsed_pair);
    
    println!("Successfully called Pair::parse. Parsed pair has ZST fields.");
    
    let data_bytes: [u8; MyTriple::SIZE] = [0x01, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00];
    
    let parsed_triple: MyTriple = MyTriple::parse(data_bytes);
    
    println!("{:?}", parsed_triple);

    fn consume_triple(_p: MyTriple) {}
    consume_triple(parsed_triple);
}