use crate::serialization_hybrid::{Pair, Product, Size};
use crate::traits::group::CryptoGroup;
use hybrid_array::typenum::{U2, U3, U4};
use hybrid_array::Array;

type Commitment<G> = Product<Product<<G as CryptoGroup>::Element, U2>, U3>;
type Response<G> = Product<<G as CryptoGroup>::Scalar, U4>;
type BitProof_<G> = Pair<Commitment<G>, Response<G>>;
pub struct BitProof<G: CryptoGroup>(BitProof_<G>);

type BitProofSize<G> = <BitProof_<G> as Size>::SizeType;
impl<G: CryptoGroup> Size for BitProof<G> 
where BitProof_<G>: Size {
    type SizeType = BitProofSize<G>;
}

impl<G: CryptoGroup> crate::serialization_hybrid::FSerializable<BitProofSize<G>> for BitProof<G>
where
    BitProof_<G>: Size,
    BitProof_<G>: crate::serialization_hybrid::FSerializable<BitProofSize<G>>,
{
    fn serialize(&self) -> Array<u8, BitProofSize<G>> {
        self.0.serialize()
    }

    fn deserialize(
        bytes: Array<u8, BitProofSize<G>>,
    ) -> Result<Self, crate::serialization_hybrid::Error> {
        let pair = BitProof_::<G>::deserialize(bytes);

        Ok(BitProof(pair?))
    }
}

/*
This is how we would like to write the same code using a macro:

---------------- code begins ------------
use exact_derive::FSerializable;

type Commitment<G> = Product<Product<<G as CryptoGroup>::Element, U2>, U3>;
type Response<G> = Product<<G as CryptoGroup>::Scalar, U4>;
type BitProof_<G> = Pair<Commitment<G>, Response<G>>;
#[derive(FSerializable)]
pub struct BitProof<G: CryptoGroup>(BitProof_<G>);
---------------- code ends ------------
*/