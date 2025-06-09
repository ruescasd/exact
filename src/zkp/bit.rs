use crate::elgamal::ElGamal;
use crate::serialization_hybrid::{FSerializable, Pair, Product, Size};
use crate::traits::element::{ElementN, GroupElement};
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::utils::rng;
use hybrid_array::typenum::{U2, U3, U4};
use hybrid_array::Array;

type E2<G> = Product<<G as CryptoGroup>::Element, U2>;
type BitProof_<G> = Pair<Product<E2<G>, U3>, <G as CryptoGroup>::Scalar>;

pub struct BitProof<G: CryptoGroup>(BitProof_<G>);

impl<G: CryptoGroup> BitProof<G> {
    pub fn new(c1: E2<G>, c2: E2<G>, c3: E2<G>, response: G::Scalar) -> Self {
        BitProof(Pair(Product(Array([c1, c2, c3])), response))
    }

    pub fn commitments(&self) -> &Array<E2<G>, U3> {
        &self.0 .0 .0
    }

    pub fn response(&self) -> &G::Scalar {
        &self.0 .1
    }
}

use core::ops::{Mul as CoreMul};
use hybrid_array::ArraySize;

pub fn prove<G: CryptoGroup>(
    bit: &G::Scalar,
    randomness: &G::Scalar,
    ciphertext: &ElGamal<G>,
    c_prime: &Product<G::Element, U2>,
    y: &G::Element
) -> Option<BitProof<G>>
where
      G::Scalar: Clone,
      G::Element: Size + Clone ,
      G::Element: FSerializable<<G::Element as Size>::SizeType>,
      ElGamal<G>: Size,
      ElGamal<G>: FSerializable<<ElGamal<G> as Size>::SizeType>,
      Product<G::Element, U2>: FSerializable<<G::Element as Size>::SizeType>,
{
    let mut rng = rng::DefaultRng;
    let generator = G::generator();
    let identity = G::Element::identity();
    
    // G=(g,y)
    // H=(1,g)
    let big_g = Product::<G::Element, U2>::new([generator, y.clone()]);
    let big_h = Product::<G::Element, U2>::new([identity, y.clone()]);
    
    // we use the real value of b when commiting
    let b_2 = Product::<G::Scalar, U2>::uniform(&bit);
    // generate random (r,s,t)
    let r = G::Scalar::random(&mut rng);
    let r_2 =  Product::<G::Scalar, U2>::uniform(&r);
    let s = G::Scalar::random(&mut rng);
    let s_2 = Product::<G::Scalar, U2>::uniform(&s);
    let t = G::Scalar::random(&mut rng);
    let t_2 = Product::<G::Scalar, U2>::uniform(&t);
    
    // hom is f(b,r,s,t)=( H^bG^r, C^bG^s, G^t )
    
    // C = H^bG^r
    let h_pow_b = big_h.scalar_mul(&b_2);
    let g_pow_r = big_g.scalar_mul(&r_2);
    let big_c = h_pow_b.add_element(&g_pow_r);
    // C^bG^s
    let c_pow_b = big_c.scalar_mul(&b_2);
    let g_pow_s = big_g.scalar_mul(&s_2);
    let cb_gs = c_pow_b.add_element(&g_pow_s);
    // G^t
    let g_pow_t = big_g.scalar_mul(&t_2);

    let challenge: G::Scalar = G::hash_to_scalar(&[
        &big_c.serialize(),
        &cb_gs.serialize(),
        &g_pow_t.serialize(),
        // include the statement in the hash
        &ciphertext.serialize(),
        &c_prime.serialize(),
    ]);

    // Challenge: v
    let v_4 = Product::uniform(&challenge);
    
    // X=(b,r,s,t) is a preimage.
    // FIXME is this r the one randomly generated or the one used when encrypting?
    let big_x: Product<G::Scalar, U4> = Product::new([bit.clone(), r.clone(), s.clone(), t.clone()]);
    let vx = v_4.mul(&big_x);
    
    // A = (b, r,s,t). b is the real value, r,s,t is randomly generated above
    let big_a: Product<G::Scalar, U4> = Product::new([bit.clone(), r.clone(), s, t]);
    // response D=vX+A
    let big_d = vx.add(&big_a);
    
    // C''=C'/C
    let c_prime_inv = c_prime.negate_element();
    let c_prime_2 = ciphertext.0.add_element(&c_prime_inv);
    // Y=(C,C',C'')
    let big_y: Product<Product<G::Element, U2>, U3> = Product::new([ciphertext.0.clone(), c_prime.clone(), c_prime_2.clone()]);
    let big_b: Product<Product<G::Element, U2>, U3> = Product::new([big_c, cb_gs, g_pow_t]);
    // Check: Y^vB=f(D)
    // Something does not line up, v is cardinality 4, but big y is cardinality 3..
    
    None
}
/*
pub fn verify<G: CryptoGroup>(
    g1: &G::Element,
    g2: &G::Element,
    public_y1: &G::Element,
    public_y2: &G::Element,
    proof: &CPProof<G>,
) -> bool
      where
      G::Element: Size + Eq + PartialEq,
      G::Element: FSerializable<<G::Element as Size>::SizeType>,
{
    let commitments = proof.commitments();
    let s_scalar = proof.response();
    let g1_bytes = g1.serialize();
    let g2_bytes = g2.serialize();
    let y1_bytes = public_y1.serialize();
    let y2_bytes = public_y2.serialize();
    let t1_bytes = commitments[0].serialize();
    let t2_bytes = commitments[1].serialize();
    let c_scalar = G::hash_to_scalar(&[
        g1_bytes.as_ref(),
        g2_bytes.as_ref(),
        y1_bytes.as_ref(),
        y2_bytes.as_ref(),
        t1_bytes.as_ref(),
        t2_bytes.as_ref(),
    ]);
    let g1_s = g1.scalar_mul(&s_scalar);
    let y1_c = public_y1.scalar_mul(&c_scalar);
    let t1_y1_c = commitments[0].add_element(&y1_c);
    let check1 = g1_s == t1_y1_c;
    let g2_s = g2.scalar_mul(&s_scalar);
    let y2_c = public_y2.scalar_mul(&c_scalar);
    let t2_y2_c = commitments[1].add_element(&y2_c);
    let check2 = g2_s == t2_y2_c;
    check1 && check2
}
*/

/*
G=(g,y)
H=(1,g)

H^bG^r is ElGamal ciphertext of g^b, where r is from the exponents of g, and not G. Similarly, b is is bits (bk,...,b0) in the exponents of g.

C=H^bG^r
C'=C^bG^s
=H^(b^2)G^(rb-s)

then C' is an encryption of b^2 (element-wise), so we require that

C''=C'/C=G^t

with t=rb-s to show that b^2=b.

Consider the map

f(b,r,s,t)=( H^bG^r, C^bHs, G^t )

Note that Y=(C,C',C'') is an image, and X=(b,r,s,t) is a preimage.

We have a homomorphism f and all we need is a single general Schnorr proof!

Y=f(X)

Commitment: Pick A (r,s,t) randomly and compute B=f(A) with the real value of b.

Challenge: v

Response: D=vX+A

Check: Y^vB=f(D)

The public statement is (C, C')
*/