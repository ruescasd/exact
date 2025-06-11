use crate::elgamal::ElGamal;
use crate::serialization_hybrid::{FSerializable, Pair, Product, Size};
use crate::traits::element::GroupElement;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::utils::rng;
use hybrid_array::typenum::{U2, U3, U4};

// type E2<G> = Product<<G as CryptoGroup>::Element, U2>;
type Commitment<G> = Product<Product<<G as CryptoGroup>::Element, U2>, U3>;
type Response<G> = Product<<G as CryptoGroup>::Scalar, U4>;
// type BitProof_<G> = Pair<Product<E2<G>, U3>, <G as CryptoGroup>::Scalar>;
type BitProof_<G> = Pair<Commitment<G>, Response<G>>;

pub struct BitProof<G: CryptoGroup>(BitProof_<G>);

impl<G: CryptoGroup> BitProof<G> {
    pub fn new(c: Commitment<G>, response: Response<G>) -> Self {
        BitProof(Pair(c, response))
    }

    pub fn commitment(&self) -> &Commitment<G> {
        &self.0 .0
    }

    pub fn response(&self) -> &Response<G> {
        &self.0 .1
    }
}

// big_g, big_h and big_c are fixed values, which we pass in for convenience
// In an alternate implementation, hom would be a trait implemented by a struct with
// these fixed values
fn hom<G: CryptoGroup>(
    big_g: &Product<G::Element, U2>,
    big_h: &Product<G::Element, U2>,
    big_c: &Product<G::Element, U2>,
    b: &G::Scalar,
    r: &G::Scalar,
    s: &G::Scalar,
    t: &G::Scalar,
) -> Product<Product<G::Element, U2>, U3>
where
    G::Scalar: Clone,
{
    let b_2 = Product::<G::Scalar, U2>::uniform(&b);
    let r_2 = Product::<G::Scalar, U2>::uniform(&r);
    let s_2 = Product::<G::Scalar, U2>::uniform(&s);
    let t_2 = Product::<G::Scalar, U2>::uniform(&t);
    // H^bG^r
    let h_pow_b = big_h.scalar_mul(&b_2);
    let g_pow_r = big_g.scalar_mul(&r_2);
    let prod = h_pow_b.add_element(&g_pow_r);
    // C^bG^s
    let c_pow_b = big_c.scalar_mul(&b_2);
    let g_pow_s = big_g.scalar_mul(&s_2);
    let cb_gs = c_pow_b.add_element(&g_pow_s);
    // G^t
    let g_pow_t = big_g.scalar_mul(&t_2);

    Product::new([prod, cb_gs, g_pow_t])
}

pub fn prove<G: CryptoGroup>(
    bit: &G::Scalar,
    r_real: &G::Scalar,
    s_real: &G::Scalar,
    ciphertext: &ElGamal<G>,
    c_prime: &Product<G::Element, U2>,
    y: &G::Element,
) -> BitProof<G>
where
    G::Scalar: Clone,
    G::Element: Size + Clone,
    G::Element: FSerializable<<G::Element as Size>::SizeType>,
    ElGamal<G>: Size,
    ElGamal<G>: FSerializable<<ElGamal<G> as Size>::SizeType>,
    Product<G::Element, U2>: Size,
    Product<G::Element, U2>: FSerializable<<Product<G::Element, U2> as Size>::SizeType>,
    Product<Product<G::Element, U2>, U3>: Size,
    Product<Product<G::Element, U2>, U3>:
        FSerializable<<Product<Product<G::Element, U2>, U3> as Size>::SizeType>,
{
    let mut rng = rng::DefaultRng;
    let generator = G::generator();
    let identity = G::Element::identity();

    // G=(g,y)
    // H=(1,g)
    let big_g = Product::<G::Element, U2>::new([generator.clone(), y.clone()]);
    let big_h = Product::<G::Element, U2>::new([identity, generator]);

    // generate random A = (r,s,t), we use b as the real value
    let b = bit.clone();
    let r = G::Scalar::random(&mut rng);
    let s = G::Scalar::random(&mut rng);
    let t = G::Scalar::random(&mut rng);

    // A = (b,r,s,t). b,r,s,t is randomly generated
    let big_a: Product<G::Scalar, U4> =
        Product::new([bit.clone(), r.clone(), s.clone(), t.clone()]);
    // commitment: compute B=f(A)
    let big_b = hom::<G>(&big_g, &big_h, &ciphertext.0, &bit, &r, &s, &t);

    let challenge: G::Scalar = G::hash_to_scalar(&[
        &big_b.serialize(),
        // include the statement in the hash
        &ciphertext.serialize(),
        &c_prime.serialize(),
    ]);

    // Challenge: v
    let v_4 = Product::uniform(&challenge);

    // X=(b,r,s,t) is a preimage.
    let t_real = r_real.mul(&b.sub(&G::Scalar::one()));
    let t_real = t_real.add(&s_real);
    // let t_real = r.mul(&b).sub(&s);
    let big_x: Product<G::Scalar, U4> =
        Product::new([bit.clone(), r_real.clone(), s_real.clone(), t_real.clone()]);
    let vx = v_4.mul(&big_x);

    // response D=vX+A
    let big_d: Product<G::Scalar, U4> = vx.add(&big_a);

    /*
    // self verify:

    // C''=C'/C
    let c_inv = ciphertext.0.negate_element();
    let c_prime_2 = c_prime.add_element(&c_inv);
    // Y=(C,C',C'')
    let big_y: Product<Product<G::Element, U2>, U3> = Product::new([ciphertext.0.clone(), c_prime.clone(), c_prime_2.clone()]);
    // Check: Y^vB=f(D)

    let v_2: Product<G::Scalar, U2> = Product::uniform(&challenge);
    let v_2_3: Product<Product<G::Scalar, U2>, U3> = Product::uniform(&v_2);
    let y_pow_v = big_y.scalar_mul(&v_2_3);

    let lhs = y_pow_v.add_element(&big_b);

    let d_values: [G::Scalar; 4] = big_d.clone().0.0;
    let rhs = hom::<G>(&big_g, &big_h, &ciphertext.0, &d_values[0], &d_values[1], &d_values[2], &d_values[3]);

    assert!(lhs.0[0].eq(&rhs.0[0]));
    assert!(lhs.0[1].eq(&rhs.0[1]));
    assert!(lhs.0[2].eq(&rhs.0[2]));
    */

    BitProof::<G>::new(big_b, big_d)
}

pub fn verify<G: CryptoGroup>(
    proof: &BitProof<G>,
    ciphertext: &ElGamal<G>,
    c_prime: &Product<G::Element, U2>,
    y: &G::Element,
) -> bool
where
    G::Scalar: Clone,
    G::Element: Size + Clone,
    G::Element: FSerializable<<G::Element as Size>::SizeType>,
    ElGamal<G>: Size,
    ElGamal<G>: FSerializable<<ElGamal<G> as Size>::SizeType>,
    Product<G::Element, U2>: Size,
    Product<G::Element, U2>: FSerializable<<Product<G::Element, U2> as Size>::SizeType>,
    Product<Product<G::Element, U2>, U3>: Size,
    Product<Product<G::Element, U2>, U3>:
        FSerializable<<Product<Product<G::Element, U2>, U3> as Size>::SizeType>,
{
    let generator = G::generator();
    let identity = G::Element::identity();

    // G=(g,y)
    // H=(1,g)
    let big_g = Product::<G::Element, U2>::new([generator.clone(), y.clone()]);
    let big_h = Product::<G::Element, U2>::new([identity, generator]);

    let challenge: G::Scalar = G::hash_to_scalar(&[
        &proof.commitment().serialize(),
        // include the statement in the hash
        &ciphertext.serialize(),
        &c_prime.serialize(),
    ]);

    // C''=C'/C
    let c_inv = ciphertext.0.negate_element();
    let c_prime_2 = c_prime.add_element(&c_inv);
    // Y=(C,C',C'')
    let big_y: Product<Product<G::Element, U2>, U3> =
        Product::new([ciphertext.0.clone(), c_prime.clone(), c_prime_2.clone()]);

    // Challenge: v
    let v_2: Product<G::Scalar, U2> = Product::uniform(&challenge);
    let v_2_3: Product<Product<G::Scalar, U2>, U3> = Product::uniform(&v_2);

    // response D=vX+A
    let resp: &[G::Scalar; 4] = &proof.response().0 .0;

    // Check: Y^vB=f(D)
    let y_pow_v = big_y.scalar_mul(&v_2_3);
    let lhs = y_pow_v.add_element(&proof.commitment());

    let rhs = hom::<G>(
        &big_g,
        &big_h,
        &ciphertext.0,
        &resp[0],
        &resp[1],
        &resp[2],
        &resp[3],
    );

    lhs.eq(&rhs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::{ElGamal, KeyPair};
    use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement, RistrettoScalar};
    use crate::serialization_hybrid::Product;
    use crate::traits::scalar::GroupScalar;
    use crate::traits::{CryptoGroup, GroupElement};
    use crate::utils::rng;
    use rand::Rng;

    #[test]
    fn test_bit_zkp_prove() {
        let g = Ristretto255Group::generator();
        let keypair = KeyPair::<Ristretto255Group>::new();

        for _ in 0..10 {
            let b = if rng::DefaultRng.gen_bool(0.5) {
                RistrettoScalar::one()
            } else {
                RistrettoScalar::zero()
            };

            let b_2: Product<RistrettoScalar, typenum::U2> = Product::uniform(&b);
            let message = g.scalar_mul(&b);

            let r = RistrettoScalar::random(&mut rng::DefaultRng);
            let gr = g.scalar_mul(&r);
            let hr = keypair.pkey().scalar_mul(&r);
            let mhr = hr.add_element(&message);
            let c = ElGamal::<Ristretto255Group>::new(gr, mhr);

            let big_g =
                Product::<RistrettoElement, typenum::U2>::new([g.clone(), keypair.pkey().clone()]);
            let s = RistrettoScalar::random(&mut rng::DefaultRng);
            let s_2: Product<RistrettoScalar, typenum::U2> = Product::uniform(&s);
            let c_pow_b = c.0.scalar_mul(&b_2);
            let g_pow_s = big_g.scalar_mul(&s_2);
            let c_prime = c_pow_b.add_element(&g_pow_s);

            let proof = prove(&b, &r, &s, &c, &c_prime, keypair.pkey());
            let ok = verify(&proof, &c, &c_prime, keypair.pkey());

            assert!(ok);
        }
    }
}

/*

r       r2              r + r2
b       b2              b + b2                  g(r+r2)(b + b2) = rb + rb2 + r2b + r2b2

g^rb    g^r2b2          g^rb + r2b2

G=(g,y)
H=(1,g)

r1b + s1 + r2b + s2 = (r1+r2)b + (s1 + s2)

H^bG^r is ElGamal ciphertext of g^b, where r is from the exponents of g, and not G. Similarly, b is is bits (bk,...,b0) in the exponents of g.

C=H^bG^r            (1^b * g^r, g^b * h^r)
C'=C^bG^s        (g^rb, g^b^2 h^rb) * (g^s, h^s) = g^rb + s, g^b^2 h^rb + s
=H^(b^2)G^(rb+s)

g^rb + s / g^r = rb - r + s = r(b - 1) + s

then C' is an encryption of b^2 (element-wise), so we require that

C''=C'/C=G^t

with t=rb-s to show that b^2=b.

Consider the map

f(b,r,s,t)=( H^bG^r, C^bG^s, G^t )

Note that Y=(C,C',C'') is an image, and X=(b,r,s,t) is a preimage.

We have a homomorphism f and all we need is a single general Schnorr proof!

Y=f(X)

Commitment: Pick A (r,s,t) randomly and compute B=f(A) with the real value of b.

Challenge: v

Response: D=vX+A

Check: Y^vB=f(D)

The public statement is (C, C')


*/

/*
For any fixed H, G, C, H

f(b,r,s,t)=(H^bG^r, C^bG^s, G^t)

= (..., C^bG^s, ...)

= ( (H^bG^r)^b * G^s)

= (1, g^b)^b * (g^r, y^r)^b * (g^s, y^s)

= (1^b, g^b^2) * (g^rb, y^rb) * (g^s, y^s)

= (1^b, g^b^2) * (g^rb, y^rb) * (g^s, y^s)

= (1^b, g^b^2) * (g^rb + s, y^rb + s)

= (g^rb + s, g^b^2 * y^rb + s)

= e(g^b^2, rb+s)


f(b,r,s,t) = (_, g^rb + s, g^b^2 * y^rb + s, _)

f(b1,r1,s1,t1) * f(b2,r2,s2,t2) = f(b1+b2, r1+r2, s1+s2, t1+t2)

(_, g^r1b1 + s1, g^b1^2 * y^r1b1 + s1, _) * (_, g^r2b2, g^b2^2 * y^r2b2 + s2, _) = (_, g^(r1 + r2)(b1 + 2), g^(b1 + b2)^2 * y^(r1+r2)(b1+b2) + (s1 + s2), _)

(_, g^r1b1+r2b2, g^b1^2 + b2^2 * y^r1b1 + s1 + r2b2 + 2) = (_, g^(r1 + r2)(b1 + 2), g^(b1 + b2)^2 * y^(r1+r2)(b1+b2) + (s1 + s2), _)

*/
