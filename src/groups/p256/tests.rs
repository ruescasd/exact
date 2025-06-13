use super::*; // Imports P256Group, P256Element, P256Scalar
use crate::serialization_hybrid::FSerializable;
use crate::traits::{element::GroupElement, group::CryptoGroup, scalar::GroupScalar};
use crate::utils::rng::DefaultRng; // For random operations
use hybrid_array::typenum::{U32, U33}; // For serialized sizes
use typenum::Unsigned; // For UXX::USIZE
                       // Removed: use std::ops::Neg as OtherNeg; // Alias to avoid conflict if Neg is already in scope from traits
                       // std::ops::Neg should be in scope via prelude or p256::Scalar's own methods.

#[test]
fn test_p256_scalar_addition() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let s3 = s1.add(&s2);

    let s1_plus_s2 = s1.0 + s2.0;
    assert_eq!(s3.0, s1_plus_s2, "Scalar addition failed");
}

#[test]
fn test_p256_scalar_subtraction() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let s3 = s1.sub(&s2);

    let s1_minus_s2 = s1.0 - s2.0;
    assert_eq!(s3.0, s1_minus_s2, "Scalar subtraction failed");
}

#[test]
fn test_p256_scalar_multiplication() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let s3 = s1.mul(&s2);

    let s1_times_s2 = s1.0 * s2.0;
    assert_eq!(s3.0, s1_times_s2, "Scalar multiplication failed");
}

#[test]
fn test_p256_scalar_negation() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s_neg = s1.negate(); // This calls P256Scalar's negate method, which calls self.0.neg()
                             // P256Scalar's negate method already uses self.0.neg().
                             // We are testing if our P256Scalar::negate() is consistent with direct negation if possible,
                             // or rather, that s_neg + s1 == 0.
                             // The P256Scalar(self.0.neg()) is what our negate() method does.
                             // So this test is more about s + (-s) = 0.
                             // Let's keep s_neg_direct as what our trait method produces.
    let s_neg_direct = s1.negate(); // This is P256Scalar(s1.0.neg())

    assert_eq!(
        s_neg, s_neg_direct,
        "Scalar negation consistency check failed"
    );
    assert_eq!(
        s_neg.add(&s1),
        P256Scalar::zero(),
        "Negation property s + (-s) = 0 failed"
    );
}

#[test]
fn test_p256_scalar_inversion() {
    let mut rng = DefaultRng;
    let s = P256Scalar::random(&mut rng);
    // Avoid inverting zero if s happens to be zero, though highly unlikely for random.
    if s == P256Scalar::zero() {
        assert!(s.invert().is_none(), "Inversion of zero should be None");
    } else {
        let s_inv = s.invert().expect("Scalar inversion failed");
        let product = s.mul(&s_inv);
        assert_eq!(product, P256Scalar::one(), "s * s_inv = 1 property failed");
    }

    let zero = P256Scalar::zero();
    assert!(zero.invert().is_none(), "Inversion of zero must be None");
}

#[test]
fn test_p256_scalar_serialization_deserialization() {
    let mut rng = DefaultRng;
    let s_orig = P256Scalar::random(&mut rng);

    let serialized_s = s_orig.serialize();
    assert_eq!(
        serialized_s.len(),
        U32::USIZE,
        "Serialized scalar length mismatch"
    );

    let s_deserialized =
        P256Scalar::deserialize(serialized_s).expect("Scalar deserialization failed");
    assert_eq!(
        s_orig, s_deserialized,
        "Original and deserialized scalars do not match"
    );

    // Test zero and one
    let s_zero = P256Scalar::zero();
    let ser_zero = s_zero.serialize();
    let des_zero = P256Scalar::deserialize(ser_zero).unwrap();
    assert_eq!(s_zero, des_zero);

    let s_one = P256Scalar::one();
    let ser_one = s_one.serialize();
    let des_one = P256Scalar::deserialize(ser_one).unwrap();
    assert_eq!(s_one, des_one);
}

#[test]
fn test_p256_element_addition() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let g = P256Group::generator();

    let e1 = g.scalar_mul(&s1);
    let e2 = g.scalar_mul(&s2);
    let e3_sum = e1.add_element(&e2);

    // (s1*G) + (s2*G) = (s1+s2)*G
    let s_sum = s1.add(&s2);
    let e3_expected = g.scalar_mul(&s_sum);

    assert_eq!(
        e3_sum, e3_expected,
        "Element addition failed: e1+e2 != (s1+s2)*G"
    );
}

#[test]
fn test_p256_element_negation() {
    let mut rng = DefaultRng;
    let s = P256Scalar::random(&mut rng);
    let g = P256Group::generator();
    let e = g.scalar_mul(&s);

    let e_neg = e.negate_element();
    let e_plus_e_neg = e.add_element(&e_neg);

    assert_eq!(
        e_plus_e_neg,
        P256Element::identity(),
        "Element negation failed: e + (-e) != Id"
    );

    let s_neg = s.negate();
    let e_neg_expected = g.scalar_mul(&s_neg);
    assert_eq!(
        e_neg, e_neg_expected,
        "Element negation failed: (-s)*G != -(s*G)"
    );
}

#[test]
fn test_p256_element_scalar_multiplication() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let g = P256Group::generator();

    // s2 * (s1 * G) = (s1*s2) * G
    let e1 = g.scalar_mul(&s1);
    let e2 = e1.scalar_mul(&s2); // s2 * (s1*G)

    let s_prod = s1.mul(&s2);
    let e_expected = g.scalar_mul(&s_prod); // (s1*s2)*G

    assert_eq!(e2, e_expected, "Element scalar multiplication failed");
}

#[test]
fn test_p256_element_identity_properties() {
    let mut rng = DefaultRng;
    let s = P256Scalar::random(&mut rng);
    let g = P256Group::generator();
    let e = g.scalar_mul(&s);
    let id = P256Element::identity();

    assert_eq!(e.add_element(&id), e, "e + Id != e");
    assert_eq!(id.add_element(&e), e, "Id + e != e");

    let zero_scalar = P256Scalar::zero();
    // 0 * G = Id
    assert_eq!(g.scalar_mul(&zero_scalar), id, "0 * G != Id");
}

#[test]
fn test_p256_element_serialization_deserialization() {
    let mut rng = DefaultRng;
    let s = P256Scalar::random(&mut rng);
    let g = P256Group::generator();
    let e_orig = g.scalar_mul(&s);

    let serialized_e = e_orig.serialize();
    assert_eq!(
        serialized_e.len(),
        U33::USIZE,
        "Serialized element length mismatch"
    );

    let e_deserialized =
        P256Element::deserialize(serialized_e).expect("Element deserialization failed");
    assert_eq!(
        e_orig, e_deserialized,
        "Original and deserialized elements do not match"
    );

    // Test identity
    let e_id = P256Element::identity();
    let ser_id = e_id.serialize();
    let des_id = P256Element::deserialize(ser_id).unwrap();
    assert_eq!(e_id, des_id);
}

#[test]
fn test_p256_group_generator() {
    let g = P256Group::generator();
    // Basic check: generator should not be identity for P-256
    assert_ne!(g, P256Element::identity(), "Generator is identity element");
    // A more robust check might involve known generator coordinates if easily accessible,
    // or checking its order, but that's more complex.
    // For now, just check it's not identity and serializes/deserializes.
    let ser_gen = g.serialize();
    let des_gen = P256Element::deserialize(ser_gen).unwrap();
    assert_eq!(g, des_gen);
}

#[test]
fn test_p256_group_random_element_and_scalar() {
    let rand_e = P256Group::random_element();
    // Check that random element is not identity (highly improbable for a good random function)
    assert_ne!(
        rand_e,
        P256Element::identity(),
        "Random element is identity"
    );

    let rand_s = P256Group::random_exponent();
    assert_ne!(rand_s, P256Scalar::zero(), "Random scalar is zero");

    // Check serialization for good measure
    let ser_e = rand_e.serialize();
    let des_e = P256Element::deserialize(ser_e).unwrap();
    assert_eq!(rand_e, des_e);

    let ser_s = rand_s.serialize();
    let des_s = P256Scalar::deserialize(ser_s).unwrap();
    assert_eq!(rand_s, des_s);
}

#[test]
fn test_p256_group_hash_to_scalar() {
    let input1 = b"some input data";
    let input2 = b"other input data";

    let s1 = P256Group::hash_to_scalar(&[input1]);
    let s2 = P256Group::hash_to_scalar(&[input1]); // Same input, same output
    let s3 = P256Group::hash_to_scalar(&[input2]);
    let s4 = P256Group::hash_to_scalar(&[input1, input2]); // Different input

    assert_eq!(s1, s2, "Hash to scalar not deterministic for same input");
    assert_ne!(
        s1, s3,
        "Hash to scalar produces same output for different inputs"
    );
    assert_ne!(
        s1, s4,
        "Hash to scalar produces same output for different input combinations"
    );

    // Check that the scalar is not zero (highly improbable for a good hash function)
    assert_ne!(s1, P256Scalar::zero(), "Hashed scalar is zero");
}

// Test commutativity of addition for elements
#[test]
fn test_p256_element_addition_commutativity() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let g = P256Group::generator();

    let e1 = g.scalar_mul(&s1);
    let e2 = g.scalar_mul(&s2);

    let sum1 = e1.add_element(&e2);
    let sum2 = e2.add_element(&e1);

    assert_eq!(sum1, sum2, "Element addition is not commutative");
}

// Test associativity of addition for elements
#[test]
fn test_p256_element_addition_associativity() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let s3 = P256Scalar::random(&mut rng);
    let g = P256Group::generator();

    let e1 = g.scalar_mul(&s1);
    let e2 = g.scalar_mul(&s2);
    let e3 = g.scalar_mul(&s3);

    // (e1 + e2) + e3
    let sum_left_assoc = (e1.add_element(&e2)).add_element(&e3);
    // e1 + (e2 + e3)
    let sum_right_assoc = e1.add_element(&(e2.add_element(&e3)));

    assert_eq!(
        sum_left_assoc, sum_right_assoc,
        "Element addition is not associative"
    );
}

// Test distributivity: s*(e1+e2) = s*e1 + s*e2
#[test]
fn test_p256_distributivity_scalar_element_addition() {
    let mut rng = DefaultRng;
    let s_op = P256Scalar::random(&mut rng); // The scalar to multiply with

    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);
    let g = P256Group::generator();

    let e1 = g.scalar_mul(&s1);
    let e2 = g.scalar_mul(&s2);

    // s_op * (e1 + e2)
    let sum_elements = e1.add_element(&e2);
    let lhs = sum_elements.scalar_mul(&s_op);

    // (s_op * e1) + (s_op * e2)
    let term1 = e1.scalar_mul(&s_op);
    let term2 = e2.scalar_mul(&s_op);
    let rhs = term1.add_element(&term2);

    assert_eq!(lhs, rhs, "Distributivity s*(e1+e2) = s*e1 + s*e2 failed");
}

// Test distributivity: (s1+s2)*E = s1*E + s2*E
#[test]
fn test_p256_distributivity_scalar_addition_element() {
    let mut rng = DefaultRng;
    let s1 = P256Scalar::random(&mut rng);
    let s2 = P256Scalar::random(&mut rng);

    let s_elem = P256Scalar::random(&mut rng); // Scalar for the base element
    let g = P256Group::generator();
    let e = g.scalar_mul(&s_elem);

    // (s1 + s2) * e
    let sum_scalars = s1.add(&s2);
    let lhs = e.scalar_mul(&sum_scalars);

    // (s1 * e) + (s2 * e)
    let term1 = e.scalar_mul(&s1);
    let term2 = e.scalar_mul(&s2);
    let rhs = term1.add_element(&term2);

    assert_eq!(lhs, rhs, "Distributivity (s1+s2)*E = s1*E + s2*E failed");
}
