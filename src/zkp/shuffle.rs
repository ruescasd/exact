use crate::traits::group::CryptoGroup;
use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;
use crate::serialization_hybrid::Product; // Assuming Product is defined here
use hybrid_array::{Array, ArraySize};
use hybrid_array::typenum::U2; // Correct U2 import

// Additional imports for the prove function
use rand::RngCore;
use crate::utils::rng::DefaultRng; // Assuming DefaultRng is here
use crate::traits::group::HashToScalar;
use crate::serialization_traits::{FSerializable, Size}; // For Fiat-Shamir and Size
use core::convert::TryInto;


// Type alias for an ElGamal ciphertext
pub type Ciphertext<G: CryptoGroup> = Product<G::Element, U2>;

// Type alias for a vector of ElGamal ciphertexts
pub type CiphertextVector<G: CryptoGroup, N: ArraySize> = Product<Ciphertext<G>, N>;

/// Instance for the shuffle proof.
#[derive(Clone, Debug)]
pub struct ShuffleInstance<G: CryptoGroup, N: ArraySize> {
    pub initial_ciphertexts: CiphertextVector<G, N>,
    pub final_ciphertexts: CiphertextVector<G, N>,
    pub public_keys: Product<G::Element, N>,
    pub perm_commitments: Product<G::Element, N>, // P_j
    pub g: G::Element, // Generator g
    pub h: G::Element, // Generator h (for Algorithm 1's Com operation)
    pub g_P: G::Element, // Generator for permutation commitments P_j
    pub h_P: G::Element, // Second generator for permutation commitments P_j

    // TODO: The following fields are placeholders for the verify function.
    // A proper shuffle proof verification typically reconstructs or verifies these
    // values differently, often through algebraic relations or polynomial identities
    // that avoid the verifier needing explicit knowledge of \pi^{-1}.
    // These are added here as a stopgap to match the provided verification equations.
    pub initial_ciphertexts_perm_by_pi_inv: Option<CiphertextVector<G, N>>,
    pub perm_commitments_perm_by_pi_inv: Option<Product<G::Element, N>>,
    pub prod_perm_commitments_perm_by_pi_inv: Option<G::Element>,
}

/// Witness for the shuffle proof.
/// Note: `permutation` stores `pi_j` as `G::Scalar`, where `pi_j` is the
/// new index for the element originally at index `j`. This requires `G::Scalar`
/// to be losslessly convertible to `usize` for practical use in array indexing.
#[derive(Clone, Debug)]
pub struct ShuffleWitness<G: CryptoGroup, N: ArraySize> {
    pub permutation: Product<G::Scalar, N>, // pi_j (new index for element j)
    pub rerandomization_factors: Product<G::Scalar, N>, // r'_j
    pub perm_commitment_randomness: Product<G::Scalar, N>, // k_j (randomness for P_j)
}

/// Commitments for the shuffle proof.
#[derive(Clone, Debug, FSerializable, Size)]
#[cfg_attr(test, derive(PartialEq))] // For tests, if elements/scalars derive PartialEq
pub struct ShuffleProofCommitments<G: CryptoGroup, N: ArraySize> {
    pub A_i: CiphertextVector<G, N>, // Vector of (A_i1, A_i2)
    pub B_i: CiphertextVector<G, N>, // Vector of (B_i1, B_i2)
    pub S: Ciphertext<G>, // (S1, S2)
    pub T: Ciphertext<G>, // (T1, T2)
}

/// Responses for the shuffle proof.
#[derive(Clone, Debug, FSerializable, Size)]
#[cfg_attr(test, derive(PartialEq))] // For tests, if elements/scalars derive PartialEq
pub struct ShuffleProofResponses<G: CryptoGroup, N: ArraySize> {
    pub k_prime_vec: Product<G::Scalar, N>, // k_prime_i in Alg1 responses
    pub r_prime_vec: Product<G::Scalar, N>, // r_prime_i in Alg1 responses
    pub s_prime: G::Scalar,                 // s_prime in Alg1 responses
    pub t_prime_vec: Product<G::Scalar, N>, // t_prime_i in Alg1 responses
}

/// Full shuffle proof.
#[derive(Clone, Debug, FSerializable, Size)]
#[cfg_attr(test, derive(PartialEq))] // For tests, if elements/scalars derive PartialEq
pub struct ShuffleProof<G: CryptoGroup, N: ArraySize> {
    pub commitments: ShuffleProofCommitments<G, N>,
    pub responses: ShuffleProofResponses<G, N>,
}

/// Performs component-wise multiplication of two ciphertexts.
pub fn ciphertext_mul<G: CryptoGroup>(c1: &Ciphertext<G>, c2: &Ciphertext<G>) -> Ciphertext<G> {
    Ciphertext::new([
        c1.0[0].add_element(&c2.0[0]),
        c1.0[1].add_element(&c2.0[1]),
    ])
}

/// Performs component-wise scalar multiplication of a ciphertext.
pub fn ciphertext_exp<G: CryptoGroup>(c: &Ciphertext<G>, s: &G::Scalar) -> Ciphertext<G> {
    Ciphertext::new([
        c.0[0].scalar_mul(s),
        c.0[1].scalar_mul(s),
    ])
}

/// Performs component-wise negation (inverse) of a ciphertext.
pub fn ciphertext_inv<G: CryptoGroup>(c: &Ciphertext<G>) -> Ciphertext<G> {
    Ciphertext::new([
        c.0[0].negate_element(),
        c.0[1].negate_element(),
    ])
}

/// Computes the permutation commitment P_j = g_P^{\pi(j)} * h_P^{k_j}.
pub fn compute_perm_commitment<G: CryptoGroup>(
    pi_j: &G::Scalar, k_j: &G::Scalar, g_P: &G::Element, h_P: &G::Element
) -> G::Element {
    let term1 = g_P.scalar_mul(pi_j);
    let term2 = h_P.scalar_mul(k_j);
    term1.add_element(&term2)
}

/// Applies a permutation to a vector of ciphertexts.
/// `output[permutation[j] as usize] = ciphertexts[j]`
pub fn apply_permutation_to_ciphertexts<G: CryptoGroup, N: ArraySize>(
    ciphertexts: &CiphertextVector<G, N>,
    permutation: &Product<G::Scalar, N>,
) -> Result<CiphertextVector<G, N>, &'static str>
where
    G::Scalar: GroupScalar + TryInto<usize> + Clone,
    <G::Scalar as TryInto<usize>>::Error: core::fmt::Debug,
    G::Element: Clone,
    Ciphertext<G>: Clone,
{
    let n_usize = N::to_usize();
    let mut out_array: Array<Ciphertext<G>, N> = Array::from_fn(|_| {
        Ciphertext::new([G::Element::identity(), G::Element::identity()])
    });

    for j in 0..n_usize {
        let new_index_scalar = &permutation.0[j];
        let new_idx = new_index_scalar.clone().try_into()
            .map_err(|_| "Failed to convert permutation scalar to usize")?;

        if new_idx >= n_usize {
            return Err("Permutation index out of bounds");
        }
        out_array[new_idx] = ciphertexts.0[j].clone();
    }
    Ok(Product(out_array))
}

/// Re-randomizes an ElGamal ciphertext.
pub fn rerandomize_ciphertext<G: CryptoGroup>(
    c: &Ciphertext<G>, pk: &G::Element, r_prime: &G::Scalar, g: &G::Element
) -> Ciphertext<G> {
    let x_prime = c.0[0].add_element(&g.scalar_mul(r_prime));
    let y_prime = c.0[1].add_element(&pk.scalar_mul(r_prime));
    Ciphertext::new([x_prime, y_prime])
}


#[allow(clippy::too_many_locals)]
pub fn prove<G: CryptoGroup, N: ArraySize>(
    instance: &ShuffleInstance<G, N>,
    witness: &ShuffleWitness<G, N>,
) -> Result<ShuffleProof<G, N>, &'static str>
where
    G::Scalar: GroupScalar + TryInto<usize> + FSerializable,
    <G::Scalar as TryInto<usize>>::Error: core::fmt::Debug,
    G::Element: GroupElement + FSerializable,
    Product<G::Element, U2>: FSerializable,
    Product<Product<G::Element, U2>, N>: FSerializable,
    Product<G::Element, N>: FSerializable,
    Product<G::Scalar, N>: FSerializable,
    G::Element: Clone,
    G::Scalar: Clone,
    Ciphertext<G>: Clone,
{
    let n_usize = N::to_usize();

    let mut pi_inv_map = vec![0usize; n_usize];
    for j in 0..n_usize {
        let new_idx_scalar = witness.permutation.0[j].clone();
        let new_idx: usize = new_idx_scalar.try_into()
            .map_err(|_| "Failed to convert pi scalar to usize for pi_inv")?;
        if new_idx >= n_usize {
            return Err("Permutation index out of bounds for pi_inv");
        }
        pi_inv_map[new_idx] = j;
    }

    let perm_initial_elements_arr = Array::from_fn(|i| {
        let old_idx = pi_inv_map[i];
        instance.initial_ciphertexts.0[old_idx].clone()
    });
    let initial_ciphertexts_permuted_by_pi_inv = Product(perm_initial_elements_arr);

    let mut rng = DefaultRng::new();
    let kappa_i_vec = Product(Array::from_fn(|_| G::Scalar::random(&mut rng)));
    let omega_A_scalar = G::Scalar::random(&mut rng);
    let rho_i_vec = Product(Array::from_fn(|_| G::Scalar::random(&mut rng)));
    let omega_B_scalar = G::Scalar::random(&mut rng);
    let sigma_scalar = G::Scalar::random(&mut rng);
    let tau_vec = Product(Array::from_fn(|_| G::Scalar::random(&mut rng)));

    let identity_element = G::Element::identity();
    let identity_ciphertext = Ciphertext::new([identity_element.clone(), identity_element.clone()]);

    let mut a_i_elements_arr: Array<Ciphertext<G>, N> = Array::from_fn(|_| identity_ciphertext.clone());
    let mut b_i_elements_arr: Array<Ciphertext<G>, N> = Array::from_fn(|_| identity_ciphertext.clone());

    for i in 0..n_usize {
        let c_pi_inv_i = &initial_ciphertexts_permuted_by_pi_inv.0[i];
        let pk_i = &instance.public_keys.0[i];
        let kappa_i = &kappa_i_vec.0[i];

        let com_a_lhs = pk_i.add_element(&instance.g.scalar_mul(kappa_i));
        let com_a_rhs = instance.h.scalar_mul(&omega_A_scalar);
        let com_a = Ciphertext::new([com_a_lhs, com_a_rhs]);
        a_i_elements_arr[i] = ciphertext_mul(&ciphertext_inv(c_pi_inv_i), &com_a);

        let c_prime_i = &instance.final_ciphertexts.0[i];
        let p_i = &instance.perm_commitments.0[i];
        let rho_i = &rho_i_vec.0[i];

        let com_b_lhs = pk_i.add_element(&instance.g.scalar_mul(rho_i));
        let com_b_rhs = p_i.add_element(&instance.h.scalar_mul(&omega_B_scalar));
        let com_b = Ciphertext::new([com_b_lhs, com_b_rhs]);
        b_i_elements_arr[i] = ciphertext_mul(&ciphertext_inv(c_prime_i), &com_b);
    }
    let a_i_vec = Product(a_i_elements_arr);
    let b_i_vec = Product(b_i_elements_arr);

    let prod_c_j = instance.initial_ciphertexts.0.iter().fold(identity_ciphertext.clone(), |acc, c| ciphertext_mul(&acc, c));
    let prod_pk_j = instance.public_keys.0.iter().fold(identity_element.clone(), |acc, pk| acc.add_element(pk));
    let sum_tau_j = tau_vec.0.iter().fold(G::Scalar::zero(), |acc, val| acc.add(val));

    let com_s_lhs = prod_pk_j.add_element(&instance.g.scalar_mul(&sigma_scalar));
    let com_s_rhs = instance.h.scalar_mul(&sum_tau_j);
    let com_s = Ciphertext::new([com_s_lhs, com_s_rhs]);
    let s_val = ciphertext_mul(&ciphertext_inv(&prod_c_j), &com_s);

    let prod_c_prime_j = instance.final_ciphertexts.0.iter().fold(identity_ciphertext.clone(), |acc, c| ciphertext_mul(&acc, c));
    let prod_p_j = instance.perm_commitments.0.iter().fold(identity_element.clone(), |acc, p| acc.add_element(p));

    let com_t_lhs = prod_pk_j.add_element(&instance.g.scalar_mul(&sigma_scalar));
    let com_t_rhs = prod_p_j.add_element(&instance.h.scalar_mul(&sum_tau_j));
    let com_t = Ciphertext::new([com_t_lhs, com_t_rhs]);
    let t_val = ciphertext_mul(&ciphertext_inv(&prod_c_prime_j), &com_t);

    let proof_commitments = ShuffleProofCommitments { A_i: a_i_vec, B_i: b_i_vec, S: s_val, T: t_val };

    let mut hasher_input_bytes: Vec<u8> = Vec::new();
    instance.g.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for g")?;
    instance.h.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for h")?;
    instance.g_P.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for g_P")?;
    instance.h_P.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for h_P")?;
    instance.initial_ciphertexts.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for initial_ciphertexts")?;
    instance.final_ciphertexts.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for final_ciphertexts")?;
    instance.public_keys.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for public_keys")?;
    instance.perm_commitments.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for perm_commitments")?;
    proof_commitments.A_i.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for A_i")?;
    proof_commitments.B_i.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for B_i")?;
    proof_commitments.S.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for S")?;
    proof_commitments.T.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for T")?;

    let challenge_x = G::hash_to_scalar(&hasher_input_bytes);

    let k_prime_elements_arr = Array::from_fn(|i| {
        let r_prime_for_c_pi_inv_i = &witness.rerandomization_factors.0[pi_inv_map[i]];
        kappa_i_vec.0[i].sub(&challenge_x.mul(r_prime_for_c_pi_inv_i))
    });

    let r_prime_elements_arr = Array::from_fn(|i| {
        let k_for_p_pi_inv_i = &witness.perm_commitment_randomness.0[pi_inv_map[i]];
        rho_i_vec.0[i].sub(&challenge_x.mul(k_for_p_pi_inv_i))
    });

    let sum_rerand_factors = witness.rerandomization_factors.0.iter().fold(G::Scalar::zero(), |acc, val| acc.add(val));
    let s_prime_val = sigma_scalar.sub(&challenge_x.mul(&sum_rerand_factors));

    let t_prime_elements_arr = Array::from_fn(|j| {
        let k_j = &witness.perm_commitment_randomness.0[j];
        tau_vec.0[j].sub(&challenge_x.mul(k_j))
    });

    let proof_responses = ShuffleProofResponses {
        k_prime_vec: Product(k_prime_elements_arr),
        r_prime_vec: Product(r_prime_elements_arr),
        s_prime: s_prime_val,
        t_prime_vec: Product(t_prime_elements_arr),
    };

    Ok(ShuffleProof { commitments: proof_commitments, responses: proof_responses })
}


#[allow(clippy::too_many_locals)]
pub fn verify<G: CryptoGroup, N: ArraySize>(
    instance: &ShuffleInstance<G, N>,
    proof: &ShuffleProof<G, N>,
) -> Result<bool, &'static str>
where
    G::Scalar: GroupScalar + FSerializable,
    G::Element: GroupElement + FSerializable,
    Product<G::Element, U2>: FSerializable + Clone,
    Product<Product<G::Element, U2>, N>: FSerializable,
    Product<G::Element, N>: FSerializable,
    Product<G::Scalar, N>: FSerializable,
    G::Element: Clone,
    G::Scalar: Clone,
    Ciphertext<G>: Clone,
{
    let n_usize = N::to_usize();

    let mut hasher_input_bytes: Vec<u8> = Vec::new();
    instance.g.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for g")?;
    instance.h.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for h")?;
    instance.g_P.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for g_P")?;
    instance.h_P.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for h_P")?;
    instance.initial_ciphertexts.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for initial_ciphertexts")?;
    instance.final_ciphertexts.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for final_ciphertexts")?;
    instance.public_keys.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for public_keys")?;
    instance.perm_commitments.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for perm_commitments")?;
    proof.commitments.A_i.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for A_i")?;
    proof.commitments.B_i.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for B_i")?;
    proof.commitments.S.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for S")?;
    proof.commitments.T.serialize(&mut hasher_input_bytes).map_err(|_| "Serialization failed for T")?;

    let challenge_x = G::hash_to_scalar(&hasher_input_bytes);

    let identity_element = G::Element::identity();
    let identity_ciphertext = Ciphertext::new([identity_element.clone(), identity_element.clone()]);

    let initial_ciphertexts_perm_by_pi_inv = instance.initial_ciphertexts_perm_by_pi_inv.as_ref()
        .ok_or("Missing initial_ciphertexts_perm_by_pi_inv in instance (placeholder for verify)")?;
    let perm_commitments_perm_by_pi_inv = instance.perm_commitments_perm_by_pi_inv.as_ref()
        .ok_or("Missing perm_commitments_perm_by_pi_inv in instance (placeholder for verify)")?;
    let prod_perm_commitments_perm_by_pi_inv = instance.prod_perm_commitments_perm_by_pi_inv.as_ref()
        .ok_or("Missing prod_perm_commitments_perm_by_pi_inv in instance (placeholder for verify)")?;

    for i in 0..n_usize {
        let c_pi_inv_i = &initial_ciphertexts_perm_by_pi_inv.0[i];
        let c_prime_i = &instance.final_ciphertexts.0[i];
        let c_prime_i_pow_x = ciphertext_exp(c_prime_i, &challenge_x);

        let lhs1_part = ciphertext_mul(&proof.commitments.A_i.0[i], c_pi_inv_i);
        let lhs1 = ciphertext_mul(&lhs1_part, &c_prime_i_pow_x);

        let pk_i = &instance.public_keys.0[i];
        let k_prime_i = &proof.responses.k_prime_vec.0[i];
        let r_prime_i_for_ve1 = &proof.responses.r_prime_vec.0[i];

        let rhs1_ct = Ciphertext::new([
            pk_i.add_element(&instance.g.scalar_mul(k_prime_i)),
            instance.h.scalar_mul(r_prime_i_for_ve1)
        ]);

        if !lhs1.0.iter().zip(rhs1_ct.0.iter()).all(|(a,b)| a.equals(b)) {
            return Ok(false);
        }
    }

    for i in 0..n_usize {
        let c_prime_i = &instance.final_ciphertexts.0[i];
        let p_i = &instance.perm_commitments.0[i];
        let p_i_pow_x = p_i.scalar_mul(&challenge_x);

        let lhs2_ciph = ciphertext_mul(&proof.commitments.B_i.0[i], c_prime_i);
        let lhs2 = Ciphertext::new([lhs2_ciph.0[0].add_element(&p_i_pow_x), lhs2_ciph.0[1].clone()]);

        let pk_i = &instance.public_keys.0[i];
        let p_pi_inv_i = &perm_commitments_perm_by_pi_inv.0[i];
        let r_prime_i_for_ve2 = &proof.responses.r_prime_vec.0[i];
        let t_prime_i = &proof.responses.t_prime_vec.0[i];

        let rhs2_ct = Ciphertext::new([
            pk_i.add_element(&instance.g.scalar_mul(r_prime_i_for_ve2)),
            p_pi_inv_i.add_element(&instance.h.scalar_mul(t_prime_i))
        ]);

        if !lhs2.0.iter().zip(rhs2_ct.0.iter()).all(|(a,b)| a.equals(b)) {
            return Ok(false);
        }
    }

    let prod_c_j = instance.initial_ciphertexts.0.iter().fold(identity_ciphertext.clone(), |a, c| ciphertext_mul(&a, c));
    let prod_c_prime_j = instance.final_ciphertexts.0.iter().fold(identity_ciphertext.clone(), |a, c| ciphertext_mul(&a, c));
    let prod_c_prime_j_pow_x = ciphertext_exp(&prod_c_prime_j, &challenge_x);

    let lhs3_part = ciphertext_mul(&proof.commitments.S, &prod_c_j);
    let lhs3 = ciphertext_mul(&lhs3_part, &prod_c_prime_j_pow_x);

    let prod_pk_j = instance.public_keys.0.iter().fold(identity_element.clone(), |a, pk| a.add_element(pk));
    let s_prime_resp = &proof.responses.s_prime;
    let sum_t_prime_j = proof.responses.t_prime_vec.0.iter().fold(G::Scalar::zero(), |a, t| a.add(t));

    let rhs3_ct = Ciphertext::new([
        prod_pk_j.add_element(&instance.g.scalar_mul(s_prime_resp)),
        instance.h.scalar_mul(&sum_t_prime_j)
    ]);

    if !lhs3.0.iter().zip(rhs3_ct.0.iter()).all(|(a,b)| a.equals(b)) {
        return Ok(false);
    }

    let prod_p_j = instance.perm_commitments.0.iter().fold(identity_element.clone(), |a, p| a.add_element(p));
    let prod_p_j_pow_x = prod_p_j.scalar_mul(&challenge_x);

    let lhs4_part = ciphertext_mul(&proof.commitments.T, &prod_c_prime_j);
    let lhs4 = Ciphertext::new([lhs4_part.0[0].add_element(&prod_p_j_pow_x), lhs4_part.0[1].clone()]);

    let sum_r_prime_j = proof.responses.r_prime_vec.0.iter().fold(G::Scalar::zero(), |a, r| a.add(r));

    let rhs4_ct = Ciphertext::new([
        prod_pk_j.add_element(&instance.g.scalar_mul(&sum_r_prime_j)),
        prod_perm_commitments_perm_by_pi_inv.add_element(&instance.h.scalar_mul(&sum_t_prime_j))
    ]);

    if !lhs4.0.iter().zip(rhs4_ct.0.iter()).all(|(a,b)| a.equals(b)) {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{Ristretto255Group, RistrettoElement, RistrettoScalar};
    use hybrid_array::typenum::{U3}; // Specific typenum for test size
    // Assuming RistrettoElement and RistrettoScalar implement PartialEq for direct comparison in tests.
    // If not, assertions in test_shuffle_serialization might need to rely solely on re-verification.

    type TestGroup = Ristretto255Group;
    type TestSizeN = U3; // Shuffle of 3 elements

    // Helper function to create ElGamal ciphertext (C1, C2) = (g^r, pk^r * M)
    // M is represented as g^m_scalar
    fn elgamal_encrypt(
        g: &RistrettoElement,
        pk: &RistrettoElement,
        m_scalar: &RistrettoScalar,
        r: &RistrettoScalar,
    ) -> Ciphertext<TestGroup> {
        let c1 = g.scalar_mul(r);
        let m_element = g.scalar_mul(m_scalar); // M = g^m_scalar
        let c2 = pk.scalar_mul(r).add_element(&m_element);
        Ciphertext::new([c1, c2])
    }

    #[allow(clippy::type_complexity)]
    fn create_dummy_instance_and_witness(
    ) -> (ShuffleInstance<TestGroup, TestSizeN>, ShuffleWitness<TestGroup, TestSizeN>) {
        let n_usize = TestSizeN::to_usize();
        let mut rng = DefaultRng::new();

        let g = TestGroup::generator();
        let h = TestGroup::hash_to_element(b"h_gen_for_shuffle_tests");
        let g_P = TestGroup::hash_to_element(b"gP_gen_for_shuffle_tests");
        let h_P = TestGroup::hash_to_element(b"hP_gen_for_shuffle_tests");

        let sk_vec: Vec<RistrettoScalar> = (0..n_usize).map(|_| TestGroup::Scalar::random(&mut rng)).collect();
        let public_keys_arr = Array::from_fn(|i| g.scalar_mul(&sk_vec[i]));
        let public_keys = Product(public_keys_arr.clone());

        let messages_as_scalars: Vec<RistrettoScalar> = (0..n_usize).map(|_| TestGroup::Scalar::random(&mut rng)).collect();
        let initial_rand_factors: Vec<RistrettoScalar> = (0..n_usize).map(|_| TestGroup::Scalar::random(&mut rng)).collect();

        let initial_ciphertexts_arr = Array::from_fn(|i| {
            elgamal_encrypt(&g, &public_keys.0[i], &messages_as_scalars[i], &initial_rand_factors[i])
        });
        let initial_ciphertexts = Product(initial_ciphertexts_arr.clone());

        let witness_perm_indices_usize: Vec<usize> = match n_usize {
            3 => vec![2, 0, 1], // 0->2, 1->0, 2->1
            _ => (0..n_usize).collect(),
        };

        let permutation_scalars_arr = Array::from_fn(|i| TestGroup::Scalar::from_u64(witness_perm_indices_usize[i] as u64));
        let permutation_witness = Product(permutation_scalars_arr);

        let rerandomization_factors_arr = Array::from_fn(|_| TestGroup::Scalar::random(&mut rng));
        let rerandomization_factors_witness = Product(rerandomization_factors_arr.clone());

        let perm_commitment_randomness_arr = Array::from_fn(|_| TestGroup::Scalar::random(&mut rng));
        let perm_commitment_randomness_witness = Product(perm_commitment_randomness_arr.clone());

        let perm_commitments_arr = Array::from_fn(|j| {
            compute_perm_commitment::<TestGroup>(
                &TestGroup::Scalar::from_u64(witness_perm_indices_usize[j] as u64),
                &perm_commitment_randomness_witness.0[j],
                &g_P,
                &h_P,
            )
        });
        let perm_commitments = Product(perm_commitments_arr.clone());

        let mut pi_inv_map_usize = vec![0usize; n_usize];
        for j in 0..n_usize {
            pi_inv_map_usize[witness_perm_indices_usize[j]] = j;
        }

        let final_ciphertexts_arr = Array::from_fn(|i_new_idx| {
            let original_idx = pi_inv_map_usize[i_new_idx];
            let original_ciphertext = &initial_ciphertexts.0[original_idx];
            let pk_for_final_ct = &public_keys.0[i_new_idx];
            let r_prime_for_final_ct = &rerandomization_factors_witness.0[i_new_idx];

            let x_prime = original_ciphertext.0[0].add_element(&g.scalar_mul(r_prime_for_final_ct));
            let y_prime = original_ciphertext.0[1].add_element(&pk_for_final_ct.scalar_mul(r_prime_for_final_ct));
            Ciphertext::new([x_prime, y_prime])
        });
        let final_ciphertexts = Product(final_ciphertexts_arr);

        let initial_ciphertexts_perm_by_pi_inv_arr = Array::from_fn(|i_new_idx| {
            initial_ciphertexts.0[pi_inv_map_usize[i_new_idx]].clone()
        });
        let initial_ciphertexts_perm_by_pi_inv = Some(Product(initial_ciphertexts_perm_by_pi_inv_arr));

        let perm_commitments_perm_by_pi_inv_arr = Array::from_fn(|i_new_idx| {
            perm_commitments.0[pi_inv_map_usize[i_new_idx]].clone()
        });
        let perm_commitments_perm_by_pi_inv = Some(Product(perm_commitments_perm_by_pi_inv_arr));

        let prod_perm_commitments_perm_by_pi_inv_val = perm_commitments_perm_by_pi_inv.as_ref().unwrap().0
            .iter().fold(TestGroup::Element::identity(), |acc, p_val| acc.add_element(p_val));
        let prod_perm_commitments_perm_by_pi_inv = Some(prod_perm_commitments_perm_by_pi_inv_val);

        let instance = ShuffleInstance {
            initial_ciphertexts,
            final_ciphertexts,
            public_keys,
            perm_commitments,
            g, h, g_P, h_P,
            initial_ciphertexts_perm_by_pi_inv,
            perm_commitments_perm_by_pi_inv,
            prod_perm_commitments_perm_by_pi_inv,
        };

        let witness = ShuffleWitness {
            permutation: permutation_witness,
            rerandomization_factors: rerandomization_factors_witness,
            perm_commitment_randomness: perm_commitment_randomness_witness,
        };

        (instance, witness)
    }

    #[test]
    fn test_shuffle_prove_verify_valid() {
        let (instance, witness) = create_dummy_instance_and_witness();
        let proof_result = prove(&instance, &witness);
        assert!(proof_result.is_ok(), "Prove failed: {:?}", proof_result.err());
        let proof = proof_result.unwrap();

        let verify_result = verify(&instance, &proof);
        assert!(verify_result.is_ok(), "Verify failed: {:?}", verify_result.err());
        assert!(verify_result.unwrap(), "Verification of a valid proof failed");
    }

    #[test]
    fn test_shuffle_tampered_proof() {
        let (instance, witness) = create_dummy_instance_and_witness();
        let proof_result = prove(&instance, &witness);
        assert!(proof_result.is_ok(), "Prove failed for tampering test: {:?}", proof_result.err());
        let mut proof = proof_result.unwrap();

        // Tamper one scalar response
        proof.responses.s_prime = proof.responses.s_prime.add(&TestGroup::Scalar::one());

        let verify_result = verify(&instance, &proof);
        assert!(verify_result.is_ok(), "Verify (after tamper) failed itself: {:?}", verify_result.err());
        assert!(!verify_result.unwrap(), "Verification of a tampered proof succeeded");
    }

    #[test]
    fn test_shuffle_serialization() {
        let (instance, witness) = create_dummy_instance_and_witness();
        let proof = prove(&instance, &witness).expect("Prove failed for serialization test");

        // Test serialization
        let mut serialized_proof_bytes = Vec::new();
        proof.serialize(&mut serialized_proof_bytes).expect("Serialization failed");

        // Test Size trait if available and gives a concrete size
        // Note: Size trait might return a type number, not a direct usize.
        // For simplicity, we check if serialized_proof_bytes has some length.
        // A more precise check would be:
        // let expected_size = <ShuffleProof<TestGroup, TestSizeN> as Size>::OutputSize::to_usize();
        // assert_eq!(serialized_proof_bytes.len(), expected_size, "Serialized proof length mismatch");
        // This requires OutputSize to be a typenum that can be converted to usize.
        // For now, just check it's not empty as a basic sanity check.
        assert!(!serialized_proof_bytes.is_empty(), "Serialized proof is empty");


        // Test deserialization
        let deserialized_proof_result = ShuffleProof::<TestGroup, TestSizeN>::deserialize(&serialized_proof_bytes[..]);
        assert!(deserialized_proof_result.is_ok(), "Deserialization failed: {:?}", deserialized_proof_result.err());
        let deserialized_proof = deserialized_proof_result.unwrap();

        // Check equality of original and deserialized proof
        // This requires ShuffleProof and its members to derive PartialEq,
        // and for the underlying group elements/scalars to correctly implement PartialEq.
        // Added #[cfg_attr(test, derive(PartialEq))] to proof structs.
        assert_eq!(proof, deserialized_proof, "Original and deserialized proofs are not equal");

        // Optionally, verify the deserialized proof again
        let verify_result = verify(&instance, &deserialized_proof);
        assert!(verify_result.is_ok(), "Verify (after deserialization) failed: {:?}", verify_result.err());
        assert!(verify_result.unwrap(), "Verification of deserialized proof failed");
    }
}
