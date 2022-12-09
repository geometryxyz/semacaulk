use std::collections::BTreeMap;

use ark_ec::PairingEngine;
use ark_ff::One;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    UVPolynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

use crate::kzg::commit;

/*
   Precomputed data will be stored in <key, value> map for key = index, value = [w_{1,2}^i]_2

   We can precompute all data, but it's very possible that just some indices will be needed,
   so we optimize precomputed data needed to store
*/
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Precomputed<E: PairingEngine> {
    w1_mapping: BTreeMap<usize, E::G2Affine>,
    w2_mapping: BTreeMap<usize, E::G2Affine>,
}

impl<E: PairingEngine> Precomputed<E> {
    pub fn empty() -> Self {
        Self {
            w1_mapping: BTreeMap::default(),
            w2_mapping: BTreeMap::default(),
        }
    }
    pub fn get_w1_i(&self, index: &usize) -> E::G2Affine {
        match self.w1_mapping.get(index) {
            Some(element) => *element,
            None => panic!("Element on index: {} is not precomputed", index),
        }
    }

    pub fn get_w2_i(&self, index: &usize) -> E::G2Affine {
        match self.w2_mapping.get(index) {
            Some(element) => *element,
            None => panic!("Element on index: {} is not precomputed", index),
        }
    }

    pub fn precompute_w1(
        &mut self,
        srs: &[E::G2Affine],
        indices: &[usize],
        c: &DensePolynomial<E::Fr>,
        domain: &GeneralEvaluationDomain<E::Fr>,
    ) {
        for index in indices {
            let w_i = domain.element(*index);
            let mut num = c.clone();
            num[0] -= c.evaluate(&w_i);

            let denom = DensePolynomial::from_coefficients_slice(&[-w_i, E::Fr::one()]);
            let w1_i = &num / &denom;
            let w1_i = commit(srs, &w1_i);
            self.w1_mapping.insert(*index, w1_i.into());
        }
    }

    pub fn precompute_w2(
        &mut self,
        srs: &[E::G2Affine],
        indices: &[usize],
        domain: &GeneralEvaluationDomain<E::Fr>,
    ) {
        let zh: DensePolynomial<_> = domain.vanishing_polynomial().into();
        for index in indices {
            let w2_i = &zh
                / &DensePolynomial::from_coefficients_slice(&[
                    -domain.element(*index),
                    E::Fr::one(),
                ]);
            let w2_i = commit(srs, &w2_i);
            self.w2_mapping.insert(*index, w2_i.into());
        }
    }
}

#[cfg(test)]
mod precomputed_test {
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
    };
    use ark_std::test_rng;

    use ark_bn254::{Bn254, Fr as F, G1Affine, G2Projective};
    use rand::rngs::StdRng;

    use crate::kzg::{commit, unsafe_setup};
    use crate::utils::construct_lagrange_basis;

    use super::Precomputed;

    // TODO: make this as a macro
    fn to_field<F: Field>(evals: &[u64]) -> Vec<F> {
        evals.iter().map(|&e| F::from(e)).collect()
    }

    // zH = w2 * zI
    fn compute_w2<E: PairingEngine>(
        precomputed: &Precomputed<E>,
        indices: &[usize],
        domain: &GeneralEvaluationDomain<E::Fr>,
    ) -> E::G2Affine {
        let mut w2 = E::G2Projective::zero();
        for i in indices {
            let w2_i = precomputed.get_w2_i(i);

            let omega_i = domain.element(*i);
            let mut denom = E::Fr::one();
            for j in indices {
                if j != i {
                    denom *= omega_i - domain.element(*j);
                }
            }

            let denom_inv = denom.inverse().unwrap();
            w2 = w2 + w2_i.mul(denom_inv);
        }
        w2.into()
    }

    // C - cI = zH * w1
    fn compute_w1<E: PairingEngine>(
        precomputed: &Precomputed<E>,
        indices: &[usize],
        domain: &GeneralEvaluationDomain<E::Fr>,
    ) -> E::G2Affine {
        let mut w1 = E::G2Projective::zero();
        for i in indices {
            let w1_i = precomputed.get_w1_i(i);

            let omega_i = domain.element(*i);
            let mut denom = E::Fr::one();
            for j in indices {
                if j != i {
                    denom *= omega_i - domain.element(*j);
                }
            }

            let denom_inv = denom.inverse().unwrap();
            w1 = w1 + w1_i.mul(denom_inv);
        }

        w1.into()
    }

    #[test]
    fn test_w2() {
        let mut rng = test_rng();
        let max_power = 8;
        let h = 8;
        let domain = GeneralEvaluationDomain::<F>::new(h).unwrap();

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);
        let zh_c = srs_g1[domain.size()] + -G1Affine::prime_subgroup_generator();

        let indices = [1, 3, 4, 5, 7];

        let mut precomputed = Precomputed::<Bn254>::empty();

        precomputed.precompute_w2(&srs_g2, &indices, &domain);

        let mut zi = DensePolynomial::<F>::from_coefficients_slice(&[F::one()]);
        for i in &indices {
            let omega_i = domain.element(*i);
            zi = &zi * &DensePolynomial::from_coefficients_slice(&[-omega_i, F::one()]);
        }

        let zi_c = commit(&srs_g1, &zi).into_affine();
        let w2 = compute_w2::<Bn254>(&precomputed, &indices, &domain);

        let lhs = Bn254::pairing(zh_c, srs_g2[0]);
        let rhs = Bn254::pairing(zi_c, w2);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_w1() {
        let mut rng = test_rng();
        let max_power = 8;
        let h = 8;
        let domain = GeneralEvaluationDomain::<F>::new(h).unwrap();

        let indices = [1, 3, 4, 5, 7];
        let elems: Vec<_> = indices.iter().map(|&i| domain.element(i)).collect();
        let t_bases = construct_lagrange_basis(&elems);

        let c_evals = [12391, 3219031, 32131, 412331, 31231, 3213, 938532, 49802342];
        let c_evals = to_field::<F>(&c_evals);
        let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&c_evals));

        let ci_evals = indices.iter().map(|&i| c_evals[i]);
        let mut ci = DensePolynomial::zero();
        for (ti, eval) in t_bases.iter().zip(ci_evals) {
            ci += &(ti * eval)
        }

        let ci_fft_evals = domain.fft(&ci);

        for (i, (c, cf)) in c_evals.iter().zip(ci_fft_evals.iter()).enumerate() {
            if c == cf {
                assert_eq!(true, indices.contains(&i));
            }
        }

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);

        let c_commitment = commit(&srs_g1, &c);
        let ci_commitment = commit(&srs_g1, &ci);

        let mut precomputed = Precomputed::<Bn254>::empty();

        precomputed.precompute_w1(&srs_g2, &indices, &c, &domain);

        let mut zi = DensePolynomial::<F>::from_coefficients_slice(&[F::one()]);
        for i in &indices {
            let omega_i = domain.element(*i);
            zi = &zi * &DensePolynomial::from_coefficients_slice(&[-omega_i, F::one()]);
        }

        let zi_c = commit(&srs_g1, &zi).into_affine();
        let w1 = compute_w1::<Bn254>(&precomputed, &indices, &domain);

        let q = &(c.clone() + -ci.clone()) / &zi;
        assert_eq!(&q * &zi, c.clone() + -ci.clone());

        let quotient_commitment = commit(&srs_g2, &q);
        assert_eq!(quotient_commitment, w1);

        let lhs = Bn254::pairing(c_commitment + -ci_commitment, srs_g2[0]);
        let rhs = Bn254::pairing(zi_c, w1);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_combined() {
        let mut rng = test_rng();
        let max_power = 8;
        let h = 8;
        let domain = GeneralEvaluationDomain::<F>::new(h).unwrap();

        let indices = [1, 3, 4, 5, 7];
        let elems: Vec<_> = indices.iter().map(|&i| domain.element(i)).collect();
        let t_bases = construct_lagrange_basis(&elems);

        let c_evals = [12391, 3219031, 32131, 412331, 31231, 3213, 938532, 49802342];
        let c_evals = to_field::<F>(&c_evals);
        let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&c_evals));

        let ci_evals = indices.iter().map(|&i| c_evals[i]);
        let mut ci = DensePolynomial::zero();
        for (ti, eval) in t_bases.iter().zip(ci_evals) {
            ci += &(ti * eval)
        }

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);

        let zh_c = srs_g1[domain.size()] + -G1Affine::prime_subgroup_generator();
        let c_commitment = commit(&srs_g1, &c);
        let ci_commitment = commit(&srs_g1, &ci);

        let mut precomputed = Precomputed::<Bn254>::empty();

        precomputed.precompute_w1(&srs_g2, &indices, &c, &domain);
        precomputed.precompute_w2(&srs_g2, &indices, &domain);

        let mut zi = DensePolynomial::<F>::from_coefficients_slice(&[F::one()]);
        for i in &indices {
            let omega_i = domain.element(*i);
            zi = &zi * &DensePolynomial::from_coefficients_slice(&[-omega_i, F::one()]);
        }

        let zi_c = commit(&srs_g1, &zi).into_affine();
        let w1 = compute_w1::<Bn254>(&precomputed, &indices, &domain);
        let w2 = compute_w2::<Bn254>(&precomputed, &indices, &domain);

        let xi_2 = F::rand(&mut rng);

        let w1_xi2_w2 = w1 + w2.mul(xi_2.into_repr()).into();

        let lhs = Bn254::pairing(
            (c_commitment + -ci_commitment) + zh_c.mul(xi_2.into_repr()),
            srs_g2[0],
        );
        let rhs = Bn254::pairing(zi_c, w1_xi2_w2);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_combined_masked() {
        let mut rng = test_rng();
        let max_power = 8;
        let h = 8;
        let domain = GeneralEvaluationDomain::<F>::new(h).unwrap();

        let indices = [1, 3, 4, 5, 7];
        let elems: Vec<_> = indices.iter().map(|&i| domain.element(i)).collect();
        let t_bases = construct_lagrange_basis(&elems);

        let c_evals = [12391, 3219031, 32131, 412331, 31231, 3213, 938532, 49802342];
        let c_evals = to_field::<F>(&c_evals);
        let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&c_evals));

        let ci_evals = indices.iter().map(|&i| c_evals[i]);
        let mut ci = DensePolynomial::zero();
        for (ti, eval) in t_bases.iter().zip(ci_evals) {
            ci += &(ti * eval)
        }

        let r1 = F::rand(&mut rng);
        let r2 = F::rand(&mut rng);
        let r3 = F::rand(&mut rng);
        let r4 = F::rand(&mut rng);

        let mut zi = DensePolynomial::<F>::from_coefficients_slice(&[r1]);
        for i in &indices {
            let omega_i = domain.element(*i);
            zi = &zi * &DensePolynomial::from_coefficients_slice(&[-omega_i, F::one()]);
        }

        let c_blinder_times_zi = &DensePolynomial::from_coefficients_slice(&[r2, r3, r4]) * &zi;
        ci += &c_blinder_times_zi;

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);

        let zh_c = srs_g1[domain.size()] + -G1Affine::prime_subgroup_generator();
        let c_commitment = commit(&srs_g1, &c);
        let ci_commitment = commit(&srs_g1, &ci);

        let c_blinder = &DensePolynomial::from_coefficients_slice(&[r2, r3, r4]);
        let c_blinder_commitment = commit(&srs_g2, &c_blinder);

        let mut precomputed = Precomputed::<Bn254>::empty();

        precomputed.precompute_w1(&srs_g2, &indices, &c, &domain);
        precomputed.precompute_w2(&srs_g2, &indices, &domain);

        let zi_c = commit(&srs_g1, &zi).into_affine();
        let w1 = compute_w1::<Bn254>(&precomputed, &indices, &domain);
        let w2 = compute_w2::<Bn254>(&precomputed, &indices, &domain);

        let xi_2 = F::rand(&mut rng);

        let w1_xi2_w2 = (w1 + w2.mul(xi_2.into_repr()).into())
            .mul(r1.inverse().unwrap().into_repr())
            - c_blinder_commitment;

        let lhs = Bn254::pairing(
            (c_commitment - ci_commitment) + zh_c.mul(xi_2.into_repr()),
            srs_g2[0],
        );
        let rhs = Bn254::pairing(zi_c, w1_xi2_w2);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_w1_w2_computation() {
        let mut rng = test_rng();
        let max_power = 8;
        let h = 8;
        let domain = GeneralEvaluationDomain::<F>::new(h).unwrap();

        let indices = [1, 3, 4, 5, 7];
        let elems: Vec<_> = indices.iter().map(|&i| domain.element(i)).collect();
        let t_bases = construct_lagrange_basis(&elems);

        let c_evals = [12391, 3219031, 32131, 412331, 31231, 3213, 938532, 49802342];
        let c_evals = to_field::<F>(&c_evals);
        let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&c_evals));

        let ci_evals = indices.iter().map(|&i| c_evals[i]);
        let mut ci = DensePolynomial::zero();
        for (ti, eval) in t_bases.iter().zip(ci_evals) {
            ci += &(ti * eval)
        }

        let (_, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);

        let mut precomputed = Precomputed::<Bn254>::empty();

        precomputed.precompute_w1(&srs_g2, &indices, &c, &domain);
        precomputed.precompute_w2(&srs_g2, &indices, &domain);

        let xi_2 = F::rand(&mut rng);

        let mut w1_xi2_w2 = G2Projective::zero();
        for i in &indices {
            let w1_i = precomputed.get_w1_i(i);
            let w2_i = precomputed.get_w2_i(i);

            let omega_i = domain.element(*i);
            let mut denom = F::one();
            for j in &indices {
                if j != i {
                    denom *= omega_i - domain.element(*j);
                }
            }

            let denom_inv = denom.inverse().unwrap();
            w1_xi2_w2 = w1_xi2_w2 + w1_i.mul(denom_inv) + w2_i.mul(denom_inv * xi_2);
        }

        let w1 = compute_w1::<Bn254>(&precomputed, &indices, &domain);
        let w2 = compute_w2::<Bn254>(&precomputed, &indices, &domain);

        let w1_xi2_w2_by_hand = w1 + w2.mul(xi_2.into_repr()).into();

        assert_eq!(w1_xi2_w2, w1_xi2_w2_by_hand);
    }
}
