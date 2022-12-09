use std::iter;

use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

use crate::{
    constants::{EXTENDED_DOMAIN_FACTOR, NUMBER_OF_MIMC_ROUNDS, SUBGROUP_SIZE},
    utils::compute_vanishing_poly_over_coset,
};

pub mod prover;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverPrecomputedData<F: PrimeField> {
    pub(crate) c_coset_evals: Vec<F>, // evaluations of mimc round constants over coset
    pub(crate) zh_inverse_coset_evals: Vec<F>, // evaluations of vanishing poly over coset
    pub(crate) q_mimc_coset_evals: Vec<F>,
    pub(crate) l0_coset_evals: Vec<F>,
}

impl<F: PrimeField> ProverPrecomputedData<F> {
    pub fn index(mimc_round_constants: &Vec<F>, dummy_value: F) -> Self {
        let domain = GeneralEvaluationDomain::<F>::new(SUBGROUP_SIZE).unwrap();
        let extended_coset_domain =
            GeneralEvaluationDomain::<F>::new(EXTENDED_DOMAIN_FACTOR * SUBGROUP_SIZE).unwrap();

        // Compute zh inverse coset evals
        let mut zh_inverse_coset_evals =
            compute_vanishing_poly_over_coset(extended_coset_domain.clone(), domain.size() as u64);
        ark_ff::batch_inversion(&mut zh_inverse_coset_evals);

        // Compute c coset evals
        assert_eq!(mimc_round_constants.len(), NUMBER_OF_MIMC_ROUNDS);
        let mut c_evals = mimc_round_constants[..].to_vec();
        let mut to_append: Vec<F> = iter::repeat(dummy_value)
            .take(SUBGROUP_SIZE - c_evals.len())
            .collect();
        c_evals.append(&mut to_append);

        let c_poly = DensePolynomial::from_coefficients_slice(&domain.ifft(&c_evals));
        let c_coset_evals = extended_coset_domain.coset_fft(&c_poly);

        // Compute q_mimc coset evals
        let mut q_mimc_evals: Vec<F> = iter::repeat(F::one()).take(NUMBER_OF_MIMC_ROUNDS).collect();
        let mut zeroes: Vec<F> = iter::repeat(F::zero())
            .take(SUBGROUP_SIZE - NUMBER_OF_MIMC_ROUNDS)
            .collect();
        q_mimc_evals.append(&mut zeroes);

        let q_mimc = DensePolynomial::from_coefficients_slice(&domain.ifft(&q_mimc_evals));
        let q_mimc_coset_evals = extended_coset_domain.coset_fft(&q_mimc);

        // Compute l0 coset evals
        let mut l0_evals = vec![F::zero(); domain.size()];
        l0_evals[0] = F::one();

        let l0 = DensePolynomial::from_coefficients_slice(&domain.ifft(&l0_evals));
        let l0_coset_evals = extended_coset_domain.coset_fft(&l0);

        Self {
            c_coset_evals,
            zh_inverse_coset_evals,
            q_mimc_coset_evals,
            l0_coset_evals,
        }
    }
}

pub struct ProverKey<E: PairingEngine> {
    pub(crate) srs_g1: Vec<E::G1Affine>,
    pub(crate) srs_g2: Vec<E::G2Affine>,
}
