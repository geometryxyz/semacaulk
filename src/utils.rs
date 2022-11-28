use std::{cmp::max, iter};

use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{FftField, Field, One, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_std::{rand::RngCore, UniformRand};

pub fn shift_dense_poly<F: Field>(
    p: &DensePolynomial<F>,
    shifting_factor: &F,
) -> DensePolynomial<F> {
    if *shifting_factor == F::one() {
        return p.clone();
    }

    let mut coeffs = p.coeffs().to_vec();
    let mut acc = F::one();
    for i in 0..coeffs.len() {
        coeffs[i] = coeffs[i] * acc;
        acc *= shifting_factor;
    }

    DensePolynomial::from_coefficients_vec(coeffs)
}

// given x coords construct Li polynomials
pub fn construct_lagrange_basis<F: FftField>(evaluation_domain: &[F]) -> Vec<DensePolynomial<F>> {
    let mut bases = Vec::with_capacity(evaluation_domain.len());
    for i in 0..evaluation_domain.len() {
        let mut l_i = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let x_i = evaluation_domain[i];
        for j in 0..evaluation_domain.len() {
            if j != i {
                let xi_minus_xj_inv = (x_i - evaluation_domain[j]).inverse().unwrap();
                l_i = &l_i
                    * &DensePolynomial::from_coefficients_slice(&[
                        -evaluation_domain[j] * xi_minus_xj_inv,
                        xi_minus_xj_inv,
                    ]);
            }
        }

        bases.push(l_i);
    }

    bases
}

#[cfg(test)]
mod util_tests {
    use ark_bn254::Fr as F;
    use ark_ff::Zero;
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
    };

    use super::construct_lagrange_basis;
    #[test]
    fn test_lagrange_bases() {
        let domain_size = 8;
        let domain = GeneralEvaluationDomain::<F>::new(domain_size).unwrap();

        let elems: Vec<F> = domain.elements().collect();
        let bases = construct_lagrange_basis(&elems);
        assert_eq!(bases.len(), domain.size());

        let to_field = |x: &u64| -> F { F::from(*x) };

        let evals: [u64; 8] = [
            930182301,
            321513131,
            3219031,
            3213941,
            2131,
            31931,
            3901820491,
            83192083109,
        ];
        let evals: Vec<F> = evals.iter().map(|x| to_field(x)).collect();

        let f_from_ifft = DensePolynomial::from_coefficients_slice(&domain.ifft(&evals));

        let mut f_from_bases = DensePolynomial::<F>::zero();
        for (l_i, &eval_i) in bases.iter().zip(evals.iter()) {
            f_from_bases += &(l_i * eval_i);
        }

        assert_eq!(f_from_bases, f_from_ifft);
    }
}
