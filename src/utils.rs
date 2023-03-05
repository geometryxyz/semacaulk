use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use std::iter;

pub fn positive_rotation_in_coset<F: PrimeField>(
    coset_evals: &[F],
    omega_i: usize,
    rotation_degree: usize,
    scaling_ratio: usize,
) -> F {
    coset_evals[(omega_i + rotation_degree * scaling_ratio) % coset_evals.len()]
}

pub fn compute_vanishing_poly_over_coset<F, D>(
    domain: D,        // domain to evaluate over
    poly_degree: u64, // degree of the vanishing polynomial
) -> Vec<F>
where
    F: PrimeField,
    D: EvaluationDomain<F>,
{
    assert!(
        (domain.size() as u64) > poly_degree,
        "domain_size = {}, poly_degree = {}",
        domain.size() as u64,
        poly_degree
    );
    let group_gen = domain.element(1);
    let coset_gen = F::multiplicative_generator().pow([poly_degree, 0, 0, 0]);
    let v_h: Vec<_> = (0..domain.size())
        .map(|i| (coset_gen * group_gen.pow([poly_degree * i as u64, 0, 0, 0])) - F::one())
        .collect();
    v_h
}

pub fn shift_dense_poly<F: Field>(
    p: &DensePolynomial<F>,
    shifting_factor: &F,
) -> DensePolynomial<F> {
    if *shifting_factor == F::one() {
        return p.clone();
    }

    let mut coeffs = p.coeffs().to_vec();
    let mut acc = F::one();
    for coeff_i in &mut coeffs {
        *coeff_i *= acc;
        acc *= shifting_factor;
    }

    DensePolynomial::from_coefficients_vec(coeffs)
}

pub fn construct_lagrange_basis_poly<F: FftField>(
    evaluation_domain: &[F],
    index: usize
) -> DensePolynomial<F> {
    let mut l_i = DensePolynomial::from_coefficients_slice(&[F::one()]);
    let x_i = evaluation_domain[index];

    for (j, &x_j) in evaluation_domain.iter().enumerate() {
        if j != index {
            let xi_minus_xj_inv = (x_i - x_j).inverse().unwrap();
            l_i = &l_i
                * &DensePolynomial::from_coefficients_slice(&[
                    -x_j * xi_minus_xj_inv,
                    xi_minus_xj_inv,
                ]);
        }
    }
    l_i
}

// Compute the Lagrange basis polynomials in O(n^2) time. This is not recommended for domains of
// size above 32.
pub fn construct_lagrange_basis_polys<F: FftField>(evaluation_domain: &[F]) -> Vec<DensePolynomial<F>> {
    let mut bases = Vec::with_capacity(evaluation_domain.len());
    for i in 0..evaluation_domain.len() {
        let l_i = construct_lagrange_basis_poly(evaluation_domain, i);

        bases.push(l_i);
    }

    bases
}

// Compute the commitments to Lagrange basis polynomials quickly.
// Credit: https://github.com/geometryresearch/cq/blob/main/src/tools.rs
pub fn compute_lagrange_basis_commitments<C: AffineCurve>(tau_powers: Vec<C>) -> Vec<C> {
    let n = tau_powers.len();
    assert!(is_pow_2(n));

    let domain = GeneralEvaluationDomain::<C::ScalarField>::new(n).unwrap();
    let n_inv = domain
        .size_as_field_element()
        .inverse()
        .unwrap()
        .into_repr();

    let tau_projective: Vec<C::Projective> = tau_powers
        .iter()
        .map(|tau_pow_i| tau_pow_i.into_projective())
        .collect();
    let p_evals: Vec<C::Projective> = domain.fft(&tau_projective);
    let p_evals_reversed = iter::once(p_evals[0]).chain(p_evals.into_iter().skip(1).rev());

    let mut ls: Vec<C::Projective> = p_evals_reversed
        .into_iter()
        .map(|pi| pi.mul(n_inv))
        .collect();
    C::Projective::batch_normalization(&mut ls);
    ls.iter().map(|li| li.into_affine()).collect()
}

pub fn is_pow_2(x: usize) -> bool {
    (x & (x - 1)) == 0
}

#[cfg(test)]
mod util_tests {
    use super::construct_lagrange_basis_polys;
    use ark_bn254::Fr as F;
    use ark_ff::Zero;
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
    };

    #[test]
    fn test_lagrange_bases() {
        let domain_size = 8;
        let domain = GeneralEvaluationDomain::<F>::new(domain_size).unwrap();

        let elems: Vec<F> = domain.elements().collect();
        let bases = construct_lagrange_basis_polys(&elems);
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
