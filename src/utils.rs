use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, UVPolynomial};

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

// given x coords construct Li polynomials
pub fn construct_lagrange_basis<F: FftField>(evaluation_domain: &[F]) -> Vec<DensePolynomial<F>> {
    let mut bases = Vec::with_capacity(evaluation_domain.len());
    for i in 0..evaluation_domain.len() {
        let mut l_i = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let x_i = evaluation_domain[i];
        for (j, &x_j) in evaluation_domain.iter().enumerate() {
            if j != i {
                let xi_minus_xj_inv = (x_i - x_j).inverse().unwrap();
                l_i = &l_i
                    * &DensePolynomial::from_coefficients_slice(&[
                        -x_j * xi_minus_xj_inv,
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
