use ark_ff::Field;

pub fn evaluate_fs<F: Field>(
    q1_eval: F,
    q1_xi: F, 
    q2_eval: F,
    q2_xi: F,
    q3_evals: &[F; 2],
    q3_xi: F, 
    q4_evals: &[F; 3],
    q4_xi: F,
    v: F, 
    alpha: F,
    omega_alpha: F, 
    omega_n_alpha: F,
    xi: F
) -> (F, F, F, F) {
    // r1&r2
    let r1_xi = q1_eval; 
    let r2_xi = q2_eval;

    // building equations
    let xi_minus_v = xi - v;
    let xi_minus_alpha = xi - alpha;
    let xi_minus_omega_alpha = xi - omega_alpha; 
    let xi_minus_omega_n_alpha = xi - omega_n_alpha; 

    let xi_minus_v_inv = xi_minus_v.inverse().unwrap();
    let xi_minus_alpha_inv = xi_minus_alpha.inverse().unwrap();
    let xi_minus_omega_alpha_inv = xi_minus_omega_alpha.inverse().unwrap(); 
    let xi_minus_omega_n_alpha_inv = xi_minus_omega_n_alpha.inverse().unwrap(); 

    let alpha_minus_omega_alpha = alpha - omega_alpha;
    let alpha_minus_omega_alpha_inv = alpha_minus_omega_alpha.inverse().unwrap();
    let omega_alpha_minus_alpha_inv = -alpha_minus_omega_alpha_inv;

    let alpha_minus_omega_n_alpha = alpha - omega_n_alpha;
    let alpha_minus_omega_n_alpha_inv = alpha_minus_omega_n_alpha.inverse().unwrap();
    let omega_n_alpha_minus_alpha_inv = -alpha_minus_omega_n_alpha_inv;

    let omega_alpha_minus_omega_n_alpha = omega_alpha - omega_n_alpha;
    let omega_alpha_minus_omega_n_alpha_inv = omega_alpha_minus_omega_n_alpha.inverse().unwrap();
    let omega_n_alpha_minus_omega_alpha_inv = -omega_alpha_minus_omega_n_alpha_inv;

    // vanishing evaluations 
    let z1_xi = xi_minus_v_inv;
    let z2_xi = xi_minus_alpha_inv;
    let z3_xi = z2_xi * xi_minus_omega_alpha_inv;
    let z4_xi = z3_xi * xi_minus_omega_n_alpha_inv;

    // r3
    let l_1_3 = xi_minus_omega_alpha * alpha_minus_omega_alpha_inv;
    let l_2_3 = xi_minus_alpha * omega_alpha_minus_alpha_inv;

    let r3_xi = q3_evals[0]*l_1_3 + q3_evals[1]*l_2_3;

    // r4
    let l_1_4 = xi_minus_omega_alpha * xi_minus_omega_n_alpha * alpha_minus_omega_alpha_inv * alpha_minus_omega_n_alpha_inv;
    let l_2_4 = xi_minus_alpha * xi_minus_omega_n_alpha * omega_alpha_minus_alpha_inv * omega_alpha_minus_omega_n_alpha_inv;
    let l_3_4 = xi_minus_alpha * xi_minus_omega_alpha * omega_n_alpha_minus_alpha_inv * omega_n_alpha_minus_omega_alpha_inv;
    
    let r4_xi = q4_evals[0]*l_1_4 + q4_evals[1]*l_2_4 + q4_evals[2]*l_3_4;

    // fs
    let f1 = (q1_xi - r1_xi) * z1_xi;
    let f2 = (q2_xi - r2_xi) * z2_xi;
    let f3 = (q3_xi - r3_xi) * z3_xi;
    let f4 = (q4_xi - r4_xi) * z4_xi;
    
    (f1, f2, f3, f4)
}

#[cfg(test)]
mod multiopen_tests {
    use ark_bn254::Fr;
    use ark_ff::{UniformRand, One};
    use ark_poly::{GeneralEvaluationDomain, EvaluationDomain, univariate::DensePolynomial, UVPolynomial, Polynomial};
    use ark_std::test_rng;

    use super::evaluate_fs;

    #[test]
    fn test_multiopen_eval_f() {
        let mut rng = test_rng();
        let n = 128usize;
        let pow = 91;

        let domain = GeneralEvaluationDomain::new(n).unwrap();
        let omega: Fr = domain.element(1);
        let omega_n = domain.element(pow);

        let v = Fr::rand(&mut rng);
        let alpha = Fr::rand(&mut rng);
        let omega_alpha = omega * alpha; 
        let omega_n_alpha = omega_n * alpha;

        let q1 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let q2 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let q3 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let q4 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);

        let xi = Fr::rand(&mut rng); 

        // prepare evals
        let q1_eval = q1.evaluate(&v);
        let q1_xi = q1.evaluate(&xi);

        let q2_eval = q2.evaluate(&alpha);
        let q2_xi = q2.evaluate(&xi);

        let q3_evals = [q3.evaluate(&alpha), q3.evaluate(&omega_alpha)];
        let q3_xi = q3.evaluate(&xi);

        let q4_evals = [q4.evaluate(&alpha), q4.evaluate(&omega_alpha), q4.evaluate(&omega_n_alpha)];
        let q4_xi = q4.evaluate(&xi);

        let (f1_xi, f2_xi, f3_xi, f4_xi) = evaluate_fs(q1_eval, q1_xi, q2_eval, q2_xi, &q3_evals, q3_xi, &q4_evals, q4_xi, v, alpha, omega_alpha, omega_n_alpha, xi);

        // prepare vanishing polys
        let z1 = DensePolynomial::from_coefficients_slice(&[-v, Fr::one()]);
        let z2 = DensePolynomial::from_coefficients_slice(&[-alpha, Fr::one()]);
        let z3 = &z2 * &DensePolynomial::from_coefficients_slice(&[-omega_alpha, Fr::one()]);
        let z4 = &z3 * &DensePolynomial::from_coefficients_slice(&[-omega_n_alpha, Fr::one()]);

        // compute fs   
        let f1 = &q1 / &z1;
        let f2 = &q2 / &z2;
        let f3 = &q3 / &z3;
        let f4 = &q4 / &z4;

        assert_eq!(f1.evaluate(&xi), f1_xi);
        assert_eq!(f2.evaluate(&xi), f2_xi);
        assert_eq!(f3.evaluate(&xi), f3_xi);
        assert_eq!(f4.evaluate(&xi), f4_xi);
    }
}