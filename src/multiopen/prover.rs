use std::iter;

use ark_ff::One;
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};

use crate::{
    kzg::{commit, open},
    transcript::Transcript,
};
use ark_bn254::{Bn254, Fr, G1Affine};

use super::MultiopenProof;

pub struct Prover {}

impl Prover {
    pub fn prove(
        //srs
        srs_g1: &[G1Affine],
        // semaphore related polys
        w0: &DensePolynomial<Fr>,
        w1: &DensePolynomial<Fr>,
        w2: &DensePolynomial<Fr>,
        key: &DensePolynomial<Fr>,
        q_mimc: &DensePolynomial<Fr>,
        c: &DensePolynomial<Fr>,
        quotient: &DensePolynomial<Fr>,
        // caulk+ related polys
        u_prime: &DensePolynomial<Fr>,
        p1: &DensePolynomial<Fr>,
        p2: &DensePolynomial<Fr>,
        // proof specific information
        v: Fr,
        alpha: Fr,
        omega_alpha: Fr,
        omega_n_alpha: Fr,
        transcript: &mut Transcript,
    ) -> MultiopenProof<Bn254> {
        let x1 = transcript.get_challenge();
        let x2 = transcript.get_challenge();

        let x1_powers: Vec<Fr> = iter::successors(Some(x1), |x1_pow| Some(*x1_pow * x1))
            .take(4)
            .collect();
        let x2_powers: Vec<Fr> = iter::successors(Some(x2), |x2_pow| Some(*x2_pow * x2))
            .take(3)
            .collect();

        // define qi-s
        let q1 = p1.clone();
        let q2 = q_mimc
            + &(c * x1_powers[0])
            + (quotient * x1_powers[1])
            + (u_prime * x1_powers[2])
            + (p2 * x1_powers[3]);
        let q3 = key.clone();
        let q4 = w0 + &(w1 * x1_powers[0]) + (w2 * x1_powers[1]);

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

        let f = f1 + (&f2 * x2_powers[0]) + (&f3 * x2_powers[1]) + (&f4 * x2_powers[2]);

        let f_cm: G1Affine = commit(srs_g1, &f).into();
        transcript.update_with_g1(&f_cm);

        let x3 = transcript.get_challenge();
        let x4 = transcript.get_challenge();
        let x4_powers: Vec<Fr> = iter::successors(Some(x4), |x4_pow| Some(*x4_pow * x4))
            .take(4)
            .collect();

        let final_poly = f
            + (&q1 * x4_powers[0])
            + (&q2 * x4_powers[1])
            + (&q3 * x4_powers[2])
            + (&q4 * x4_powers[3]);
        let (_, final_poly_proof) = open(srs_g1, &final_poly, x3);

        MultiopenProof {
            q1_opening: q1.evaluate(&x3),
            q2_opening: q2.evaluate(&x3),
            q3_opening: q3.evaluate(&x3),
            q4_opening: q4.evaluate(&x3),
            f_cm,
            final_poly_proof,
        }
    }
}
