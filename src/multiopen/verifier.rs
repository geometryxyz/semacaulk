use std::{iter, ops::Neg};

use ark_bn254::{Bn254, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One};

use crate::transcript::Transcript;

use super::MultiopenProof;

pub struct Verifier {}

impl Verifier {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        transcript: &mut Transcript,
        proof: &MultiopenProof<Bn254>,
        // semaphore related polys
        w0: &G1Affine,
        w0_openings: &[Fr; 3],
        w1: &G1Affine,
        w1_openings: &[Fr; 3],
        w2: &G1Affine,
        w2_openings: &[Fr; 3],
        key: &G1Affine,
        key_openings: &[Fr; 2],
        q_mimc: &G1Affine,
        q_mimc_opening: Fr,
        c: &G1Affine,
        c_opening: Fr,
        quotient: &G1Affine,
        quotient_opening: Fr,
        // caulk+ related polys
        u_prime: &G1Affine,
        u_prime_opening: Fr,
        p1: &G1Affine,
        p1_opening: Fr,
        p2: &G1Affine,
        p2_opening: Fr,
        // challenge points
        v: Fr,
        alpha: Fr,
        omega_alpha: Fr,
        omega_n_alpha: Fr,
        // proof specific information
        x_g2: G2Affine,
    ) -> bool {
        let (final_poly, final_poly_eval, x3) = Self::compute_final_poly(
            transcript,
            proof,
            w0,
            w0_openings,
            w1,
            w1_openings,
            w2,
            w2_openings,
            key,
            key_openings,
            q_mimc,
            q_mimc_opening,
            c,
            c_opening,
            quotient,
            quotient_opening,
            u_prime,
            u_prime_opening,
            p1,
            p1_opening,
            p2,
            p2_opening,
            v,
            alpha,
            omega_alpha,
            omega_n_alpha,
        );

        Self::verify_final_poly(
            &final_poly,
            final_poly_eval,
            proof.final_poly_proof,
            x3,
            x_g2,
        )
    }

    /// @dev This function is used in dev purposes
    /// final check is batched with rest of caulk+ pairings
    pub fn verify_final_poly(
        final_poly: &G1Affine,
        final_poly_opening: Fr,
        final_poly_proof: G1Affine,
        x3: Fr,
        x_g2: G2Affine,
    ) -> bool {
        let g2_gen = G2Affine::prime_subgroup_generator();
        let minus_y = G1Affine::prime_subgroup_generator()
            .mul(final_poly_opening)
            .neg();
        let zq = final_poly_proof.mul(x3);
        let lhs_1 = (zq + minus_y).add_mixed(final_poly);
        let res = Bn254::product_of_pairings(&[
            (lhs_1.into_affine().into(), g2_gen.into()),
            (final_poly_proof.neg().into(), x_g2.into()),
        ]);

        res == Fq12::one()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_final_poly(
        transcript: &mut Transcript,
        proof: &MultiopenProof<Bn254>,
        // semaphore related polys
        w0: &G1Affine,
        w0_openings: &[Fr; 3],
        w1: &G1Affine,
        w1_openings: &[Fr; 3],
        w2: &G1Affine,
        w2_openings: &[Fr; 3],
        key: &G1Affine,
        key_openings: &[Fr; 2],
        q_mimc: &G1Affine,
        q_mimc_opening: Fr,
        c: &G1Affine,
        c_opening: Fr,
        quotient: &G1Affine,
        quotient_opening: Fr,
        // caulk+ related polys
        u_prime: &G1Affine,
        u_prime_opening: Fr,
        p1: &G1Affine,
        p1_opening: Fr,
        p2: &G1Affine,
        p2_opening: Fr,
        // challenge points
        v: Fr,
        alpha: Fr,
        omega_alpha: Fr,
        omega_n_alpha: Fr,
    ) -> (G1Affine, Fr, Fr) {
        let x1 = transcript.get_challenge();
        let x2 = transcript.get_challenge();

        let x1_powers: Vec<Fr> = iter::successors(Some(x1), |x1_pow| Some(*x1_pow * x1))
            .take(4)
            .collect();
        let x2_powers: Vec<Fr> = iter::successors(Some(x2), |x2_pow| Some(*x2_pow * x2))
            .take(3)
            .collect();

        transcript.round_5(&proof.f_cm);

        let x3 = transcript.get_challenge();
        let x4 = transcript.get_challenge();

        let x4_powers: Vec<Fr> = iter::successors(Some(x4), |x4_pow| Some(*x4_pow * x4))
            .take(4)
            .collect();

        // q1
        let q1 = *p1;
        let q1_eval = p1_opening;

        // q2
        let q2: G1Affine = {
            let projective_part = c.mul(x1_powers[0])
                + quotient.mul(x1_powers[1])
                + u_prime.mul(x1_powers[2])
                + p2.mul(x1_powers[3]);
            projective_part.add_mixed(q_mimc).into()
        };
        let q2_eval = q_mimc_opening
            + c_opening * x1_powers[0]
            + quotient_opening * x1_powers[1]
            + u_prime_opening * x1_powers[2]
            + p2_opening * x1_powers[3];

        // q3
        let q3 = *key;
        let q3_evals = key_openings;

        // q4
        let q4: G1Affine = {
            let projective_part = w1.mul(x1_powers[0]) + w2.mul(x1_powers[1]);
            projective_part.add_mixed(w0).into()
        };

        let q4_at_alpha =
            w0_openings[0] + x1_powers[0] * w1_openings[0] + x1_powers[1] * w2_openings[0];
        let q4_at_omega_alpha =
            w0_openings[1] + x1_powers[0] * w1_openings[1] + x1_powers[1] * w2_openings[1];
        let q4_at_omega_n_alpha =
            w0_openings[2] + x1_powers[0] * w1_openings[2] + x1_powers[1] * w2_openings[2];
        let q4_evals = [q4_at_alpha, q4_at_omega_alpha, q4_at_omega_n_alpha];

        let (f1, f2, f3, f4) = Self::evaluate_fs(
            q1_eval,
            proof.q1_opening,
            q2_eval,
            proof.q2_opening,
            q3_evals,
            proof.q3_opening,
            &q4_evals,
            proof.q4_opening,
            v,
            alpha,
            omega_alpha,
            omega_n_alpha,
            x3,
        );

        let f_eval = f1 + (x2_powers[0] * f2) + (x2_powers[1] * f3) + (x2_powers[2] * f4);

        let final_poly: G1Affine = {
            let projective_part = q1.mul(x4_powers[0])
                + q2.mul(x4_powers[1])
                + q3.mul(x4_powers[2])
                + q4.mul(x4_powers[3]);
            projective_part.add_mixed(&proof.f_cm).into()
        };

        let final_poly_eval = f_eval
            + proof.q1_opening * x4_powers[0]
            + proof.q2_opening * x4_powers[1]
            + proof.q3_opening * x4_powers[2]
            + proof.q4_opening * x4_powers[3];

        (final_poly, final_poly_eval, x3)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_fs<F: Field>(
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
        xi: F,
    ) -> (F, F, F, F) {
        // r1 & r2
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
        let omega_alpha_minus_omega_n_alpha_inv =
            omega_alpha_minus_omega_n_alpha.inverse().unwrap();
        let omega_n_alpha_minus_omega_alpha_inv = -omega_alpha_minus_omega_n_alpha_inv;

        // vanishing evaluations
        let z1_xi = xi_minus_v_inv;
        let z2_xi = xi_minus_alpha_inv;
        let z3_xi = z2_xi * xi_minus_omega_alpha_inv;
        let z4_xi = z3_xi * xi_minus_omega_n_alpha_inv;

        // r3
        let l_1_3 = xi_minus_omega_alpha * alpha_minus_omega_alpha_inv;
        let l_2_3 = xi_minus_alpha * omega_alpha_minus_alpha_inv;

        let r3_xi = q3_evals[0] * l_1_3 + q3_evals[1] * l_2_3;

        // r4
        let l_1_4 = xi_minus_omega_alpha
            * xi_minus_omega_n_alpha
            * alpha_minus_omega_alpha_inv
            * alpha_minus_omega_n_alpha_inv;
        let l_2_4 = xi_minus_alpha
            * xi_minus_omega_n_alpha
            * omega_alpha_minus_alpha_inv
            * omega_alpha_minus_omega_n_alpha_inv;
        let l_3_4 = xi_minus_alpha
            * xi_minus_omega_alpha
            * omega_n_alpha_minus_alpha_inv
            * omega_n_alpha_minus_omega_alpha_inv;

        let r4_xi = q4_evals[0] * l_1_4 + q4_evals[1] * l_2_4 + q4_evals[2] * l_3_4;

        // fs
        let f1 = (q1_xi - r1_xi) * z1_xi;
        let f2 = (q2_xi - r2_xi) * z2_xi;
        let f3 = (q3_xi - r3_xi) * z3_xi;
        let f4 = (q4_xi - r4_xi) * z4_xi;

        (f1, f2, f3, f4)
    }
}
