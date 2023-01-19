use std::iter;
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use crate::prover::Proof;
use crate::transcript::Transcript;
use crate::constants::{ NUMBER_OF_MIMC_ROUNDS, SUBGROUP_SIZE};
use crate::multiopen::verifier::Verifier as MultiopenVerifier;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{Zero, One};
use ark_ff::Field;

pub struct Verifier {}

impl Verifier {
    pub fn verify(
        proof: &Proof<Bn254>,
        x_g2: G2Affine,
        accumulator: G1Affine,
        external_nullifier: Fr,
        nullifier_hash: Fr,
    ) -> bool {
        let mut transcript = Transcript::new_transcript();

        // Derive challenges
        transcript.update_with_g1(&proof.commitments.w0);
        transcript.update_with_g1(&proof.commitments.key);
        transcript.update_with_g1(&proof.commitments.w1);
        transcript.update_with_g1(&proof.commitments.w2);

        let v = transcript.get_challenge();
        transcript.update_with_g1(&proof.commitments.quotient);
        transcript.update_with_g1(&proof.commitments.zi);
        transcript.update_with_g1(&proof.commitments.ci);
        transcript.update_with_g1(&proof.commitments.u_prime);
        let _hi_1 = transcript.get_challenge();
        let _hi_2 = transcript.get_challenge();
        let alpha = transcript.get_challenge();

        let domain_h = GeneralEvaluationDomain::new(SUBGROUP_SIZE).unwrap();

        let omega: Fr = domain_h.element(1);
        let omega_n = domain_h.element(NUMBER_OF_MIMC_ROUNDS);

        let omega_alpha = omega * alpha;
        let omega_n_alpha = omega_n * alpha;

        let mut q_mimc_evals: Vec<Fr> = iter::repeat(Fr::one())
            .take(NUMBER_OF_MIMC_ROUNDS)
            .collect();
        let mut zeroes: Vec<Fr> = iter::repeat(Fr::zero())
            .take(SUBGROUP_SIZE - NUMBER_OF_MIMC_ROUNDS)
            .collect();
        q_mimc_evals.append(&mut zeroes);

        // Compute key
        let key_openings = [
            proof.openings.key_openings_0,
            proof.openings.key_openings_1,
        ];

        let q_mimc_opening = proof.openings.q_mimc_opening;
        let c_opening = proof.openings.c_opening;
        let w0_openings = [
            proof.openings.w0_openings_0,
            proof.openings.w0_openings_1,
            proof.openings.w0_openings_2,
        ];
        let w1_openings = [
            proof.openings.w1_openings_0,
            proof.openings.w1_openings_1,
            proof.openings.w1_openings_2,
        ];

        let w2_openings = [
            proof.openings.w2_openings_0,
            proof.openings.w2_openings_1,
            proof.openings.w2_openings_2,
        ];

        // Check if the gate equations are valid

        let l0_eval = domain_h.evaluate_all_lagrange_coefficients(alpha)[0];
        
        // Compute the zh_eval - quotient_opening value, which is what the challenge-separated linear
        // combination of the gate evaluations should equal
        let pow_7 = |x: Fr| x.pow(&[7, 0, 0, 0]);

        // Gate 0: q_mimc_opening * ((w0_openings[0] + c_opening) ^ 7 - w0_openings[1])
        let gate_0_eval = q_mimc_opening * (pow_7(w0_openings[0] + c_opening) - w0_openings[1]);

        // Gate 1: q_mimc_opening * ((w1_openings[0] + key_openings[0] + c_opening) ^ 7 - w1_openings[1])
        let gate_1_eval = q_mimc_opening * (pow_7(w1_openings[0] + key_openings[0] + c_opening) - w1_openings[1]);

        // Gate 2:
        // q_mimc_opening * ((w2_openings[0] + key_openings[0] + c_opening) ^ 7 - w2_openings[1]) 
        let gate_2_eval = q_mimc_opening * (pow_7(w2_openings[0] + key_openings[0] + c_opening) - w2_openings[1]);
        
        // Gate 3:
        // q_mimc_opening * (key_openings[0] - key_openings[1])
        let gate_3_eval = q_mimc_opening * (key_openings[0] - key_openings[1]);
        
        // Gate 4:
        // l0 * (key_openings[0] - w0_openings[0] - w0_openings[2])
        let gate_4_eval = l0_eval * (key_openings[0] - w0_openings[0] - w0_openings[2]);
        
        // Gate 5:
        // l0 * (nullifierHash - w2_openings[0] - w2_openings[2] - (2 * key_openings[0])) 
        let gate_5_eval = l0_eval * (nullifier_hash - w2_openings[0] - w2_openings[2] - (Fr::from(2) * key_openings[0]));

        // Gate 6:
        // l0 * (w2_openings[0] - external_nullifier)
        let gate_6_eval = l0_eval * (w2_openings[0] - external_nullifier);

        let v_pow_2 = v.pow(&[2, 0, 0, 0]);
        let v_pow_3 = v.pow(&[3, 0, 0, 0]);
        let v_pow_4 = v.pow(&[4, 0, 0, 0]);
        let v_pow_5 = v.pow(&[5, 0, 0, 0]);
        let v_pow_6 = v.pow(&[6, 0, 0, 0]);

        let lhs =          gate_0_eval +
            (v       * gate_1_eval) +
            (v_pow_2 * gate_2_eval) +
            (v_pow_3 * gate_3_eval) +
            (v_pow_4 * gate_4_eval) +
            (v_pow_5 * gate_5_eval) +
            (v_pow_6 * gate_6_eval);

        let zh_eval = alpha.pow(&[SUBGROUP_SIZE as u64, 0, 0, 0]) - Fr::one();
        let quotient_opening = proof.openings.quotient_opening;
        let rhs = zh_eval * quotient_opening;
        //println!("verifier rhs: {}", rhs);

        if lhs != rhs {
            return false;
        }

        transcript.update_with_u256(proof.openings.w0_openings_0);
        transcript.update_with_u256(proof.openings.w0_openings_1);
        transcript.update_with_u256(proof.openings.w0_openings_2);

        transcript.update_with_u256(proof.openings.w1_openings_0);
        transcript.update_with_u256(proof.openings.w1_openings_1);
        transcript.update_with_u256(proof.openings.w1_openings_2);

        transcript.update_with_u256(proof.openings.w2_openings_0);
        transcript.update_with_u256(proof.openings.w2_openings_1);
        transcript.update_with_u256(proof.openings.w2_openings_2);

        transcript.update_with_u256(proof.openings.key_openings_0);
        transcript.update_with_u256(proof.openings.key_openings_1);

        transcript.update_with_u256(q_mimc_opening);
        transcript.update_with_u256(c_opening);
        transcript.update_with_u256(proof.openings.quotient_opening);

        transcript.update_with_u256(proof.openings.u_prime_opening);
        transcript.update_with_u256(proof.openings.p1_opening);
        transcript.update_with_u256(proof.openings.p2_opening);

        // Verify multiopen proof
        let is_multiopen_valid = MultiopenVerifier::verify(
            &mut transcript,
            &proof.multiopen_proof,
            &proof.commitments.w0,
            &[
                proof.openings.w0_openings_0,
                proof.openings.w0_openings_1,
                proof.openings.w0_openings_2,
            ],
            &proof.commitments.w1,
            &[
                proof.openings.w1_openings_0,
                proof.openings.w1_openings_1,
                proof.openings.w1_openings_2,
            ],
            &proof.commitments.w2,
            &[
                proof.openings.w2_openings_0,
                proof.openings.w2_openings_1,
                proof.openings.w2_openings_2,
            ],
            &proof.commitments.key,
            &[
                proof.openings.key_openings_0,
                proof.openings.key_openings_1,
            ],
            &proof.commitments.q_mimc,
            q_mimc_opening,
            &proof.commitments.c,
            c_opening,
            &proof.commitments.quotient,
            quotient_opening,
            &proof.commitments.u_prime,
            proof.openings.u_prime_opening,
            &proof.commitments.p1,
            proof.openings.p1_opening,
            &proof.commitments.p2,
            proof.openings.p2_opening,
            proof.openings.u_prime_opening, //v,
            alpha,
            omega_alpha,
            omega_n_alpha,
            x_g2,
        );

        // What the caulk+ verifier needs:
        // public_input: &PublicInput<E>,
        //   - srs_g1[domain_h.size()], srs_g2[1] (x_g2)
        //
        // common_input: &CommonInput<E>,
        //   - domain_h
        //   - domain_v
        //   - c_commitment (?) - the poly representing the lookup table
        //   - a_commitment (?) - the values at which only some indices match the values in the
        //                        lookup table
        //   - rotation         - the 
        //
        // proof: &Proof<E>,
        //   - zi_commitment - (proof.commitments.zi)
        //   - ci_commitment - (proof.commitments.ci)
        //   - u_commitment  - (proof.commitments.u_prime)
        //   - w_commitment: - (can be taken from the prover)
        //   - h_commitment: - (can be taken from the prover)
        //   - u_eval: E::Fr, (proof.openings.u_prime_opening)
        //   - u_proof: E::G1Affine (KZG proof of u_prime evaluated at alpha)
        //   - p1_eval: - p1 evaluated at u_prime_opening
        //   - p1_proof: - (KZG proof of p1 evaluated at u_prime_opening)
        //   - p2_proof: - (KZG proof of p2 evaluated at alpha)
        // a_opening_at_rotation - (?)
        // fs_rng: &mut impl FiatShamirRng,

        is_multiopen_valid
    }
}

