/*
   For detailed spec check:
    - https://hackmd.io/D-bL6-oNSbSej7Ao_-9PLA?view
   For background in multiopen argument check:
    - https://zcash.github.io/halo2/design/proving-system/multipoint-opening.html
*/

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

pub mod prover;
pub mod verifier;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultiopenProof<E: PairingEngine> {
    pub(crate) q1_opening: E::Fr,
    pub(crate) q2_opening: E::Fr,
    pub(crate) q3_opening: E::Fr,
    pub(crate) q4_opening: E::Fr,
    pub(crate) f_cm: E::G1Affine,
    pub(crate) final_poly_proof: E::G1Affine,
}

#[cfg(test)]
mod multiopen_tests {
    use ark_bn254::{Bn254, Fr};
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
        UVPolynomial,
    };
    use ark_std::test_rng;
    use rand::rngs::StdRng;

    use crate::{
        kzg::{commit, unsafe_setup},
        transcript::Transcript,
    };

    use super::{prover::Prover, verifier::Verifier};
    use crate::constants::{NUMBER_OF_MIMC_ROUNDS, SUBGROUP_SIZE};

    #[test]
    fn test_full_multiopen_roundtrip() {
        let mut rng = test_rng();
        let n = SUBGROUP_SIZE;
        let pow = NUMBER_OF_MIMC_ROUNDS;

        let domain = GeneralEvaluationDomain::new(n).unwrap();
        let omega: Fr = domain.element(1);
        let omega_n = domain.element(pow);

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(n - 1, 1, &mut rng);

        let mut transcript = Transcript::new_transcript();

        let w0 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let w1 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let w2 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let key = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let q_mimc = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let c = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let quotient = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let u_prime = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let p1 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);
        let p2 = DensePolynomial::<Fr>::rand(n - 1, &mut rng);

        // 1. commitments to all polynomials
        let w0_cm = commit(&srs_g1, &w0).into();
        let w1_cm = commit(&srs_g1, &w1).into();
        let w2_cm = commit(&srs_g1, &w2).into();
        let key_cm = commit(&srs_g1, &key).into();
        let q_mimc_cm = commit(&srs_g1, &q_mimc).into();
        let c_cm = commit(&srs_g1, &c).into();
        let quotient_cm = commit(&srs_g1, &quotient).into();
        let u_prime_cm = commit(&srs_g1, &u_prime).into();
        let p1_cm = commit(&srs_g1, &p1).into();
        let p2_cm = commit(&srs_g1, &p2).into();

        // NOTE: in real protocol all commitments are added to transcript
        // here we just mock it
        transcript.update_with_g1(&w0_cm);

        // v and alpha are be derived from transcript
        let v = transcript.get_challenge();
        let alpha = transcript.get_challenge();

        let omega_alpha = omega * alpha;
        let omega_n_alpha = omega_n * alpha;

        // compute all openings
        let w0_openings = [
            w0.evaluate(&alpha),
            w0.evaluate(&omega_alpha),
            w0.evaluate(&omega_n_alpha),
        ];

        let w1_openings = [
            w1.evaluate(&alpha),
            w1.evaluate(&omega_alpha),
            w1.evaluate(&omega_n_alpha),
        ];

        let w2_openings = [
            w2.evaluate(&alpha),
            w2.evaluate(&omega_alpha),
            w2.evaluate(&omega_n_alpha),
        ];

        let key_openings = [key.evaluate(&alpha), key.evaluate(&omega_alpha)];

        let q_mimc_opening = q_mimc.evaluate(&alpha);
        let c_opening = c.evaluate(&alpha);
        let quotient_opening = quotient.evaluate(&alpha);
        let u_prime_opening = u_prime.evaluate(&alpha);
        let p1_opening = p1.evaluate(&v);
        let p2_opening = p2.evaluate(&alpha);

        // NOTE: in real protocol openings are appended in transcript

        // compute proof
        let multiopen_proof = Prover::prove(
            &srs_g1,
            &w0,
            &w1,
            &w2,
            &key,
            &q_mimc,
            &c,
            &quotient,
            &u_prime,
            &p1,
            &p2,
            v,
            alpha,
            omega_alpha,
            omega_n_alpha,
            &mut transcript,
        );

        // We reset transcript for verifier
        let mut transcript = Transcript::new_transcript();

        // NOTE: in real protocol all commitments are added to transcript
        // here we just mock it
        transcript.update_with_g1(&w0_cm);

        // v and alpha are be derived from transcript
        let v = transcript.get_challenge();
        let alpha = transcript.get_challenge();

        let omega_alpha = omega * alpha;
        let omega_n_alpha = omega_n * alpha;

        let verification_result = Verifier::verify(
            &mut transcript,
            &multiopen_proof,
            &w0_cm,
            &w0_openings,
            &w1_cm,
            &w1_openings,
            &w2_cm,
            &w2_openings,
            &key_cm,
            &key_openings,
            &q_mimc_cm,
            q_mimc_opening,
            &c_cm,
            c_opening,
            &quotient_cm,
            quotient_opening,
            &u_prime_cm,
            u_prime_opening,
            &p1_cm,
            p1_opening,
            &p2_cm,
            p2_opening,
            v,
            alpha,
            omega_alpha,
            omega_n_alpha,
            srs_g2[1],
        );
        assert_eq!(verification_result, true);
    }
}
