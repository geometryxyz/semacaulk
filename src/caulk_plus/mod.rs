use ark_ec::PairingEngine;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

pub mod precomputed;
pub mod proof;
pub mod prover;
pub mod verifier;

/*
    Modified caulk+ argument for efficient membership proofs
    Note: In this modification zV is specifically = {1}, so we always have that both domain_h and domain_v are powers of two
    Note: We do not consider duplicates in this modification even though it's probably possible to extend it
*/

pub struct PublicInput<E: PairingEngine> {
    pub(crate) srs_g1: Vec<E::G1Affine>,
    pub(crate) srs_g2: Vec<E::G2Affine>,
}

pub struct CommonInput<E: PairingEngine> {
    pub(crate) domain_h: GeneralEvaluationDomain<E::Fr>,
    pub(crate) domain_v: GeneralEvaluationDomain<E::Fr>,
    pub(crate) c_commitment: E::G1Affine,
    pub(crate) a_commitment: E::G1Affine,
    pub(crate) rotation: usize,
}

impl<E: PairingEngine> CommonInput<E> {
    pub fn new(
        order_n: usize,
        order_m: usize,
        c_commitment: E::G1Affine,
        a_commitment: E::G1Affine,
        rotation: usize
    ) -> Self {
        let domain_h = GeneralEvaluationDomain::new(order_n).unwrap();
        let domain_v = GeneralEvaluationDomain::new(order_m).unwrap();
        Self {
            domain_h,
            domain_v,
            c_commitment,
            a_commitment,
            rotation
        }
    }
}

#[cfg(test)]
mod caulk_plus_tests {
    use crate::{
        caulk_plus::{verifier::Verifier, PublicInput, CommonInput, prover::{WitnessInput, Prover}, precomputed::Precomputed},
        rng::{FiatShamirRng, SimpleHashFiatShamirRng},
        kzg::{unsafe_setup, commit},
    };

    use ark_bn254::{Bn254, Fr as F};
    use ark_ec::ProjectiveCurve;
    use ark_ff::{to_bytes, Field};
    use ark_poly::{GeneralEvaluationDomain, EvaluationDomain, univariate::DensePolynomial, UVPolynomial};
    use ark_std::{rand::rngs::StdRng, test_rng};
    use blake2::Blake2s;
    use rand_chacha::ChaChaRng;

    type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;

    fn to_field<F: Field>(evals: &[u64]) -> Vec<F> {
        evals.iter().map(|&e| F::from(e)).collect()
    }

    /* EXAMPLE OF STANDARD CAULK PROOF */
    // #[test]
    // fn test_classic_caulk() {
    //     let mut rng = test_rng();
    //     let max_power = 32;
    //     let h = 8;
    //     let domain_h = GeneralEvaluationDomain::<F>::new(h).unwrap();

    //     let v = 4;
    //     let domain_v = GeneralEvaluationDomain::<F>::new(v).unwrap();

    //     let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);
    //     let public_input = PublicInput::<Bn254> {
    //         srs_g1: srs_g1.clone(),
    //         srs_g2,
    //     };

    //     let evals = &[132, 321, 213141, 32193, 43892, 12319, 321341, 32910841];
    //     let c_evals = to_field::<F>(evals);

    //     let a_evals = vec![c_evals[1], c_evals[2], c_evals[5], c_evals[7]];
    //     let mapping = vec![1, 2, 5, 7];

    //     let c = DensePolynomial::from_coefficients_slice(&domain_h.ifft(&c_evals));
    //     let a = DensePolynomial::from_coefficients_slice(&domain_v.ifft(&a_evals));

    //     let c_commitment = commit(&srs_g1, &c).into_affine();
    //     let a_commitment = commit(&srs_g1, &a).into_affine();

    //     let common_input = CommonInput::<Bn254> {
    //         domain_h: domain_h.clone(),
    //         domain_v: domain_v.clone(),
    //         c_commitment,
    //         a_commitment,
    //     };

    //     let witness = WitnessInput::<F> {
    //         indices: vec![1, 2, 5, 7],
    //         values: a_evals,
    //         _c: c.clone(),
    //         a,
    //         mapping,
    //     };

    //     let mut fs_rng = FS::initialize(&to_bytes![&[0u8]].unwrap());

    //     let mut precomputed = Precomputed::<Bn254>::empty();
    //     precomputed.precompute_w1(&public_input.srs_g2, &[1, 2, 5, 7], &c, &domain_h);
    //     precomputed.precompute_w2(&public_input.srs_g2, &[1, 2, 5, 7], &domain_h);

    //     let proof = Prover::prove(
    //         &public_input,
    //         &common_input,
    //         &witness,
    //         &precomputed,
    //         &mut rng,
    //         &mut fs_rng,
    //     );

    //     // Repeat initialization
    //     let mut fs_rng = FS::initialize(&to_bytes![&[0u8]].unwrap());

    //     let verifier_input = VerifierInput {
    //         p2_eval: F::zero(),
    //         a_opening_at_rotation: F::zero(),
    //     };

    //     let res = Verifier::verify(&public_input, &common_input, &verifier_input, &proof, &mut fs_rng);
    //     assert_eq!(res.is_ok(), true);
    // }

    #[test]
    fn test_mimc() {
        let mut rng = test_rng();
        let max_power = 32;
        let h = 8;
        let domain_h = GeneralEvaluationDomain::<F>::new(h).unwrap();

        let v = 1;
        let domain_v = GeneralEvaluationDomain::<F>::new(v).unwrap();

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);
        let public_input = PublicInput::<Bn254> {
            srs_g1: srs_g1.clone(),
            srs_g2,
        };

        let c_evals = &[132, 321, 213141, 32193, 43892, 12319, 321341, 32910841];
        let a_evals = &[89274, 4392042, 43920, 49234, 42342, c_evals[5], 89742, 4328];
        let c_evals = to_field::<F>(c_evals);
        let a_evals = to_field::<F>(a_evals);

        let mapping = vec![5];

        let c = DensePolynomial::from_coefficients_slice(&domain_h.ifft(&c_evals));
        let a = DensePolynomial::from_coefficients_slice(&domain_h.ifft(&a_evals));

        let c_commitment = commit(&srs_g1, &c).into_affine();
        let a_commitment = commit(&srs_g1, &a).into_affine();

        let common_input = CommonInput::<Bn254> {
            domain_h: domain_h.clone(),
            domain_v: domain_v.clone(),
            c_commitment,
            a_commitment,
            rotation: 5
        };

        let witness = WitnessInput::<F> {
            indices: vec![5],
            values: vec![c_evals[5]],
            _c: c.clone(),
            a,
            rotation: 5,
            mapping,
        };

        let mut fs_rng = FS::initialize(&to_bytes![&[0u8]].unwrap());

        let mut precomputed = Precomputed::<Bn254>::empty();
        precomputed.precompute_w1(&public_input.srs_g2, &[5], &c, &domain_h);
        precomputed.precompute_w2(&public_input.srs_g2, &[5], &domain_h);

        let (proof, a_opening_at_rotation) = Prover::prove(
            &public_input,
            &common_input,
            &witness,
            &precomputed,
            &mut rng,
            &mut fs_rng,
        );

        // Repeat initialization
        let mut fs_rng = FS::initialize(&to_bytes![&[0u8]].unwrap());

        let res = Verifier::verify(&public_input, &common_input, &proof, a_opening_at_rotation, &mut fs_rng);
        assert_eq!(res.is_ok(), true);
    }
}
