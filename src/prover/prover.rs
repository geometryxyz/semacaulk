use std::{
    iter::{self, successors},
    marker::PhantomData,
    vec,
};

use ark_bn254::{Bn254, Fr};
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial, Polynomial,
};

use crate::{
    constants::{EXTENDED_DOMAIN_FACTOR, SUBGROUP_SIZE},
    gates::{KeyCopyGate, KeyEquality, Mimc7RoundGate, NullifierGate},
    kzg::commit,
    layouter::Assignment,
    transcript::Transcript,
};

use super::{ProverKey, ProverPrecomputedData};

pub struct Prover {}

impl Prover {
    pub fn prove(
        pk: &ProverKey<Bn254>,
        index: &ProverPrecomputedData<Fr>,
        assignment: &Assignment<Fr>,
        // public inputs
        nullifier: Fr
    ) {
        let mut transcirpt = Transcript::new_transcript();

        let (nullifier_wire, key_wire, nullifier_trapdoor_wire, nullifier_external_wire) =
            Self::assignment_round(assignment);

        let nullifier_cm = commit(&pk.srs_g1, &nullifier_wire).into_affine();
        let key_cm = commit(&pk.srs_g1, &key_wire).into_affine();
        let nullifier_trapdoor_cm = commit(&pk.srs_g1, &nullifier_trapdoor_wire).into_affine();
        let nullifier_external_cm = commit(&pk.srs_g1, &nullifier_external_wire).into_affine();

        transcirpt.update_with_g1(&nullifier_cm);
        transcirpt.update_with_g1(&key_cm);
        transcirpt.update_with_g1(&nullifier_trapdoor_cm);
        transcirpt.update_with_g1(&nullifier_external_cm);

        let alpha = transcirpt.get_challenge();

        let quotient = Self::quotient_round(
            index,
            &nullifier_wire,
            &key_wire,
            &nullifier_trapdoor_wire,
            &nullifier_external_wire,
            alpha,
            nullifier,
        );

        println!("quotient degree {}", quotient.degree());

        let quotient_cm = commit(&pk.srs_g1, &quotient).into_affine();
        transcirpt.update_with_g1(&quotient_cm);

        println!("Alive here");
    }

    fn assignment_round<F: PrimeField>(
        assignment: &Assignment<F>,
    ) -> (
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
    ) {
        let domain = GeneralEvaluationDomain::<F>::new(SUBGROUP_SIZE).unwrap();

        let nullifier_wire =
            DensePolynomial::from_coefficients_slice(&domain.ifft(&assignment.nullifier));
        let key_wire = DensePolynomial::from_coefficients_slice(&domain.ifft(&assignment.key));
        let nullifier_trapdoor_wire =
            DensePolynomial::from_coefficients_slice(&domain.ifft(&assignment.nullifier_trapdoor));
        let nullifier_external_wire =
            DensePolynomial::from_coefficients_slice(&domain.ifft(&assignment.nullifier_external));

        (
            nullifier_wire,
            key_wire,
            nullifier_trapdoor_wire,
            nullifier_external_wire,
        )
    }

    fn quotient_round<F: PrimeField>(
        index: &ProverPrecomputedData<F>,
        nullifier_wire: &DensePolynomial<F>,
        key_wire: &DensePolynomial<F>,
        nullifier_trapdoor_wire: &DensePolynomial<F>,
        nullifier_external_wire: &DensePolynomial<F>,
        alpha: F,
        nullifier: F, // public input
    ) -> DensePolynomial<F> {
        let extended_coset_domain =
            GeneralEvaluationDomain::<F>::new(EXTENDED_DOMAIN_FACTOR * SUBGROUP_SIZE).unwrap();

        let nullifier_coset_evals = extended_coset_domain.coset_fft(nullifier_wire);
        let key_coset_evals = extended_coset_domain.coset_fft(key_wire);
        let nullifier_trapdoor_coset_evals =
            extended_coset_domain.coset_fft(nullifier_trapdoor_wire);
        let nullifier_external_coset_evals =
            extended_coset_domain.coset_fft(nullifier_external_wire);
        let zeroes: Vec<F> = iter::repeat(F::zero())
            .take(extended_coset_domain.size())
            .collect();

        let num_of_gates = 6;
        let alpha_powers: Vec<F> =
            iter::successors(Some(F::one()), |alpha_i: &F| Some(alpha_i.clone() * alpha))
                .take(num_of_gates)
                .collect();

        let mut numerator_coset_evals = vec![F::zero(); extended_coset_domain.size()];
        for i in 0..extended_coset_domain.size() {
            // Gate0:
            numerator_coset_evals[i] += alpha_powers[0]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &nullifier_coset_evals,
                    &zeroes,
                    &index.c_coset_evals,
                    &index.q_mimc_coset_evals,
                );

            // Gate1:
            numerator_coset_evals[i] += alpha_powers[1]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &nullifier_trapdoor_coset_evals,
                    &key_coset_evals,
                    &index.c_coset_evals,
                    &index.q_mimc_coset_evals,
                );

            // Gate2:
            numerator_coset_evals[i] += alpha_powers[2]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &nullifier_external_coset_evals,
                    &key_coset_evals,
                    &index.c_coset_evals,
                    &index.q_mimc_coset_evals,
                );

            // Gate3:
            numerator_coset_evals[i] += alpha_powers[3]
                * KeyEquality::compute_in_coset(i, &key_coset_evals, &index.q_mimc_coset_evals);

            // Gate4:
            numerator_coset_evals[i] += alpha_powers[4]
                * KeyCopyGate::compute_in_coset(
                    i,
                    &nullifier_coset_evals,
                    &key_coset_evals,
                    &index.l0_coset_evals,
                );

            // Gate5:
            numerator_coset_evals[i] += alpha_powers[5]
                * NullifierGate::compute_in_coset(
                    i,
                    &nullifier_external_coset_evals,
                    &key_coset_evals,
                    &index.l0_coset_evals,
                    nullifier,
                );
        }

        // sanity check 
        // TODO: add cfg if sanity
        {
            let domain = GeneralEvaluationDomain::<F>::new(SUBGROUP_SIZE).unwrap();
            let zh: DensePolynomial<F> = domain.vanishing_polynomial().into();

            let numerator = DensePolynomial::from_coefficients_slice(
                &extended_coset_domain.coset_ifft(&numerator_coset_evals),
            );

            let q = &numerator / &zh; 
            assert_eq!(&q * &zh, numerator);
        } 

        let quotient_coset_evals: Vec<_> = numerator_coset_evals
            .iter()
            .zip(index.zh_inverse_coset_evals.iter())
            .map(|(&num, &denom)| num * denom).collect();

        // Note: SRS for committing full vector of identities will be large, so we don't need to split quotient into chunks
        // it's just important to check it's degree in verifier
        let quotient = DensePolynomial::from_coefficients_slice(
            &extended_coset_domain.coset_ifft(&quotient_coset_evals),
        );

        quotient
    }
}

#[cfg(test)]
mod prover_tests {
    use ark_bn254::{Fr, Bn254};
    use ark_ff::Zero;
    use ark_std::test_rng;
    use rand::rngs::StdRng;

    use crate::{mimc7::Mimc7, layouter::Layouter, prover::{ProverPrecomputedData, ProverKey}, kzg::unsafe_setup};

    use super::Prover;

    #[test]
    fn test_prover() {
        let n_rounds = 91;
        let mut rng = test_rng();

        let mimc7 = Mimc7::<Fr>::new("mimc".into(), n_rounds);

        let identity_nullifier = Fr::from(100u64);
        let identity_trapdoor = Fr::from(200u64);

        let external_nullifier = Fr::from(300u64);

        let nullifier_external =
            mimc7.multi_hash(&[identity_nullifier, external_nullifier], Fr::zero());

        let assignment = Layouter::assign(
            identity_nullifier,
            identity_trapdoor,
            external_nullifier,
            &mimc7.cts,
            &mut rng,
        );

        let dummy_value = Fr::from(9999u64);
        let index = ProverPrecomputedData::index(&mimc7.cts, dummy_value);

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(900, 128, &mut rng);
        let pk = ProverKey {
            srs_g1, 
            srs_g2
        };

        Prover::prove(&pk, &index, &assignment, nullifier_external);

    }
}