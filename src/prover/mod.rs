use std::iter;
use std::{cmp::max, vec};

use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    UVPolynomial,
};
use ark_std::{cfg_into_iter, UniformRand};
use rand::RngCore;

use crate::{
    constants::{EXTENDED_DOMAIN_FACTOR, NUMBER_OF_MIMC_ROUNDS, SUBGROUP_SIZE},
    gates::{ExternalNullifierGate, KeyCopyGate, KeyEquality, Mimc7RoundGate, NullifierGate},
    kzg::commit,
    layouter::Assignment,
    multiopen::{
        prover::Prover as MultiopenProver, verifier::Verifier as MultiopenVerifier, MultiopenProof,
    },
    transcript::Transcript,
    utils::construct_lagrange_basis,
    utils::shift_dense_poly,
};

pub mod structs;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
pub use structs::*;

type OpeningRoundResult = (
    MultiopenProof<Bn254>,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    Fr,
    DensePolynomial<Fr>,
    DensePolynomial<Fr>,
);

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct WitnessInput<F: PrimeField> {
    pub(crate) identity_nullifier: F,
    pub(crate) identity_trapdoor: F,
    pub(crate) identity_commitment: F,
    pub(crate) index: usize,
}

pub struct State<'a, E: PairingEngine> {
    // init data in the state
    pub(crate) proving_key: &'a ProvingKey<E>,
    pub(crate) assignment: &'a Assignment<E::Fr>,
    pub(crate) witness: &'a WitnessInput<E::Fr>,
    pub(crate) precomputed: &'a ProverPrecomputedData<E>,
    pub(crate) public_input: &'a PublicData<E>,
    // pub(crate) shifted_a: DensePolynomial<E::Fr>,

    // domains
    pub(crate) domain_h: GeneralEvaluationDomain<E::Fr>,
    pub(crate) domain_v: GeneralEvaluationDomain<E::Fr>,
    pub(crate) domain_t: GeneralEvaluationDomain<E::Fr>,

    // data after first round
    pub(crate) r1: Option<E::Fr>,
    pub(crate) r2: Option<E::Fr>,
    pub(crate) r3: Option<E::Fr>,
    pub(crate) r4: Option<E::Fr>,
    pub(crate) r5: Option<E::Fr>,
    pub(crate) r6: Option<E::Fr>,

    pub(crate) w0: Option<DensePolynomial<E::Fr>>,
    pub(crate) key: Option<DensePolynomial<E::Fr>>,
    pub(crate) w1: Option<DensePolynomial<E::Fr>>,
    pub(crate) w2: Option<DensePolynomial<E::Fr>>,

    pub(crate) quotient: Option<DensePolynomial<E::Fr>>,

    pub(crate) a: Option<DensePolynomial<E::Fr>>,
    pub(crate) zi: Option<DensePolynomial<E::Fr>>,
    pub(crate) ci: Option<DensePolynomial<E::Fr>>,
    pub(crate) u_prime: Option<DensePolynomial<E::Fr>>,

    // data after second round
    pub(crate) zi_of_ui: Option<DensePolynomial<E::Fr>>,
    pub(crate) ci_of_ui: Option<DensePolynomial<E::Fr>>,
    pub(crate) h: Option<DensePolynomial<E::Fr>>,
}

pub struct Prover {}

impl Prover {
    pub fn init<'a, E: PairingEngine>(
        proving_key: &'a ProvingKey<E>,
        witness: &'a WitnessInput<E::Fr>,
        assignment: &'a Assignment<E::Fr>,
        public_input: &'a PublicData<E>,
        precomputed: &'a ProverPrecomputedData<E>,
        table_size: usize,
    ) -> State<'a, E> {
        let domain_h = GeneralEvaluationDomain::new(SUBGROUP_SIZE).unwrap();
        let domain_v = GeneralEvaluationDomain::new(1).unwrap();
        let domain_t = GeneralEvaluationDomain::new(table_size).unwrap();
        // let omega_pow_rotation = domain_h.element(NUMBER_OF_MIMC_ROUNDS);
        // let shifted_a = shift_dense_poly(&witness.a, &omega_pow_rotation);
        State {
            proving_key,
            witness,
            assignment,
            public_input,
            precomputed,
            // shifted_a,
            domain_h,
            domain_v,
            domain_t,

            w0: None,
            key: None,
            w1: None,
            w2: None,

            quotient: None,

            r1: None,
            r2: None,
            r3: None,
            r4: None,
            r5: None,
            r6: None,

            a: None,
            zi: None,
            ci: None,
            u_prime: None,

            zi_of_ui: None,
            ci_of_ui: None,
            h: None,
        }
    }

    pub fn prove<R: RngCore>(
        pk: &ProvingKey<Bn254>,
        witness: &WitnessInput<Fr>,
        assignment: &Assignment<Fr>,
        public_input: &PublicData<Bn254>,
        precomputed: &ProverPrecomputedData<Bn254>,
        zk_rng: &mut R,
        table_size: usize,
    ) -> Proof<Bn254> {
        let mut state = Self::init(
            pk,
            witness,
            assignment,
            public_input,
            precomputed,
            table_size,
        );
        let mut transcript = Transcript::new_transcript();

        let (w0, key, w1, w2) = Self::assignment_round(&mut state);

        transcript.round_0_public_inputs([
            public_input.external_nullifier,
            public_input.nullifier_hash,
            public_input.signal_hash,
        ]);

        transcript.round_1([&w0, &key, &w1, &w2]);

        let v = transcript.get_challenge();

        let quotient = Self::quotient_round(&mut state, v);

        let (zi, ci, u_prime) = Self::caulk_plus_first_round(&mut state, zk_rng);

        transcript.round_2([&quotient, &zi, &ci, &u_prime]);

        let hi_1 = transcript.get_challenge();
        let hi_2 = transcript.get_challenge();

        let (w, h) = Self::caulk_plus_second_round(&mut state, hi_1, hi_2);

        transcript.round_3(&w, &h);

        let alpha = transcript.get_challenge();

        let (
            multiopen_proof,
            w0_openings_0,
            w0_openings_1,
            w0_openings_2,
            w1_openings_0,
            w1_openings_1,
            w1_openings_2,
            w2_openings_0,
            w2_openings_1,
            w2_openings_2,
            key_openings_0,
            key_openings_1,
            q_mimc_opening,
            c_opening,
            quotient_opening,
            u_prime_opening,
            p1_opening,
            p2_opening,
            p1,
            p2,
        ) = Self::opening_round(&state, hi_1, alpha, &mut transcript);

        // Sanity check multiopen_proof
        let mut transcript = Transcript::new_transcript();
        transcript.update_with_u256(public_input.external_nullifier);
        transcript.update_with_u256(public_input.nullifier_hash);
        transcript.update_with_u256(public_input.signal_hash);
        transcript.update_with_g1(&w0);
        transcript.update_with_g1(&key);
        transcript.update_with_g1(&w1);
        transcript.update_with_g1(&w2);
        let _v = transcript.get_challenge();
        transcript.update_with_g1(&quotient);
        transcript.update_with_g1(&zi);
        transcript.update_with_g1(&ci);
        transcript.update_with_g1(&u_prime);
        let _hi_1 = transcript.get_challenge();
        let _hi_2 = transcript.get_challenge();
        transcript.update_with_g2(&w);
        transcript.update_with_g1(&h);
        let alpha = transcript.get_challenge();
        transcript.update_with_u256(w0_openings_0);
        transcript.update_with_u256(w0_openings_1);
        transcript.update_with_u256(w0_openings_2);

        transcript.update_with_u256(w1_openings_0);
        transcript.update_with_u256(w1_openings_1);
        transcript.update_with_u256(w1_openings_2);

        transcript.update_with_u256(w2_openings_0);
        transcript.update_with_u256(w2_openings_1);
        transcript.update_with_u256(w2_openings_2);

        transcript.update_with_u256(key_openings_0);
        transcript.update_with_u256(key_openings_1);

        transcript.update_with_u256(q_mimc_opening);
        transcript.update_with_u256(c_opening);
        transcript.update_with_u256(quotient_opening);

        transcript.update_with_u256(u_prime_opening);
        transcript.update_with_u256(p1_opening);
        transcript.update_with_u256(p2_opening);

        let n = SUBGROUP_SIZE;
        let domain = GeneralEvaluationDomain::new(n).unwrap();

        let omega: Fr = domain.element(1);
        let omega_n = domain.element(NUMBER_OF_MIMC_ROUNDS);
        let omega_alpha = omega * alpha;
        let omega_n_alpha = omega_n * alpha;

        let q_mimc = commit(&state.proving_key.srs_g1, &state.precomputed.q_mimc).into_affine();
        let c = commit(&state.proving_key.srs_g1, &state.precomputed.c).into_affine();
        let p1 = commit(&state.proving_key.srs_g1, &p1).into_affine();
        let p2 = commit(&state.proving_key.srs_g1, &p2).into_affine();

        let is_multiopen_proof_valid = MultiopenVerifier::verify(
            &mut transcript,
            &multiopen_proof,
            &w0,
            &[w0_openings_0, w0_openings_1, w0_openings_2],
            &w1,
            &[w1_openings_0, w1_openings_1, w1_openings_2],
            &w2,
            &[w2_openings_0, w2_openings_1, w2_openings_2],
            &key,
            &[key_openings_0, key_openings_1],
            &q_mimc,
            q_mimc_opening,
            &c,
            c_opening,
            &quotient,
            quotient_opening,
            &u_prime,
            u_prime_opening,
            &p1,
            p1_opening,
            &p2,
            p2_opening,
            u_prime_opening, //v,
            alpha,
            omega_alpha,
            omega_n_alpha,
            pk.srs_g2[1],
        );
        assert!(is_multiopen_proof_valid);

        let commitments = Commitments {
            w0,
            w1,
            w2,
            key,
            c,
            quotient,
            u_prime,
            zi,
            ci,
            p1,
            p2,
            q_mimc,
            h,
            w,
        };

        let openings = Openings {
            q_mimc: q_mimc_opening,
            c: c_opening,
            quotient: quotient_opening,
            u_prime: u_prime_opening,
            p1: p1_opening,
            p2: p2_opening,
            w0_0: w0_openings_0,
            w0_1: w0_openings_1,
            w0_2: w0_openings_2,
            w1_0: w1_openings_0,
            w1_1: w1_openings_1,
            w1_2: w1_openings_2,
            w2_0: w2_openings_0,
            w2_1: w2_openings_1,
            w2_2: w2_openings_2,
            key_0: key_openings_0,
            key_1: key_openings_1,
        };

        Proof {
            multiopen_proof,
            openings,
            commitments,
        }
    }

    fn assignment_round<E: PairingEngine>(
        state: &mut State<E>,
    ) -> (E::G1Affine, E::G1Affine, E::G1Affine, E::G1Affine) {
        let domain = GeneralEvaluationDomain::<E::Fr>::new(SUBGROUP_SIZE).unwrap();

        let w0 =
            DensePolynomial::from_coefficients_slice(&domain.ifft(&state.assignment.nullifier));
        let key = DensePolynomial::from_coefficients_slice(&domain.ifft(&state.assignment.key));
        let w1 = DensePolynomial::from_coefficients_slice(
            &domain.ifft(&state.assignment.identity_commitment),
        );
        let w2 = DensePolynomial::from_coefficients_slice(
            &domain.ifft(&state.assignment.external_nullifier),
        );

        let omega_pow_rotation = state.domain_h.element(NUMBER_OF_MIMC_ROUNDS);
        let w1_shifted_n = shift_dense_poly(&w1, &omega_pow_rotation);
        let a: DensePolynomial<_> = &w1_shifted_n + &w1 + &key * E::Fr::from(2u64);

        let w0_commit = commit(&state.proving_key.srs_g1, &w0);
        let key_commit = commit(&state.proving_key.srs_g1, &key);
        let w1_commit = commit(&state.proving_key.srs_g1, &w1);
        let w2_commit = commit(&state.proving_key.srs_g1, &w2);

        state.w0 = Some(w0);
        state.key = Some(key);
        state.w1 = Some(w1);
        state.w2 = Some(w2);
        state.a = Some(a);

        (
            w0_commit.into(),
            key_commit.into(),
            w1_commit.into(),
            w2_commit.into(),
        )
    }

    fn quotient_round<E: PairingEngine>(state: &mut State<E>, v: E::Fr) -> E::G1Affine {
        let w0 = state.w0.as_ref().unwrap();
        let key = state.key.as_ref().unwrap();
        let w1 = state.w1.as_ref().unwrap();
        let w2 = state.w2.as_ref().unwrap();

        let extended_coset_domain =
            GeneralEvaluationDomain::<E::Fr>::new(EXTENDED_DOMAIN_FACTOR * SUBGROUP_SIZE).unwrap();

        let w0_coset_evals = extended_coset_domain.coset_fft(w0);
        let key_coset_evals = extended_coset_domain.coset_fft(key);
        let w1_coset_evals = extended_coset_domain.coset_fft(w1);
        let w2_coset_evals = extended_coset_domain.coset_fft(w2);
        let zeroes: Vec<_> = iter::repeat(E::Fr::zero())
            .take(extended_coset_domain.size())
            .collect();

        let num_of_gates = 7;
        let v_powers: Vec<E::Fr> =
            iter::successors(Some(E::Fr::one()), |v_i: &E::Fr| Some(*v_i * v))
                .take(num_of_gates)
                .collect();

        let mut numerator_coset_evals = vec![E::Fr::zero(); extended_coset_domain.size()];
        for (i, numerator_coset_eval_i) in numerator_coset_evals
            .iter_mut()
            .enumerate()
            .take(extended_coset_domain.size())
        {
            // Gate 0:
            *numerator_coset_eval_i += v_powers[0]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &w0_coset_evals,
                    &zeroes,
                    &state.precomputed.c_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate 1:
            *numerator_coset_eval_i += v_powers[1]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &w1_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.c_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate 2:
            *numerator_coset_eval_i += v_powers[2]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &w2_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.c_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate 3:
            *numerator_coset_eval_i += v_powers[3]
                * KeyEquality::compute_in_coset(
                    i,
                    &key_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate 4:
            *numerator_coset_eval_i += v_powers[4]
                * KeyCopyGate::compute_in_coset(
                    i,
                    &w0_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.l0_coset_evals,
                );

            // Gate 5:
            *numerator_coset_eval_i += v_powers[5]
                * NullifierGate::compute_in_coset(
                    i,
                    &w2_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.l0_coset_evals,
                    state.public_input.nullifier_hash,
                );

            // Gate 6:
            *numerator_coset_eval_i += v_powers[6]
                * ExternalNullifierGate::compute_in_coset(
                    i,
                    &w2_coset_evals,
                    &state.precomputed.l0_coset_evals,
                    state.public_input.external_nullifier,
                );
        }

        // sanity check
        // TODO: add cfg if sanity
        {
            let domain = GeneralEvaluationDomain::<E::Fr>::new(SUBGROUP_SIZE).unwrap();
            let zh: DensePolynomial<_> = domain.vanishing_polynomial().into();

            let numerator = DensePolynomial::from_coefficients_slice(
                &extended_coset_domain.coset_ifft(&numerator_coset_evals),
            );

            let q = &numerator / &zh;
            assert_eq!(&q * &zh, numerator);
        }

        let quotient_coset_evals: Vec<_> = numerator_coset_evals
            .iter()
            .zip(state.precomputed.zh_inverse_coset_evals.iter())
            .map(|(&num, &denom)| num * denom)
            .collect();

        // Note: SRS for committing full vector of identities will be large, so we don't need to split quotient into chunks
        // it's just important to check it's degree in verifier
        let quotient = DensePolynomial::from_coefficients_slice(
            &extended_coset_domain.coset_ifft(&quotient_coset_evals),
        );

        let quotient_commit = commit(&state.proving_key.srs_g1, &quotient);
        state.quotient = Some(quotient);
        quotient_commit.into()
    }

    fn caulk_plus_first_round<E: PairingEngine, R: RngCore>(
        state: &mut State<E>,
        rng: &mut R,
    ) -> (E::G1Affine, E::G1Affine, E::G1Affine) {
        // 1. sample blinding factors
        let r1 = E::Fr::rand(rng);
        let r2 = E::Fr::rand(rng);
        let r3 = E::Fr::rand(rng);
        let r4 = E::Fr::rand(rng);
        let r5 = E::Fr::rand(rng);
        let r6 = E::Fr::rand(rng);

        state.r1 = Some(r1);
        state.r2 = Some(r2);
        state.r3 = Some(r3);
        state.r4 = Some(r4);
        state.r5 = Some(r5);
        state.r6 = Some(r6);

        // 2. compute lagrange basis polynomial t_i over w^j for j = index
        let omega = state.domain_t.element(state.witness.index);
        let ts = construct_lagrange_basis(&[omega]);

        // 3. define and mask zI`
        let mut zi = DensePolynomial::<E::Fr>::from_coefficients_slice(&[r1]);
        zi = &zi * &DensePolynomial::from_coefficients_slice(&[-omega, E::Fr::one()]);

        {
            // Sanity check on zi
            let domain = state.domain_t;
            let zh: DensePolynomial<_> = domain.vanishing_polynomial().into();
            let q = &zh / &zi;
            assert_eq!(&q * &zi, zh);
        }

        // 4. define CI
        let mut ci = DensePolynomial::<E::Fr>::zero();
        ci += &(&ts[0] * state.witness.identity_commitment);

        // 5. blind CI
        let ci_blind = &DensePolynomial::from_coefficients_slice(&[r2, r3, r4]) * &zi;
        ci += &ci_blind;

        // 6. define u_prime
        let u_prime_eval = state.domain_t.element(state.witness.index);
        let mut u_prime =
            DensePolynomial::from_coefficients_slice(&state.domain_v.ifft(&[u_prime_eval]));

        // 7. blind u_prime
        let zv: DensePolynomial<_> = state.domain_v.vanishing_polynomial().into();
        let u_blind = &DensePolynomial::from_coefficients_slice(&[r5, r6]) * &zv;
        u_prime += &u_blind;

        // 8. Commit
        let zi_commitment = commit(&state.proving_key.srs_g1, &zi);
        let ci_commitment = commit(&state.proving_key.srs_g1, &ci);
        let u_prime_commitment = commit(&state.proving_key.srs_g1, &u_prime);

        // store data in the state
        state.zi = Some(zi);
        state.ci = Some(ci);
        state.u_prime = Some(u_prime);

        (
            zi_commitment.into(),
            ci_commitment.into(),
            u_prime_commitment.into(),
        )
    }

    fn caulk_plus_second_round<E: PairingEngine>(
        state: &mut State<E>,
        hi_1: E::Fr,
        hi_2: E::Fr,
    ) -> (E::G2Affine, E::G1Affine) {
        // 1. compute linearly separated quotients in g2
        let w1_i = state
            .precomputed
            .caulk_plus_precomputed
            .get_w1_i(&state.witness.index);
        let w2_i = state
            .precomputed
            .caulk_plus_precomputed
            .get_w2_i(&state.witness.index);

        let w1_xi2_w2 = w1_i + w2_i.mul(hi_2).into_affine();

        // 2. Compute H
        let zi = state.zi.as_ref().unwrap();
        let ci = state.ci.as_ref().unwrap();
        let u_prime = state.u_prime.as_ref().unwrap();
        let a = state.a.as_ref().unwrap();

        let composed_degree = max(
            zi.degree() * u_prime.degree(),
            ci.degree() * u_prime.degree(),
        );
        let extended_domain = GeneralEvaluationDomain::<E::Fr>::new(composed_degree).unwrap();

        let u_prime_evals_on_extended_domain =
            cfg_into_iter!(extended_domain.elements()).map(|omega_i| u_prime.evaluate(&omega_i));
        let mut zi_of_u_prime_evals = vec![E::Fr::zero(); extended_domain.size()];
        let mut ci_of_u_prime_evals = vec![E::Fr::zero(); extended_domain.size()];
        for (i, ui) in u_prime_evals_on_extended_domain.enumerate() {
            zi_of_u_prime_evals[i] = zi.evaluate(&ui);
            ci_of_u_prime_evals[i] = ci.evaluate(&ui);
        }

        let zi_of_ui =
            DensePolynomial::from_coefficients_slice(&extended_domain.ifft(&zi_of_u_prime_evals));
        let ci_of_ui =
            DensePolynomial::from_coefficients_slice(&extended_domain.ifft(&ci_of_u_prime_evals));

        let num = &zi_of_ui + &(&(&ci_of_ui - a) * hi_1);
        let (h, r) = num.divide_by_vanishing_poly(state.domain_v).unwrap();

        // sanity
        assert!(r.is_zero());

        // 3. Commit
        let r1 = state.r1.unwrap();
        let r2 = state.r2.unwrap();
        let r3 = state.r3.unwrap();
        let r4 = state.r4.unwrap();

        let ci_blinder = &DensePolynomial::from_coefficients_slice(&[r2, r3, r4]);
        let ci_blinder_commitment = commit(&state.proving_key.srs_g2, ci_blinder);

        let w_commitment = w1_xi2_w2.mul(r1.inverse().unwrap().into_repr()) - ci_blinder_commitment;
        let h_commitment = commit(&state.proving_key.srs_g1, &h);

        // store data in the state
        state.zi_of_ui = Some(zi_of_ui);
        state.ci_of_ui = Some(ci_of_ui);
        state.h = Some(h);

        (w_commitment.into(), h_commitment.into())
    }

    fn opening_round<'a>(
        state: &State<'a, Bn254>,
        hi_1: Fr,
        alpha: Fr, // evaluation challenge
        transcript: &mut Transcript,
    ) -> OpeningRoundResult {
        let omega = state.domain_h.element(1);
        let omega_n = state.domain_h.element(NUMBER_OF_MIMC_ROUNDS);

        let omega_alpha = omega * alpha;
        let omega_n_alpha = omega_n * alpha;

        let w0 = state.w0.as_ref().unwrap();
        let w1 = state.w1.as_ref().unwrap();
        let w2 = state.w2.as_ref().unwrap();
        let key = state.key.as_ref().unwrap();
        let quotient = state.quotient.as_ref().unwrap();

        let c = &state.precomputed.c;
        let q_mimc = &state.precomputed.q_mimc;

        let zi = state.zi.as_ref().unwrap();
        let ci = state.ci.as_ref().unwrap();
        let u_prime = state.u_prime.as_ref().unwrap();
        let h = state.h.as_ref().unwrap();
        let a = state.a.as_ref().unwrap();

        // 1. Compute P1
        let p1 = zi + &(ci * hi_1);

        // 2. Compute P2
        let p2 = {
            let u_at_alpha = u_prime.evaluate(&alpha);
            let zi_at_u_alpha = zi.evaluate(&u_at_alpha);
            let ci_at_u_alpha = ci.evaluate(&u_at_alpha);
            let a_at_alpha = a.evaluate(&alpha);

            let zv_alpha = state.domain_v.evaluate_vanishing_polynomial(alpha);

            let free_coeff = hi_1 * ci_at_u_alpha + zi_at_u_alpha - hi_1 * a_at_alpha;
            let mut h_zv = h * -zv_alpha;
            h_zv[0] += free_coeff;

            h_zv
        };

        // compute all evaluations
        let v = u_prime.evaluate(&alpha);

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
        let u_prime_opening = v;
        let p1_opening = p1.evaluate(&v);
        let p2_opening = p2.evaluate(&alpha);

        assert_eq!(p2_opening, Fr::zero());

        transcript.round_4([
            w0_openings[0],
            w0_openings[1],
            w0_openings[2],
            w1_openings[0],
            w1_openings[1],
            w1_openings[2],
            w2_openings[0],
            w2_openings[1],
            w2_openings[2],
            key_openings[0],
            key_openings[1],
            q_mimc_opening,
            c_opening,
            quotient_opening,
            u_prime_opening,
            p1_opening,
            p2_opening,
        ]);

        // compute proof
        let m = MultiopenProver::prove(
            &state.proving_key.srs_g1,
            w0,
            w1,
            w2,
            key,
            q_mimc,
            c,
            quotient,
            u_prime,
            &p1,
            &p2,
            v,
            alpha,
            omega_alpha,
            omega_n_alpha,
            transcript,
        );

        (
            m,
            w0_openings[0],
            w0_openings[1],
            w0_openings[2],
            w1_openings[0],
            w1_openings[1],
            w1_openings[2],
            w2_openings[0],
            w2_openings[1],
            w2_openings[2],
            key_openings[0],
            key_openings[1],
            q_mimc_opening,
            c_opening,
            quotient_opening,
            u_prime_opening,
            p1_opening,
            p2_opening,
            p1,
            p2,
        )
    }
}
