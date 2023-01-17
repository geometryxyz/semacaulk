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

use crate::proof::Proof;
use crate::{
    constants::{EXTENDED_DOMAIN_FACTOR, NUMBER_OF_MIMC_ROUNDS, SUBGROUP_SIZE},
    gates::{KeyCopyGate, KeyEquality, Mimc7RoundGate, NullifierGate},
    kzg::commit,
    layouter::Assignment,
    transcript::Transcript,
    utils::construct_lagrange_basis,
    utils::shift_dense_poly,
    multiopen::{prover::Prover as MultiopenProver, MultiopenProof}
};

use super::{ProverPrecomputedData, ProvingKey, PublicData};

pub struct WitnessInput<F: PrimeField> {
    identity_nullifier: F,
    identity_trapdoor: F,
    identity_commitment: F,
    index: usize,
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
    pub(crate) u: Option<DensePolynomial<E::Fr>>,

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
    ) -> State<'a, E> {
        let domain_h = GeneralEvaluationDomain::new(SUBGROUP_SIZE).unwrap();
        let domain_v = GeneralEvaluationDomain::new(1).unwrap();
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
            u: None,

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
    ) {
        let mut state = Self::init(pk, witness, assignment, public_input, precomputed);
        let mut transcript = Transcript::new_transcript();

        // TODO: append public data

        let (w0, key, w1, w2) = Self::assignment_round(&mut state);

        transcript.update_with_g1(&w0);
        transcript.update_with_g1(&key);
        transcript.update_with_g1(&w1);
        transcript.update_with_g1(&w2);

        let v = transcript.get_challenge();

        let quotient = Self::quotient_round(&mut state, v);

        transcript.update_with_g1(&quotient);

        let (zi_commitment, ci_commitment, u_commitment) =
            Self::caulk_plus_first_round(&mut state, zk_rng);

        transcript.update_with_g1(&zi_commitment);
        transcript.update_with_g1(&ci_commitment);
        transcript.update_with_g1(&u_commitment);

        let hi_1 = transcript.get_challenge();
        let hi_2 = transcript.get_challenge();

        let (_w_commitment, _h_commitment) = Self::caulk_plus_second_round(&mut state, hi_1, hi_2);
        //let (w_commitment, h_commitment) = Self::caulk_plus_second_round(&mut state, hi_1, hi_2);
        // transcript.update_with_g1(&w_commitment);
        // transcript.update_with_g1(&h_commitment);

        let alpha = transcript.get_challenge();

        let multiopen_proof = Self::opening_round(&state, hi_1, alpha, &mut transcript);
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

        let num_of_gates = 6;
        let v_powers: Vec<E::Fr> =
            iter::successors(Some(E::Fr::one()), |v_i: &E::Fr| Some(v_i.clone() * v))
                .take(num_of_gates)
                .collect();

        let mut numerator_coset_evals = vec![E::Fr::zero(); extended_coset_domain.size()];
        for i in 0..extended_coset_domain.size() {
            // Gate0:
            numerator_coset_evals[i] += v_powers[0]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &w0_coset_evals,
                    &zeroes,
                    &state.precomputed.c_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate1:
            numerator_coset_evals[i] += v_powers[1]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &w1_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.c_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate2:
            numerator_coset_evals[i] += v_powers[2]
                * Mimc7RoundGate::compute_in_coset(
                    i,
                    &w2_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.c_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate3:
            numerator_coset_evals[i] += v_powers[3]
                * KeyEquality::compute_in_coset(
                    i,
                    &key_coset_evals,
                    &state.precomputed.q_mimc_coset_evals,
                );

            // Gate4:
            numerator_coset_evals[i] += v_powers[4]
                * KeyCopyGate::compute_in_coset(
                    i,
                    &w0_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.l0_coset_evals,
                );

            // Gate5:
            numerator_coset_evals[i] += v_powers[5]
                * NullifierGate::compute_in_coset(
                    i,
                    &w2_coset_evals,
                    &key_coset_evals,
                    &state.precomputed.l0_coset_evals,
                    state.public_input.nullifier_hash,
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
        let omega = state.domain_h.element(state.witness.index);
        let ts = construct_lagrange_basis(&[omega]);

        // 3. define and mask zI`
        let mut zi = DensePolynomial::<E::Fr>::from_coefficients_slice(&[r1]);
        zi = &zi * &DensePolynomial::from_coefficients_slice(&[-omega, E::Fr::one()]);

        // 4. define CI
        let mut ci = DensePolynomial::<E::Fr>::zero();
        ci += &(&ts[0] * state.witness.identity_commitment);

        // 5. blind CI
        let ci_blind = &DensePolynomial::from_coefficients_slice(&[r2, r3, r4]) * &zi;
        ci += &ci_blind;

        // 6. define U
        let u_eval = state.domain_h.element(state.witness.index);
        let mut u = DensePolynomial::from_coefficients_slice(&state.domain_v.ifft(&[u_eval]));

        // 7. blind U
        let zv: DensePolynomial<_> = state.domain_v.vanishing_polynomial().into();
        let u_blind = &DensePolynomial::from_coefficients_slice(&[r5, r6]) * &zv;
        u += &u_blind;

        // 8. Commit
        let zi_commitment = commit(&state.proving_key.srs_g1, &zi);
        let ci_commitment = commit(&state.proving_key.srs_g1, &ci);
        let u_commitment = commit(&state.proving_key.srs_g1, &u);

        // store data in the state
        state.zi = Some(zi);
        state.ci = Some(ci);
        state.u = Some(u);

        (
            zi_commitment.into(),
            ci_commitment.into(),
            u_commitment.into(),
        )
    }

    fn caulk_plus_second_round<'a, E: PairingEngine>(
        state: &mut State<'a, E>,
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
        let u = state.u.as_ref().unwrap();
        let a = state.a.as_ref().unwrap();

        let composed_degree = max(zi.degree() * u.degree(), ci.degree() * u.degree());
        let extended_domain = GeneralEvaluationDomain::<E::Fr>::new(composed_degree).unwrap();

        let u_evals_on_extended_domain =
            cfg_into_iter!(extended_domain.elements()).map(|omega_i| u.evaluate(&omega_i));
        let mut zi_of_u_evals = vec![E::Fr::zero(); extended_domain.size()];
        let mut ci_of_u_evals = vec![E::Fr::zero(); extended_domain.size()];
        for (i, ui) in u_evals_on_extended_domain.enumerate() {
            zi_of_u_evals[i] = zi.evaluate(&ui);
            ci_of_u_evals[i] = ci.evaluate(&ui);
        }

        let zi_of_ui =
            DensePolynomial::from_coefficients_slice(&extended_domain.ifft(&zi_of_u_evals));
        let ci_of_ui =
            DensePolynomial::from_coefficients_slice(&extended_domain.ifft(&ci_of_u_evals));

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
        let ci_blinder_commitment = commit(&state.proving_key.srs_g2, &ci_blinder);

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
        transcript: &mut Transcript
    ) -> MultiopenProof<Bn254> {
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
        let u = state.u.as_ref().unwrap();
        let h = state.h.as_ref().unwrap();
        let a = state.a.as_ref().unwrap();

        // 1. Compute P1
        let p1 = zi + &(ci * hi_1);

        // 2. Compute P2
        let p2 = {
            let u_at_alpha = u.evaluate(&alpha);
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
        let v = u.evaluate(&alpha);

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

        // BEGIN: append all openings to transcipt
        transcript.update_with_u256(w0_openings[0]);
        transcript.update_with_u256(w0_openings[1]);
        transcript.update_with_u256(w0_openings[2]);

        transcript.update_with_u256(w1_openings[0]);
        transcript.update_with_u256(w1_openings[1]);
        transcript.update_with_u256(w1_openings[2]);

        transcript.update_with_u256(w2_openings[0]);
        transcript.update_with_u256(w2_openings[1]);
        transcript.update_with_u256(w2_openings[2]);

        transcript.update_with_u256(key_openings[0]);
        transcript.update_with_u256(key_openings[1]);

        transcript.update_with_u256(q_mimc_opening);
        transcript.update_with_u256(c_opening);
        transcript.update_with_u256(quotient_opening);

        transcript.update_with_u256(u_prime_opening);
        transcript.update_with_u256(p1_opening);
        transcript.update_with_u256(p2_opening);
        // END: append all openings to transcipt

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
            u,
            &p1,
            &p2,
            v,
            alpha,
            omega_alpha,
            omega_n_alpha,
            transcript,
        );

        // let x = Proof {
        //     w0,
        //     w1,
        //     w2,
        //     key,
        //     quotient,
        //     w0_alpha: todo!(),
        //     w0_omega_alpha: todo!(),
        //     w0_omega_n_alpha: todo!(),
        //     w1_alpha: todo!(),
        //     w1_omega_alpha: todo!(),
        //     w1_omega_n_alpha: todo!(),
        //     w2_alpha: todo!(),
        //     w2_omega_alpha: todo!(),
        //     w2_omega_n_alpha: todo!(),
        //     key_alpha: todo!(),
        //     key_omega_alpha: todo!(),
        //     q_mimc_alpha: todo!(),
        //     c_alpha: todo!(),
        //     quotient_alpha: todo!(),
        //     zi,
        //     ci,
        //     u,
        //     h,
        //     u_alpha: todo!(),
        //     p1_v: todo!(),
        //     p2_alpha: todo!(),
        //     multiopen_proof: todo!(),
        // };

        m
    }
}

#[cfg(test)]
mod prover_tests {
    use ark_bn254::{Bn254, Fr};
    use ark_ec::ProjectiveCurve;
    use ark_ff::{UniformRand, Zero};
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
    };
    use ark_std::test_rng;
    use rand::rngs::StdRng;
    //use semaphore::identity;

    use crate::{
        //caulk_plus::precomputed,
        kzg::{commit, unsafe_setup},
        layouter::Layouter,
        mimc7::Mimc7,
        prover::{ProverPrecomputedData, ProvingKey, PublicData},
    };

    use super::{Prover, WitnessInput};

    #[test]
    fn test_prover() {
        let n_rounds = 91;
        let mut rng = test_rng();

        let domain_size = 1024;
        let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap();

        let mimc7 = Mimc7::<Fr>::new("mimc".into(), n_rounds);

        let identity_nullifier = Fr::from(100u64);
        let identity_trapdoor = Fr::from(200u64);

        let external_nullifier = Fr::from(300u64);

        let nullifier_hash =
            mimc7.multi_hash(&[identity_nullifier, external_nullifier], Fr::zero());

        let identity_commitment =
            mimc7.multi_hash(&[identity_nullifier, identity_trapdoor], Fr::zero());

        let assignment = Layouter::assign(
            identity_nullifier,
            identity_trapdoor,
            external_nullifier,
            &mimc7.cts,
            &mut rng,
        );

        let dummy_value = Fr::from(9999u64);

        let mut identity_commitments: Vec<_> = (0..1024).map(|_| Fr::rand(&mut rng)).collect();
        let index = 10;
        identity_commitments[index] = identity_commitment;
        let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&identity_commitments));

        let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(1024, 1024, &mut rng);
        let pk = ProvingKey::<Bn254> { srs_g1, srs_g2 };

        let precomputed = ProverPrecomputedData::index(&pk, &mimc7.cts, dummy_value, index, &c);

        let witness = WitnessInput {
            identity_nullifier,
            identity_trapdoor,
            identity_commitment,
            index,
        };

        let c_commitment = commit(&pk.srs_g1, &c).into_affine();
        let public_input = PublicData::<Bn254> {
            c_commitment: c_commitment,
            external_nullifier,
            nullifier_hash,
        };

        Prover::prove(
            &pk,
            &witness,
            &assignment,
            &public_input,
            &precomputed,
            &mut rng,
        );

        // Prover::prove(&pk, &index, &assignment, nullifier_external);
    }
}
