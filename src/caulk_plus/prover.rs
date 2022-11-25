use std::{cmp::max, collections::BTreeMap, marker::PhantomData};

use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    UVPolynomial,
};
use ark_std::{cfg_into_iter, rand::RngCore, UniformRand};

use crate::utils::construct_lagrange_basis;

use super::{
    precomputed::{self, Precomputed},
    verifier::VerifierMessages,
    CommonInput, PublicInput,
};

pub struct WitnessInput<F: Field> {
    indices: Vec<usize>,
    values: Vec<F>,
    c: DensePolynomial<F>,
    a: DensePolynomial<F>,
    mapping: Vec<usize>,
}

struct State<'a, E: PairingEngine> {
    // init data in the state
    pub(crate) common_input: &'a CommonInput<E>,
    pub(crate) witness: &'a WitnessInput<E::Fr>,
    pub(crate) precomputed: &'a Precomputed<E>,

    // data after first round
    pub(crate) r1: Option<E::Fr>,
    pub(crate) r2: Option<E::Fr>,
    pub(crate) r3: Option<E::Fr>,
    pub(crate) r4: Option<E::Fr>,
    pub(crate) r5: Option<E::Fr>,
    pub(crate) r6: Option<E::Fr>,

    pub(crate) zi: Option<DensePolynomial<E::Fr>>,
    pub(crate) ci: Option<DensePolynomial<E::Fr>>,
    pub(crate) u: Option<DensePolynomial<E::Fr>>,

    // data after second round
    pub(crate) zi_of_ui: Option<DensePolynomial<E::Fr>>,
    pub(crate) ci_of_ui: Option<DensePolynomial<E::Fr>>,
    pub(crate) h: Option<DensePolynomial<E::Fr>>,
}

pub struct Prover<E: PairingEngine> {
    _pe: PhantomData<E>,
}

impl<E: PairingEngine> Prover<E> {
    pub fn prove<R: RngCore>(
        common_input: &CommonInput<E>,
        witness: &WitnessInput<E::Fr>,
        precomputed: &Precomputed<E>,
        zk_rng: &mut R,
    ) {
        let mut state = Self::init(common_input, witness, precomputed);
        let mut verifier_msgs = VerifierMessages::<E::Fr>::empty();

        let (zi, ci, u) = Self::first_round(&mut state, zk_rng);

        // commit to zi, ci, u

        // get first message
        verifier_msgs.receive_first_msg(zk_rng); //TODO: this should be from fs_rng in FiatShamir

        // second round
        Self::second_round(&mut state, &verifier_msgs);

        // get second message
    }

    fn init<'a>(
        common_input: &'a CommonInput<E>,
        witness: &'a WitnessInput<E::Fr>,
        precomputed: &'a Precomputed<E>,
    ) -> State<'a, E> {
        State {
            common_input,
            witness,
            precomputed,
            r1: None,
            r2: None,
            r3: None,
            r4: None,
            r5: None,
            r6: None,

            zi: None,
            ci: None,
            u: None,

            zi_of_ui: None,
            ci_of_ui: None,
            h: None,
        }
    }

    fn first_round<R: RngCore>(
        state: &mut State<E>,
        rng: &mut R,
    ) -> (
        DensePolynomial<E::Fr>,
        DensePolynomial<E::Fr>,
        DensePolynomial<E::Fr>,
    ) {
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

        // 2. compute lagrange basis polynomials t_i over w^j for j in I
        let elems: Vec<E::Fr> = state
            .witness
            .indices
            .iter()
            .map(|&i| state.common_input.domain_h.element(i))
            .collect();
        let ts = construct_lagrange_basis(&elems);

        // 3. define and mask zI`
        let mut zi = DensePolynomial::<E::Fr>::from_coefficients_slice(&[r1]);
        for omega_i in elems {
            zi = &zi * &DensePolynomial::from_coefficients_slice(&[-omega_i, E::Fr::one()]);
        }

        // 4. define CI
        let mut ci = DensePolynomial::<E::Fr>::zero();
        for (t_i, &eval) in ts.iter().zip(state.witness.values.iter()) {
            ci += &(t_i * eval)
        }

        // 5. blind CI
        let ci_blind = &DensePolynomial::from_coefficients_slice(&[r2, r3, r4]) * &zi;
        ci += &ci_blind;

        // 6. define U
        let u_evals = (0..state.common_input.domain_v.size())
            .map(|i| {
                state
                    .common_input
                    .domain_h
                    .element(state.witness.mapping[i])
            })
            .collect::<Vec<_>>();
        let mut u =
            DensePolynomial::from_coefficients_slice(&state.common_input.domain_v.ifft(&u_evals));

        // 7. blind U
        let zv: DensePolynomial<_> = state.common_input.domain_v.vanishing_polynomial().into();
        let u_blind = &DensePolynomial::from_coefficients_slice(&[r5, r6]) * &zv;
        u += &u_blind;

        // store data in the state
        state.zi = Some(zi.clone());
        state.ci = Some(ci.clone());
        state.u = Some(u.clone());

        // 8. Commit

        (zi, ci, u)
    }

    fn second_round<'a>(state: &mut State<'a, E>, msgs: &VerifierMessages<E::Fr>) {
        let xi_1 = msgs.xi_1.unwrap();
        let xi_2 = msgs.xi_2.unwrap();

        // 1. compute linearly separated quotients in g2
        let mut w1_xi2_w2 = E::G2Projective::zero();
        for i in &state.witness.indices {
            let w1_i = state.precomputed.get_w1_i(i);
            let w2_i = state.precomputed.get_w2_i(i);

            let omega_i = state.common_input.domain_h.element(*i);
            let mut denom = E::Fr::one();
            for j in &state.witness.indices {
                if j != i {
                    denom *= omega_i - state.common_input.domain_h.element(*j);
                }
            }

            let denom_inv = denom.inverse().unwrap();
            w1_xi2_w2 = w1_xi2_w2 + w1_i.mul(denom_inv) + w2_i.mul(denom_inv * xi_2);
        }

        // 2. Compute H
        let zi = state.zi.as_ref().unwrap();
        let ci = state.ci.as_ref().unwrap();
        let u = state.u.as_ref().unwrap();

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

        let num = &zi_of_ui + &(&(&ci_of_ui - &state.witness.a) * xi_1);
        let (h, r) = num
            .divide_by_vanishing_poly(state.common_input.domain_v)
            .unwrap();

        // sanity
        assert!(r.is_zero());

        // store data in the state
        state.zi_of_ui = Some(zi_of_ui.clone());
        state.ci_of_ui = Some(ci_of_ui.clone());
        state.h = Some(h.clone());

        // 3. Commit
    }

    fn third_round<'a>(state: &State<'a, E>, msgs: &VerifierMessages<E::Fr>) {
        let xi_1 = msgs.xi_1.unwrap();
        let xi_2 = msgs.xi_2.unwrap();
        let alpha = msgs.alpha.unwrap();

        let zi = state.zi.as_ref().unwrap();
        let ci = state.ci.as_ref().unwrap();
        let u = state.u.as_ref().unwrap();
        let h = state.h.as_ref().unwrap();


        // 1. Compute P1
        let p1 = zi + &(ci * xi_1);

        // 2. Compute P2
        let p2 = {
            let u_at_alpha = u.evaluate(&alpha);
            let zi_at_u_alpha = zi.evaluate(&u_at_alpha);
            let ci_at_u_alpha = ci.evaluate(&u_at_alpha);

            let zv: DensePolynomial<_> = state.common_input.domain_v.vanishing_polynomial().into();

            let mut acc = &state.witness.a * -xi_1;
            acc[0] += xi_1 * ci_at_u_alpha + zi_at_u_alpha;

            let h_zv = h * &zv;

            &acc - &h_zv
        };

        // 3. Open

    }
}

#[cfg(test)]
mod prover_tests {
    use crate::utils::unsafe_setup;

    use super::*;
    use ark_bn254::{Bn254, Fr as F, G1Affine, G2Affine};
    use ark_std::{rand::rngs::StdRng, test_rng};

    fn to_field<F: Field>(evals: &[u64]) -> Vec<F> {
        evals.iter().map(|&e| F::from(e)).collect()
    }

    #[test]
    fn test_simple_proof() {
        let mut rng = test_rng();
        let max_power = 8;
        let h = 8;
        let domain_h = GeneralEvaluationDomain::<F>::new(h).unwrap();

        let v = 4;
        let domain_v = GeneralEvaluationDomain::<F>::new(v).unwrap();

        let (srs, srs_g2) = unsafe_setup::<Bn254, StdRng>(max_power, max_power, &mut rng);
        let pi = PublicInput::<Bn254> {
            srs_g1: srs,
            srs_g2,
        };

        let common_input = CommonInput::<Bn254> {
            domain_h: domain_h.clone(),
            domain_v: domain_v.clone(),
            c_commitment: G1Affine::zero(), //for now
            a_commitment: G1Affine::zero(), // for now
        };

        let evals = &[132, 321, 213141, 32193, 43892, 12319, 321341, 32910841];
        let c_evals = to_field::<F>(evals);

        let a_evals = vec![c_evals[1], c_evals[2], c_evals[5], c_evals[7]];
        let mapping = vec![1, 2, 5, 7];

        let c = DensePolynomial::from_coefficients_slice(&domain_h.ifft(&c_evals));
        let a = DensePolynomial::from_coefficients_slice(&domain_v.ifft(&a_evals));

        // for elem in domain_v.elements() {
        //     println!("a_I: {}", a.evaluate(&elem));
        // }

        // println!("==============");

        let witness = WitnessInput::<F> {
            indices: vec![1, 2, 5, 7],
            values: a_evals,
            c: c.clone(),
            a,
            mapping,
        };

        let mut precomputed = Precomputed::<Bn254>::empty();
        precomputed.precompute_w1(&pi.srs_g2, &[1, 2, 5, 7], &c, &domain_h);
        precomputed.precompute_w2(&pi.srs_g2, &[1, 2, 5, 7], &domain_h);

        Prover::prove(&common_input, &witness, &precomputed, &mut rng);
    }
}
