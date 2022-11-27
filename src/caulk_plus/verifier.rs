use std::marker::PhantomData;

use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{to_bytes, Field, One, PrimeField};
use ark_poly::EvaluationDomain;
use ark_std::rand::RngCore;

use crate::{error::Error, rng::FiatShamirRng};

use super::{proof::Proof, CommonInput, PublicInput};

pub struct VerifierMessages<F: Field> {
    pub xi_1: Option<F>,
    pub xi_2: Option<F>,
    pub alpha: Option<F>,
}

impl<F: Field> VerifierMessages<F> {
    pub fn empty() -> Self {
        Self {
            xi_1: None,
            xi_2: None,
            alpha: None,
        }
    }
    pub fn first_msg<R: RngCore>(&mut self, rng: &mut R) {
        self.xi_1 = Some(F::rand(rng));
        self.xi_2 = Some(F::rand(rng));
    }

    pub fn second_msg<R: RngCore>(&mut self, rng: &mut R) {
        self.alpha = Some(F::rand(rng));
    }
}

pub struct Verifier<E: PairingEngine> {
    _e: PhantomData<E>,
}

impl<E: PairingEngine> Verifier<E> {
    // TODO: return result from here
    pub fn verify(
        public_input: &PublicInput<E>,
        common_input: &CommonInput<E>,
        proof: &Proof<E>,
        fs_rng: &mut impl FiatShamirRng,
    ) -> Result<(), Error> {
        let mut verifier_msgs = VerifierMessages::<E::Fr>::empty();
        fs_rng.absorb(
            &to_bytes![
                &proof.zi_commitment,
                &proof.ci_commitment,
                &proof.u_commitment
            ]
            .unwrap(),
        );
        verifier_msgs.first_msg(fs_rng);

        fs_rng.absorb(&to_bytes![&proof.w_commitment, &proof.h_commitment].unwrap());
        verifier_msgs.second_msg(fs_rng);

        // TODO: create get methods which return error if some msm is None
        let xi_1 = verifier_msgs.xi_1.as_ref().unwrap();
        let xi_2 = verifier_msgs.xi_2.as_ref().unwrap();
        let alpha = verifier_msgs.alpha.as_ref().unwrap();

        // 1. compute p1
        let p1 = proof.zi_commitment + proof.ci_commitment.mul(xi_1.into_repr()).into();

        // 2. compute p2
        let zv_at_alpha = common_input.domain_v.evaluate_vanishing_polynomial(*alpha);
        let p2 = E::G1Affine::prime_subgroup_generator().mul(proof.p1_eval.into_repr())
            - common_input.a_commitment.mul(xi_1.into_repr())
            - proof.h_commitment.mul(zv_at_alpha.into_repr());

        // 3. check openings
        let lhs_1: E::G1Affine = {
            // TODO: [x^n - 1] can be precomputed
            common_input.c_commitment
                + -proof.ci_commitment
                + (public_input.srs_g1[common_input.domain_h.size()]
                    + -E::G1Affine::prime_subgroup_generator())
                .mul(xi_2.into_repr())
                .into()
        };

        let res = E::product_of_pairings(&[
            ((-lhs_1).into(), public_input.srs_g2[0].into()),
            (proof.zi_commitment.into(), proof.w_commitment.into()),
        ]);
        if res != E::Fqk::one() {
            return Err(Error::FinalPairingCheckFailed);
        }

        Ok(())
    }
}
