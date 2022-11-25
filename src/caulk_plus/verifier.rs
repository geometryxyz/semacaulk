use std::marker::PhantomData;

use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::rand::RngCore;

use super::{PublicInput, CommonInput, proof::Proof};

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
    pub fn receive_first_msg<R: RngCore>(&mut self, rng: &mut R) {
        self.xi_1 = Some(F::rand(rng));
        self.xi_2 = Some(F::rand(rng));
    }

    pub fn receive_second_msg<R: RngCore>(&mut self, rng: &mut R) {
        self.alpha = Some(F::rand(rng));
    }
}

pub struct Verifier<E: PairingEngine> {
    _e: PhantomData<E>
}

impl<E: PairingEngine> Verifier<E> {
    // TODO: return result from here
    pub fn verify(
        public_input: &PublicInput<E>, 
        common_input: &CommonInput<E>, 
        proof: &Proof<E>
    ) {
        // 1. compute p1

        // 2. compute p2

        // 3. check openings
    }
}
