use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::{
    constants::{EXTENDED_DOMAIN_FACTOR, NUMBER_OF_MIMC_ROUNDS},
    utils::positive_rotation_in_coset,
};

pub mod gate_sanity_checks;
pub mod utils;

// TODO: add "compute in opening" for each gate in order to perform sanity checks

pub struct Mimc7RoundGate<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Mimc7RoundGate<F> {
    pub fn compute_in_coset(
        omega_i: usize,
        x: &Vec<F>,
        k: &Vec<F>,
        c: &Vec<F>,
        q_mimc: &Vec<F>,
    ) -> F {
        let pow_7 = |x: F| x.pow(&[7, 0, 0, 0]);

        let x_next = positive_rotation_in_coset(x, omega_i, 1, EXTENDED_DOMAIN_FACTOR);
        q_mimc[omega_i] * (pow_7(x[omega_i] + k[omega_i] + c[omega_i]) - x_next)
    }
}

pub struct KeyEquality<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> KeyEquality<F> {
    pub fn compute_in_coset(omega_i: usize, key: &Vec<F>, q_mimc: &Vec<F>) -> F {
        let key_next = positive_rotation_in_coset(key, omega_i, 1, EXTENDED_DOMAIN_FACTOR);
        q_mimc[omega_i] * (key[omega_i] - key_next)
    }
}

pub struct KeyCopyGate<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> KeyCopyGate<F> {
    pub fn compute_in_coset(omega_i: usize, nullifier: &Vec<F>, key: &Vec<F>, l0: &Vec<F>) -> F {
        let nullifier_pow_n = positive_rotation_in_coset(
            nullifier,
            omega_i,
            NUMBER_OF_MIMC_ROUNDS,
            EXTENDED_DOMAIN_FACTOR,
        );
        l0[omega_i] * (key[omega_i] - nullifier[omega_i] - nullifier_pow_n)
    }
}

pub struct NullifierGate<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> NullifierGate<F> {
    pub fn compute_in_coset(
        omega_i: usize,
        nullifier_external: &Vec<F>,
        key: &Vec<F>,
        l0: &Vec<F>,
        nullifier: F, // public input
    ) -> F {
        let nullifier_external_pow_n = positive_rotation_in_coset(
            nullifier_external,
            omega_i,
            NUMBER_OF_MIMC_ROUNDS,
            EXTENDED_DOMAIN_FACTOR,
        );
        l0[omega_i]
            * (nullifier
                - nullifier_external_pow_n
                - F::from(2u64) * key[omega_i]
                - nullifier_external[omega_i])
    }
}

#[cfg(test)]
mod tests;
