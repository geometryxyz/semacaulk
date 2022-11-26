use std::collections::BTreeMap;

use ark_ec::PairingEngine;
use ark_ff::One;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    UVPolynomial,
};

use crate::utils::commit;

/*
   Precomputed data will be stored in <key, value> map for key = index, value = [w_{1,2}^i]_2

   We can precompute all data, but it's very possible that just some indices will be needed,
   so we optimize precomputed data needed to store
*/
pub struct Precomputed<E: PairingEngine> {
    w1_mapping: BTreeMap<usize, E::G2Affine>,
    w2_mapping: BTreeMap<usize, E::G2Affine>,
}

impl<E: PairingEngine> Precomputed<E> {
    pub fn empty() -> Self {
        Self {
            w1_mapping: BTreeMap::default(),
            w2_mapping: BTreeMap::default(),
        }
    }
    pub fn get_w1_i(&self, index: &usize) -> E::G2Affine {
        match self.w1_mapping.get(index) {
            Some(element) => *element,
            None => panic!("Element on index: {} is not precomputed", index),
        }
    }

    pub fn get_w2_i(&self, index: &usize) -> E::G2Affine {
        match self.w2_mapping.get(index) {
            Some(element) => *element,
            None => panic!("Element on index: {} is not precomputed", index),
        }
    }

    pub fn precompute_w1(
        &mut self,
        srs: &[E::G2Affine],
        indices: &[usize],
        c: &DensePolynomial<E::Fr>,
        domain: &GeneralEvaluationDomain<E::Fr>,
    ) {
        for index in indices {
            let w_i = domain.element(*index);
            let mut num = c.clone();
            num[0] -= c.evaluate(&w_i);

            let denom = DensePolynomial::from_coefficients_slice(&[-w_i, E::Fr::one()]);
            let w1_i = &num / &denom;
            let w1_i = commit(srs, &w1_i);
            self.w1_mapping.insert(*index, w1_i.into());
        }
    }

    pub fn precompute_w2(
        &mut self,
        srs: &[E::G2Affine],
        indices: &[usize],
        domain: &GeneralEvaluationDomain<E::Fr>,
    ) {
        let zh: DensePolynomial<_> = domain.vanishing_polynomial().into();
        for index in indices {
            let w2_i = &zh
                / &DensePolynomial::from_coefficients_slice(&[
                    -domain.element(*index),
                    E::Fr::one(),
                ]);
            let w2_i = commit(srs, &w2_i);
            self.w2_mapping.insert(*index, w2_i.into());
        }
    }
}
