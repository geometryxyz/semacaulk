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
}

impl<E: PairingEngine> CommonInput<E> {
    pub fn new(
        order_n: usize,
        order_m: usize,
        c_commitment: E::G1Affine,
        a_commitment: E::G1Affine,
    ) -> Self {
        let domain_h = GeneralEvaluationDomain::new(order_n).unwrap();
        let domain_v = GeneralEvaluationDomain::new(order_m).unwrap();
        Self {
            domain_h,
            domain_v,
            c_commitment,
            a_commitment,
        }
    }
}
