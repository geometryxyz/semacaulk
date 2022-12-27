/*
   We have: v, alpha, w^1alpha and w^91alpha
*/

use ark_ec::PairingEngine;

pub mod fi;
pub mod prover;
pub mod verifier;

pub struct MultiopenProof<E: PairingEngine> {
    pub(crate) q1_opening: E::Fr,
    pub(crate) q2_opening: E::Fr,
    pub(crate) q3_opening: E::Fr,
    pub(crate) q4_opening: E::Fr,
    pub(crate) f_cm: E::G1Affine,
    pub(crate) final_poly_proof: E::G1Affine
}
