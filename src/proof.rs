use ark_ec::PairingEngine;

use crate::multiopen::MultiopenProof;

// TODO: add some descriptive methods around proof

pub struct Proof<E: PairingEngine> {
    // semaphore related oracles
    pub(crate) w0: E::G1Affine, 
    pub(crate) w1: E::G1Affine, 
    pub(crate) w2: E::G1Affine, 
    pub(crate) key: E::G1Affine, 
    pub(crate) quotient: E::G1Affine,

    //semaphore related openings
    pub(crate) w0_alpha: E::Fr,
    pub(crate) w0_omega_alpha: E::Fr,
    pub(crate) w0_omega_n_alpha: E::Fr,

    pub(crate) w1_alpha: E::Fr,
    pub(crate) w1_omega_alpha: E::Fr,
    pub(crate) w1_omega_n_alpha: E::Fr,

    pub(crate) w2_alpha: E::Fr,
    pub(crate) w2_omega_alpha: E::Fr,
    pub(crate) w2_omega_n_alpha: E::Fr,

    pub(crate) key_alpha: E::Fr,
    pub(crate) key_omega_alpha: E::Fr,

    pub(crate) q_mimc_alpha: E::Fr, 
    pub(crate) c_alpha: E::Fr, 
    pub(crate) quotient_alpha: E::Fr,

    // caulk+ related oracles
    pub(crate) zi: E::G1Affine, 
    pub(crate) ci: E::G1Affine, 
    pub(crate) u: E::G1Affine, 
    pub(crate) h: E::G1Affine,

    // caulk+ related openings
    pub(crate) u_alpha: E::Fr, 
    pub(crate) p1_v: E::Fr, 
    pub(crate) p2_alpha: E::Fr,

    // multiopen proof
    pub(crate) multiopen_proof: MultiopenProof<E>
}