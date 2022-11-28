use ark_ec::PairingEngine;

pub struct Proof<E: PairingEngine> {
    // round 1
    pub(crate) zi_commitment: E::G1Affine,
    pub(crate) ci_commitment: E::G1Affine,
    pub(crate) u_commitment: E::G1Affine,

    // round 2
    pub(crate) w_commitment: E::G2Affine,
    pub(crate) h_commitment: E::G1Affine,

    // round 3
    pub(crate) u_eval: E::Fr,
    pub(crate) u_proof: E::G1Affine,

    pub(crate) p1_eval: E::Fr,
    pub(crate) p1_proof: E::G1Affine,

    pub(crate) p2_proof: E::G1Affine,
}
