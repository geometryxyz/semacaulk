use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{One, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_std::UniformRand;
use rand::RngCore;
use std::{cmp::max, iter};

pub fn unsafe_setup<E: PairingEngine, R: RngCore>(
    max_power_g1: usize,
    max_power_g2: usize,
    rng: &mut R,
) -> (Vec<E::G1Affine>, Vec<E::G2Affine>) {
    let tau = E::Fr::rand(rng);
    let size = max(max_power_g1 + 1, max_power_g2 + 1);
    let powers_of_tau: Vec<E::Fr> = iter::successors(Some(E::Fr::one()), |p| Some(p.clone() * tau))
        .take(size)
        .collect();

    let g1_gen = E::G1Affine::prime_subgroup_generator();
    let g2_gen = E::G2Affine::prime_subgroup_generator();

    let srs_g1: Vec<E::G1Affine> = powers_of_tau
        .iter()
        .take(max_power_g1 + 1)
        .map(|tp| g1_gen.mul(tp.into_repr()).into())
        .collect();

    let srs_g2: Vec<E::G2Affine> = powers_of_tau
        .iter()
        .take(max_power_g2 + 1)
        .map(|tp| g2_gen.mul(tp.into_repr()).into())
        .collect();
    (srs_g1, srs_g2)
}

pub fn commit<G: AffineCurve>(srs: &[G], poly: &DensePolynomial<G::ScalarField>) -> G::Projective {
    let coeff_scalars: Vec<_> = poly.coeffs.iter().map(|c| c.into_repr()).collect();
    VariableBaseMSM::multi_scalar_mul(&srs, &coeff_scalars)
}

pub fn open<G: AffineCurve>(
    srs: &[G],
    poly: &DensePolynomial<G::ScalarField>,
    challenge: G::ScalarField,
) -> (G::ScalarField, G) {
    let q = poly / &DensePolynomial::from_coefficients_slice(&[-challenge, G::ScalarField::one()]);
    if srs.len() - 1 < q.degree() {
        panic!(
            "SRS size to small! Can't commit to polynomial of degree {} with srs of size {}",
            q.degree(),
            srs.len()
        );
    }
    let proof = commit(srs, &q);
    (poly.evaluate(&challenge), proof.into())
}
