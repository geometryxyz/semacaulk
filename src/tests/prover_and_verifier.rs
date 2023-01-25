use ark_bn254::{Bn254, Fr};
use ark_ec::ProjectiveCurve;
use ark_ff::{UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ark_std::test_rng;
use rand::rngs::StdRng;
use crate::{
    kzg::{commit, unsafe_setup},
    layouter::Layouter,
    mimc7::init_mimc7,
    prover::{ProverPrecomputedData, ProvingKey, PublicData},
};
use crate::prover::prover::{Prover, WitnessInput};
use crate::verifier::Verifier;

#[test]
pub fn test_prover_and_verifier() {
    let mut rng = test_rng();
    let table_size: usize = 1024;
    let domain = GeneralEvaluationDomain::<Fr>::new(table_size).unwrap();

    let mimc7 = init_mimc7::<Fr>();

    let identity_nullifier = Fr::from(100u64);
    let identity_trapdoor = Fr::from(200u64);
    let external_nullifier = Fr::from(300u64);
    let signal_hash = Fr::from(888u64);

    let nullifier_hash =
        mimc7.multi_hash(&[identity_nullifier, external_nullifier], Fr::zero());

    let identity_commitment =
        mimc7.multi_hash(&[identity_nullifier, identity_trapdoor], Fr::zero());

    let assignment = Layouter::assign(
        identity_nullifier,
        identity_trapdoor,
        external_nullifier,
        &mimc7.cts,
        &mut rng,
    );

    let mut identity_commitments: Vec<_> = (0..table_size).map(|_| Fr::rand(&mut rng)).collect();
    let index = 10;
    identity_commitments[index] = identity_commitment;
    let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&identity_commitments));

    let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(table_size, table_size, &mut rng);
    let pk = ProvingKey::<Bn254> { srs_g1, srs_g2: srs_g2.clone() };

    let precomputed = ProverPrecomputedData::index(&pk, &mimc7.cts, index, &c, table_size);

    let witness = WitnessInput {
        identity_nullifier,
        identity_trapdoor,
        identity_commitment,
        index,
    };

    let accumulator = commit(&pk.srs_g1, &c).into_affine();
    let public_input = PublicData::<Bn254> {
        accumulator: accumulator,
        external_nullifier,
        nullifier_hash,
        signal_hash,
    };

    let proof = Prover::prove(
        &pk,
        &witness,
        &assignment,
        &public_input,
        &precomputed,
        &mut rng,
        table_size,
    );

    let is_valid = Verifier::verify(
        &proof,
        pk.srs_g1[table_size].clone(),
        srs_g2[1].clone(),
        accumulator,
        &public_input,
    );

    assert_eq!(is_valid, true);
}
