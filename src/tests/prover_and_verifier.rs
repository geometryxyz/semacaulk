use crate::prover::prover::{Prover, WitnessInput};
use crate::setup::setup;
use crate::utils::construct_lagrange_basis_poly;
use crate::verifier::Verifier;
use crate::{
    kzg::commit,
    layouter::Layouter,
    mimc7::init_mimc7,
    prover::{ProverPrecomputedData, PublicData},
};
use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    UVPolynomial,
};
use ark_std::{test_rng, One};

#[test]
pub fn test_prover_and_verifier() {
    let mut rng = test_rng();
    let log_2_table_size = 10;
    let table_size: usize = 1 << log_2_table_size;
    let (pk, _) = setup(log_2_table_size, "./11.ptau");

    let domain = GeneralEvaluationDomain::<Fr>::new(table_size).unwrap();

    let mimc7 = init_mimc7::<Fr>();

    let identity_nullifier = Fr::from(100u64);
    let identity_trapdoor = Fr::from(200u64);
    let external_nullifier = Fr::from(300u64);
    let signal_hash = Fr::from(888u64);

    let nullifier_hash = mimc7.multi_hash(&[identity_nullifier, external_nullifier], Fr::zero());

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

    let mut precomputed = ProverPrecomputedData::precompute_fixed(&mimc7.cts);
    precomputed.precompute_w1(&pk, &[index], &c, table_size);
    precomputed.precompute_w2(&pk, &[index], table_size);

    let witness = WitnessInput {
        identity_nullifier,
        identity_trapdoor,
        identity_commitment,
        index,
    };

    let accumulator = commit(&pk.srs_g1, &c).into_affine();
    let public_input = PublicData::<Bn254> {
        accumulator,
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
        pk.srs_g1[table_size],
        pk.srs_g2[1],
        accumulator,
        &public_input,
    );

    assert!(is_valid);
}

#[test]
pub fn test_update_precomputed_w1() {
    let mut rng = test_rng();
    let log_2_table_size = 10;
    let table_size: usize = 1 << log_2_table_size;
    let (pk, lagrange_comms) = setup(log_2_table_size, "./11.ptau");
    let zero = Fr::from(0);

    let domain = GeneralEvaluationDomain::<Fr>::new(table_size).unwrap();

    let mimc7 = init_mimc7::<Fr>();

    // Alice's public and private inputs
    let identity_nullifier = Fr::from(100u64);
    let identity_trapdoor = Fr::from(200u64);
    let external_nullifier = Fr::from(300u64);
    let signal_hash = Fr::from(888u64);
    let nullifier_hash = mimc7.multi_hash(&[identity_nullifier, external_nullifier], Fr::zero());
    let identity_commitment =
        mimc7.multi_hash(&[identity_nullifier, identity_trapdoor], Fr::zero());

    let mut identity_commitments: Vec<_> = (0..table_size).map(|_| zero).collect();

    // Alice inserts to index 0 and Bob inserts to index 1
    let index_alice = 0;
    let index_bob = 1;
    identity_commitments[index_alice] = identity_commitment;

    // Compute the accumulator
    let accumulator_alice_poly =
        DensePolynomial::from_coefficients_slice(&domain.ifft(&identity_commitments));

    // Precompute
    let mut precomputed = ProverPrecomputedData::index(
        &pk,
        &mimc7.cts,
        &[index_alice, index_bob],
        &accumulator_alice_poly,
        table_size,
    );

    let accumulator_alice = commit(&pk.srs_g1, &accumulator_alice_poly).into_affine();

    let identity_nullifier_bob = Fr::from(300u64);
    let identity_trapdoor_bob = Fr::from(400u64);
    let identity_commitment_bob =
        mimc7.multi_hash(&[identity_nullifier_bob, identity_trapdoor_bob], Fr::zero());

    // The identity commitment which Bob replaces
    let original_bob = identity_commitments[index_bob];

    // Check w1_alice
    let w_old = precomputed.caulk_plus_precomputed.get_w1_i(&index_alice);
    let w_i = domain.element(index_alice);
    let denom = DensePolynomial::from_coefficients_slice(&[-w_i, Fr::one()]);
    let mut num = accumulator_alice_poly.clone();
    num[0] -= accumulator_alice_poly.evaluate(&w_i);
    let p = &num / &denom;
    let p_comm = commit(&pk.srs_g2, &p).into_affine();
    assert_eq!(w_old, p_comm);

    // Bob replaces the leaf at index_bob
    identity_commitments[index_bob] = identity_commitment_bob;
    let accumulator_bob_poly =
        DensePolynomial::from_coefficients_slice(&domain.ifft(&identity_commitments));
    let accumulator_bob = commit(&pk.srs_g1, &accumulator_bob_poly).into_affine();
    assert_ne!(accumulator_alice, accumulator_bob);

    // delta
    let delta = identity_commitment_bob - original_bob;

    // Check the new accumulator
    let l_j_comm = lagrange_comms[index_bob];
    let l_j_delta_comm = l_j_comm.mul(delta).into_affine();
    let new_c = accumulator_alice + l_j_delta_comm;
    assert_eq!(new_c, accumulator_bob);

    // L_j(X) / (X - w_i)
    let elems: Vec<Fr> = domain.elements().collect();
    let l_j = construct_lagrange_basis_poly(&elems, index_bob);
    let w_i = domain.element(index_alice);
    let denom = DensePolynomial::from_coefficients_slice(&[-w_i, Fr::one()]);
    let p = &l_j / &denom;
    let p_comm = commit(&pk.srs_g2, &p).into_affine();

    let delta_p_comm = p_comm.mul(delta);

    let w_old = precomputed.caulk_plus_precomputed.get_w1_i(&index_alice);
    let w_new = w_old + delta_p_comm.into();

    // Use update_w1() to update Alice's precomputed data
    precomputed.update_w1(index_alice, w_new);

    // Generate proof for Alice
    let witness = WitnessInput {
        identity_nullifier,
        identity_trapdoor,
        identity_commitment,
        index: index_alice,
    };

    let public_input = PublicData::<Bn254> {
        accumulator: accumulator_bob,
        external_nullifier,
        nullifier_hash,
        signal_hash,
    };

    let assignment = Layouter::assign(
        identity_nullifier,
        identity_trapdoor,
        external_nullifier,
        &mimc7.cts,
        &mut rng,
    );

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
        pk.srs_g1[table_size],
        pk.srs_g2[1],
        accumulator_bob,
        &public_input,
    );
    assert!(is_valid);
    /*
     */
}
