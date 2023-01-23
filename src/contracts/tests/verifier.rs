use ark_bn254::{Bn254, Fr};
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ark_std::test_rng;
use rand::rngs::StdRng;
use ethers::prelude::abigen;
use ethers::types::U256;
use crate::{
    bn_solidity_utils::{f_to_u256, u256_to_hex},
    kzg::{commit, unsafe_setup},
    layouter::Layouter,
    mimc7::init_mimc7,
    prover::{ProverPrecomputedData, ProvingKey, PublicData},
};
use crate::prover::prover::{Prover, WitnessInput};
use crate::verifier::{Verifier as SemacaulkVerifier};
use crate::constants::DUMMY_VALUE;
use crate::contracts::format_proof;
use super::setup_eth_backend;

abigen!(
    Verifier,
    "./src/contracts/out/Verifier.sol/Verifier.json",
);

#[tokio::test]
pub async fn test_semacaulk_verifier() {
    let mut rng = test_rng();

    let table_size: usize = 1024;
    let domain = GeneralEvaluationDomain::<Fr>::new(table_size).unwrap();

    let mimc7 = init_mimc7::<Fr>();

    let identity_nullifier = Fr::from(100u64);
    let identity_trapdoor = Fr::from(200u64);
    let external_nullifier = Fr::from(300u64);

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

    let dummy_value = Fr::from(DUMMY_VALUE);

    let mut identity_commitments: Vec<_> = (0..table_size).map(|_| Fr::rand(&mut rng)).collect();
    let index = 10;
    identity_commitments[index] = identity_commitment;
    let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&identity_commitments));

    let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(table_size, table_size, &mut rng);
    let pk = ProvingKey::<Bn254> { srs_g1, srs_g2: srs_g2.clone() };

    let precomputed = ProverPrecomputedData::index(&pk, &mimc7.cts, dummy_value, index, &c, table_size);

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

    let is_valid = SemacaulkVerifier::verify(
        &proof,
        pk.srs_g1[table_size].clone(),
        srs_g2[1].clone(),
        accumulator,
        external_nullifier,
        nullifier_hash,
    );

    assert_eq!(is_valid, true);

    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;
    
    let contract = Verifier::deploy(client, ()).unwrap().send().await.unwrap();
    let result = contract.verify(
        p_to_p(&format_proof(&proof)),
        f_to_u256(external_nullifier),
        f_to_u256(nullifier_hash),
    ).call().await.unwrap();

    //println!("u_prime_opening: {}", proof.openings.u_prime);
    println!("\nresult0: {}", u256_to_hex(result.0));
    println!("result1: {}", u256_to_hex(result.1));
    drop(anvil);
}

// Get past the type errors that stem from the way that ethers-rs magically brings abigen types in
// into scope
fn p_to_p(p: &crate::contracts::verifier::Proof) -> Proof {
    let m = MultiopenProof {
        q_1_opening: p.multiopen_proof.q_1_opening,
        q_2_opening: p.multiopen_proof.q_2_opening,
        q_3_opening: p.multiopen_proof.q_3_opening,
        q_4_opening: p.multiopen_proof.q_4_opening,
        f_cm: G1Point {
            x: p.multiopen_proof.f_cm.x,
            y: p.multiopen_proof.f_cm.y,
        },
        final_poly_proof: G1Point {
            x: p.multiopen_proof.final_poly_proof.x,
            y: p.multiopen_proof.final_poly_proof.y,
        },
    };

    let o = Openings {
        q_mimc: p.openings.q_mimc,
        c: p.openings.c,
        quotient: p.openings.quotient,
        u_prime: p.openings.u_prime,
        p_1: p.openings.p_1,
        p_2: p.openings.p_2,
        w_0_0: p.openings.w_0_0,
        w_0_1: p.openings.w_0_1,
        w_0_2: p.openings.w_0_2,
        w_1_0: p.openings.w_1_0,
        w_1_1: p.openings.w_1_1,
        w_1_2: p.openings.w_1_2,
        w_2_0: p.openings.w_2_0,
        w_2_1: p.openings.w_2_1,
        w_2_2: p.openings.w_2_2,
        key_0: p.openings.key_0,
        key_1: p.openings.key_1,
    };

    let c = Commitments {
        w_0: G1Point {
            x: p.commitments.w_0.x,
            y: p.commitments.w_0.y,
        },
        w_1: G1Point  {
            x: p.commitments.w_1.x,
            y: p.commitments.w_1.y,
        },
        w_2: G1Point  {
            x: p.commitments.w_2.x,
            y: p.commitments.w_2.y,
        },
        key: G1Point  {
            x: p.commitments.key.x,
            y: p.commitments.key.y,
        },
        c: G1Point  {
            x: p.commitments.c.x,
            y: p.commitments.c.y,
        },
        quotient: G1Point  {
            x: p.commitments.quotient.x,
            y: p.commitments.quotient.y,
        },
        u_prime: G1Point  {
            x: p.commitments.u_prime.x,
            y: p.commitments.u_prime.y,
        },
        zi: G1Point  {
            x: p.commitments.zi.x,
            y: p.commitments.zi.y,
        },
        ci: G1Point  {
            x: p.commitments.ci.x,
            y: p.commitments.ci.y,
        },
        p_1: G1Point  {
            x: p.commitments.p_1.x,
            y: p.commitments.p_1.y,
        },
        p_2: G1Point  {
            x: p.commitments.p_2.x,
            y: p.commitments.p_2.y,
        },
        q_mimc: G1Point  {
            x: p.commitments.q_mimc.x,
            y: p.commitments.q_mimc.y,
        },
        h: G1Point  {
            x: p.commitments.h.x,
            y: p.commitments.h.y,
        },
        w: G2Point  {
            x_0: p.commitments.w.x_0,
            x_1: p.commitments.w.x_1,
            y_0: p.commitments.w.y_0,
            y_1: p.commitments.w.y_1,
        },
    };

    Proof {
        multiopen_proof: m,
        commitments: c,
        openings: o,
    }
}

#[tokio::test]
pub async fn test_offchain_batch_invert() {
    let num_vals = 8;
    let mut a_vals = Vec::<Fr>::with_capacity(num_vals);
    for i in 0..num_vals {
        a_vals.push(Fr::from((1 + i) as u64))
    }

    let mut b_vals = Vec::<Fr>::with_capacity(num_vals);
    b_vals.push(a_vals[0]);
    for i in 1..num_vals {
        b_vals.push(a_vals[i] * b_vals[i - 1]);
    }

    let t_n = b_vals[num_vals - 1].inverse().unwrap();
    //println!("t_n: {}", f_to_u256(t_n));

    let mut c_vals: Vec<Fr> = vec![Fr::from(0); num_vals];
    let mut t_vals: Vec<Fr> = vec![Fr::from(0); num_vals];
    t_vals[num_vals - 1] = t_n;

    for index in 2..(num_vals + 1) {
        let i = num_vals - index + 2;
        t_vals[i - 2] = t_vals[i - 1] * a_vals[i - 1];
        c_vals[i - 1] = t_vals[i - 1] * b_vals[i - 2];
        //println!("{} * {}", t_vals[i - 1], a_vals[i - 1]);
    }

    let mut result: Vec<Fr> = vec![];
    result.push(t_vals[0]);
    for index in 1..num_vals {
        let i = num_vals - index - 1;
        result.push(c_vals[num_vals - i - 1]);
    }

    //for i in 0..num_vals {
        //println!("t[{}]: {}", i, f_to_u256(t_vals[i]));
        ////println!("a: {}", a_vals[i]);
        //println!("b[{}]: {}", i, f_to_u256(b_vals[i]));
        //println!("c[{}]: {}", i, f_to_u256(c_vals[i]));
        ////let inv = a_vals[i].inverse().unwrap();
        //assert_eq!(a_vals[i].inverse().unwrap(), result[i]);
        //println!("")
    //}
}

#[tokio::test]
pub async fn test_batch_invert() {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

    let contract = Verifier::deploy(client, ()).unwrap().send().await.unwrap();

    let inputs_as_f = vec![
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];

    let expected_inverses = inputs_as_f.iter().map(|x| x.inverse().unwrap()).collect::<Vec<Fr>>();

    let results = contract.batch_invert(
        inputs_as_f.iter().map(|x| f_to_u256(*x)).collect::<Vec<U256>>().try_into().unwrap()
    ).call().await.unwrap();

    assert_eq!(results.len(), expected_inverses.len());
    //println!("{:?}", results);
    //println!("{:?}", expected_inverses);
    for i in 0..results.len() {
        assert_eq!(results[i], f_to_u256(expected_inverses[i]));
    }

    drop(anvil)
}
