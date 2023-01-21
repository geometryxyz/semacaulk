use std::ops::Neg;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_bn254::{Bn254, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::AffineCurve;
use ark_ec::PairingEngine;
use ark_ec::ProjectiveCurve;
use ark_ff::BigInteger256;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::Zero;
use ark_ff::{PrimeField, UniformRand};
use ark_std::test_rng;
use ethers::contract::abigen;
use tokio::test;
use super::setup_eth_backend;
use crate::transcript::Transcript;
use crate::{
    bn_solidity_utils::{f_to_u256, format_g1, format_g2},
};

abigen!(
    BN254,
    "./src/contracts/out/BN254.sol/BN254.json",
);
abigen!(
    TestTranscript,
    "./src/contracts/out/TestTranscript.sol/TestTranscript.json",
);
abigen!(
    TestLagrange,
    "./src/contracts/out/TestLagrange.sol/TestLagrange.json",
);

pub fn g1_affine_to_g1point(pt: &G1Affine) -> G1Point {
    G1Point {
        x: f_to_u256(pt.x),
        y: f_to_u256(pt.y),
    }
}

pub fn g2_affine_to_g2point(pt: &G2Affine) -> G2Point {
    G2Point {
        x_0: f_to_u256(pt.x.c1),
        x_1: f_to_u256(pt.x.c0),
        y_0: f_to_u256(pt.y.c1),
        y_1: f_to_u256(pt.y.c0),
    }
}

#[test]
pub async fn test_u256_conversion() {
    let mut rng = test_rng();

    let f = Fr::rand(&mut rng);
    let f_converted = f_to_u256(f);

    let repr = f.into_repr().0;
    assert_eq!(f_converted.0, repr);

    let f_back = Fr::from_repr(BigInteger256::new(f_converted.0)).unwrap();
    assert_eq!(f_back, f);
}

#[tokio::test]
pub async fn test_pairing() {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

    let mut rng = test_rng();

    let bn254_contract = BN254::deploy(client, ()).unwrap().send().await.unwrap();

    // Pairing tests that: e(-a1, a2) * e(b1, b2) * e(c2, c3) == 1

    let a2 = Fr::rand(&mut rng);

    let b1 = Fr::rand(&mut rng);
    let b2 = Fr::rand(&mut rng);

    let c1 = Fr::rand(&mut rng);
    let c2 = Fr::rand(&mut rng);

    let a1 = (b1 * b2 + c1 * c2) * a2.inverse().unwrap();

    // Sanity 1
    assert_eq!(-a1 * a2 + b1 * b2 + c1 * c2, Fr::zero());

    let g1 = G1Affine::prime_subgroup_generator();
    let g2 = G2Affine::prime_subgroup_generator();

    let a1 = g1.mul(-a1).into_affine();
    let a2 = g2.mul(a2).into_affine();
    let b1 = g1.mul(b1).into_affine();
    let b2 = g2.mul(b2).into_affine();
    let c1 = g1.mul(c1).into_affine();
    let c2 = g2.mul(c2).into_affine();

    let res = Bn254::product_of_pairings(&[
        (a1.into(), a2.into()),
        (b1.into(), b2.into()),
        (c1.into(), c2.into()),
    ]);

    // Sanity 2
    assert_eq!(res, Fq12::one());

    let result: bool = bn254_contract
        .verify_pairing_three(
            format_g1(a1),
            format_g2(a2),
            format_g1(b1),
            format_g2(b2),
            format_g1(c1),
            format_g2(c2),
        )
        .call()
        .await
        .unwrap();

    assert!(result);

    drop(anvil);
}

#[tokio::test]
pub async fn test_transcript() {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

    let contract = TestTranscript::deploy(client, ()).unwrap().send().await.unwrap();
    let u1 = Fr::from(100);
    let u2 = Fr::from(200);
    let g1 = G1Affine::prime_subgroup_generator();
    let g2 = G2Affine::prime_subgroup_generator();

    let (ch_contract_1, ch_contract_2) = contract.test_challenges(
        f_to_u256(u1),
        f_to_u256(u2),
        g1_affine_to_g1point(&g1),
        g2_affine_to_g2point(&g2),
    ).call().await.unwrap();

    let mut transcript = Transcript::new_transcript();

    transcript.update_with_u256(u1);
    transcript.update_with_g1(&g1);

    let challenge_1 = transcript.get_challenge();

    transcript.update_with_u256(u2);
    transcript.update_with_g2(&g2);

    let challenge_2 = transcript.get_challenge();

    assert_eq!(ch_contract_1, f_to_u256(challenge_1));
    assert_eq!(ch_contract_2, f_to_u256(challenge_2));

    drop(anvil);
}

#[tokio::test]
pub async fn test_compute_l0_eval() {
    // Test computeL0Eval with 0 and 123
    //test_compute_l0_eval_case(Fr::zero()).await;
    test_compute_l0_eval_case(Fr::from(123u64)).await;
}

pub async fn test_compute_l0_eval_case(alpha: Fr) {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

    let domain_size = 1024;
    let log2_domain_size = 10;
    let domain_size_inv = Fr::from(domain_size as u64).inverse().unwrap();
    //println!("{}", domain_size_inv);
 
    let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap();

    // Sanity check
    let l0_eval = domain.evaluate_all_lagrange_coefficients(alpha)[0];
    let expected = (alpha.pow(&[domain_size as u64, 0, 0, 0]) - Fr::one()) /
        Fr::from(domain_size as u64) /
        (alpha - Fr::one());
    assert_eq!(expected, l0_eval);
    
    // The above computation is represented in the Solidity verifier using the following steps:

    // Step 1: Compute the evaluation of the vanishing polynomial of the domain with domain_size at
    // alpha
    let mut vanishing_poly_eval;
    if alpha == Fr::zero() {
        vanishing_poly_eval = Fr::one().neg();
    } else {
        vanishing_poly_eval = alpha;
        for _ in 0..log2_domain_size {
            vanishing_poly_eval = vanishing_poly_eval * vanishing_poly_eval;
        }
        vanishing_poly_eval = vanishing_poly_eval - Fr::one();
    }

    // Step 2: Compute the value 1 / (alpha - 1)
    let mut one_div_alpha_minus_one;
    if alpha == Fr::zero() {
        one_div_alpha_minus_one = Fr::one().neg();
    } else {
        one_div_alpha_minus_one = alpha - Fr::one();
    }
    one_div_alpha_minus_one = one_div_alpha_minus_one.inverse().unwrap();

    // Step 3: Compute the evaluation of the Lagrange polynomial at point alpha
    let result = (vanishing_poly_eval * domain_size_inv) * one_div_alpha_minus_one;
    
    assert_eq!(result, l0_eval);

    let contract = TestLagrange::deploy(client, ()).unwrap().send().await.unwrap();
    let onchain_result = contract.test_compute_l0_eval(
        f_to_u256(alpha),
    ).call().await.unwrap();
    assert_eq!(onchain_result, f_to_u256(l0_eval));

    drop(anvil);
}
