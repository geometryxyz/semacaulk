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
use ethers::types::U256;
use tokio::test;
use super::setup_eth_backend;
use crate::transcript::Transcript;
use crate::{
    bn_solidity_utils::{f_to_u256, format_g1, format_g2},
};

abigen!(
    TestTranscript,
    "./src/contracts/out/TestTranscript.sol/TestTranscript.json",
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

    transcript.update_with_f(u1);
    transcript.update_with_g1(&g1);

    let challenge_1 = transcript.get_challenge();

    transcript.update_with_f(u2);
    transcript.update_with_g2(&g2);

    let challenge_2 = transcript.get_challenge();

    assert_eq!(ch_contract_1, f_to_u256(challenge_1));
    assert_eq!(ch_contract_2, f_to_u256(challenge_2));

    drop(anvil);
}
