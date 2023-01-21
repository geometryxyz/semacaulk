use crate::accumulator::{
    commit_to_lagrange_bases, compute_lagrange_tree, compute_zero_leaf, Accumulator,
};
use crate::kzg::unsafe_setup_g1;
use crate::transcript::Transcript;
use crate::{
    bn_solidity_utils::{f_to_u256, formate_g1, formate_g2},
    keccak_tree::flatten_proof,
};
use ark_bn254::{Bn254, Fq, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::AffineCurve;
use ark_ec::PairingEngine;
use ark_ec::ProjectiveCurve;
use ark_ff::BigInteger256;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::Zero;
use ark_ff::{PrimeField, UniformRand};
use ark_std::{rand::rngs::StdRng, test_rng};
use ethers::contract::abigen;
use ethers::core::types::U256;
use ethers::core::utils::hex;
use ethers::middleware::SignerMiddleware;
use ethers::providers::Http;
use tokio::test;
use super::{
    setup_eth_backend,
    EthersClient,
};

abigen!(
    Semacaulk,
    "./src/contracts/out/Semacaulk.sol/Semacaulk.json",
);
abigen!(
    BN254,
    "./src/contracts/out/BN254.sol/BN254.json",
);

type SemacaulkContract = semacaulk::Semacaulk<
    SignerMiddleware<
        ethers::providers::Provider<Http>,
        ethers::signers::Wallet<ethers::core::k256::ecdsa::SigningKey>,
    >,
>;

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

pub async fn deploy_semacaulk(
    domain_size: usize,
    rng: &mut StdRng,
    client: EthersClient,
) -> (SemacaulkContract, Accumulator<Bn254>) {
    let zero = compute_zero_leaf::<Fr>();
    let srs_g1 = unsafe_setup_g1::<Bn254, StdRng>(domain_size, rng);

    let lagrange_comms = commit_to_lagrange_bases::<Bn254>(domain_size, &srs_g1);

    let acc = Accumulator::<Bn254>::new(zero, &lagrange_comms);

    let empty_accumulator_x = f_to_u256::<Fq>(acc.point.x);
    let empty_accumulator_y = f_to_u256::<Fq>(acc.point.y);

    // Construct the tree of commitments to the Lagrange bases
    let tree = compute_lagrange_tree::<Bn254>(&lagrange_comms);
    let root = tree.root();

    // Deploy contract
    let semacaulk_contract =
        Semacaulk::deploy(client, (root, empty_accumulator_x, empty_accumulator_y))
            .unwrap()
            .send()
            .await
            .unwrap();

    (semacaulk_contract, acc)
}

#[tokio::test]
pub async fn test_pairing() {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

    let domain_size = 8;
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
            formate_g1(a1),
            formate_g2(a2),
            formate_g1(b1),
            formate_g2(b2),
            formate_g1(c1),
            formate_g2(c2),
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

    let domain_size = 8;
    let mut rng = test_rng();

    let semacaulk_contract_and_acc = deploy_semacaulk(domain_size, &mut rng, client).await;
    let semacaulk_contract = semacaulk_contract_and_acc.0;

    let (ch_contract_1, ch_contract_2) =
        semacaulk_contract.verify_transcript().call().await.unwrap();

    let mut transcript = Transcript::new_transcript();

    let u1 = Fr::from(100);
    transcript.update_with_u256(u1);

    let g1 = G1Affine::prime_subgroup_generator();
    transcript.update_with_g1(&g1);

    let challenge_1 = transcript.get_challenge();

    let u2 = Fr::from(200);
    transcript.update_with_u256(u2);

    let challenge_2 = transcript.get_challenge();

    assert_eq!(ch_contract_1, f_to_u256(challenge_1));
    assert_eq!(ch_contract_2, f_to_u256(challenge_2));

    drop(anvil);
}
