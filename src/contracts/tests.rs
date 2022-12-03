use tokio::test;
use ethers::core::utils::keccak256;
use ethers::core::utils::hex;
use ethers::providers::{Provider, Http};
use ethers::contract::abigen;
use ark_std::{rand::rngs::StdRng, test_rng};
use ark_bn254::Bn254;
use ark_ff::ToBytes;

use crate::kzg::unsafe_setup_g1;
use crate::commit_to_lagrange_bases;
use crate::compute_lagrange_tree;
use ethers::core::types::U256;
use ethers::{prelude::*, utils::Anvil};
use std::{convert::TryFrom, sync::Arc, time::Duration};
use crate::keccak_tree::{
    Branch,
    KeccakTree,
    KeccakMerkleProof,
};

fn flatten_proof(proof: &KeccakMerkleProof) -> Vec<[u8; 32]> {
    let mut result = Vec::with_capacity(proof.0.len());
    for branch in &proof.0 {
        let hash = match branch {
            Branch::Left(hash) => hash,
            Branch::Right(hash) => hash,
        };
        result.push(hash.clone());
    }
    result
}

#[test]
pub async fn test_keccak_256() {
    // preimage = abi.encode[bytes32(0), bytes32(0)]
    let preimage = [0u8; 64];
    let hash = keccak256(preimage);
    assert_eq!(hex::encode(hash), "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5");

    let mut preimage = Vec::from(hash);
    let mut x = preimage.clone();
    preimage.append(&mut x);
    let r2 = keccak256(preimage);
    assert_eq!(hex::encode(r2), "b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30");
}

#[tokio::test]
pub async fn test_keccak_mt() {
    abigen!(KeccackMT, "./src/contracts/out/KeccakMT.sol/KeccakMT.json",);

    // Launch anvil
    let anvil = Anvil::new().spawn();

    // Instantiate the wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    // Connect to the network
    let provider =
        Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));

    // Instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id())));

    // Deploy contract
    let keccak_mt_contract = KeccackMT::deploy(client, ()).unwrap().send().await.unwrap();

    let mut tree = KeccakTree::new(4, [0; 32]);

    for index in 0..tree.num_leaves() {
        let mut leaf = [0u8; 32];
        leaf[31] = index as u8;
        tree.set(index, leaf);
    }

    for index in 0..tree.num_leaves() {
        let proof = tree.proof(index).unwrap();
        let flattened_proof = flatten_proof(&proof);

        let leaf = tree.leaves()[index];

        // Call the contract function
        let index = U256::from(index);
        let result = keccak_mt_contract.gen_root_from_path(index, leaf, flattened_proof).call().await.unwrap();
        assert_eq!(hex::encode(tree.root()), hex::encode(result));
    }
}

#[tokio::test]
pub async fn test_semacaulk_insert() {
    abigen!(Semacaulk, "./src/contracts/out/Semacaulk.sol/Semacaulk.json",);

    // Launch anvil
    let anvil = Anvil::new().spawn();

    // Instantiate the wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    // Connect to the network
    let provider =
        Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));

    // Instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id())));

    // Construct the tree of commitments to the Lagrange bases
    let domain_size = 8;
    let mut rng = test_rng();

    let srs_g1 = unsafe_setup_g1::<Bn254, StdRng>(domain_size, &mut rng);
    let lagrange_comms = commit_to_lagrange_bases::<Bn254>(domain_size, srs_g1);

    let tree = compute_lagrange_tree::<Bn254>(&lagrange_comms);
    let root = tree.root();

    // Deploy contract
    let keccak_mt_contract = Semacaulk::deploy(client, root).unwrap().send().await.unwrap();

    for index in 0..tree.num_leaves() {
        let proof = tree.proof(index).unwrap();
        let flattened_proof = flatten_proof(&proof);

        let l_i = &lagrange_comms[index];
        let mut l_i_x = Vec::with_capacity(32);
        let mut l_i_y = Vec::with_capacity(32);
        let _ = l_i.x.write(&mut l_i_x);
        let _ = l_i.y.write(&mut l_i_y);

        // Call the contract function
        let index = U256::from(index);
        let result = keccak_mt_contract.insert_identity(
            U256::zero(),
            l_i_x.try_into().unwrap(),
            l_i_y.try_into().unwrap(),
            flattened_proof,
        ).send()
        .await.unwrap()
        .await.unwrap()
        .expect("no receipt found");
        assert_eq!(result.status.unwrap(), ethers::types::U64::from(1));

        // Check that currentIndex is incremented
        let new_index = keccak_mt_contract.current_index().call().await.unwrap();
        assert_eq!(new_index, index + 1);
    }
}
