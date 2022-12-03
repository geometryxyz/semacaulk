use tokio::test;
use ethers::core::utils::keccak256;
use ethers::core::utils::hex;
use ethers::abi::Contract;
use ethers::providers::{Provider, Http};
use ethers::contract::abigen;

use ethers::{prelude::*, utils::Anvil};
// use eyre::Result;
use std::{convert::TryFrom, sync::Arc, time::Duration};
use semaphore::merkle_tree::Branch;
use crate::keccak_tree::{
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
    use keccack_mt::KeccackMT;
    use ethers::core::types::U256;

    // 1. Launch anvil
    let anvil = Anvil::new().spawn();

    // 2. Instantiate the wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    // 3. Connect to the network
    let provider =
        Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));

    // 4. Instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id())));

    // 5. Deploy contract
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

        // 6. Call the contract function
        let index = U256::from(index);
        let result = keccak_mt_contract.gen_root_from_path(index, leaf, flattened_proof).call().await.unwrap();
        assert_eq!(hex::encode(tree.root()), hex::encode(result));
    }
}
