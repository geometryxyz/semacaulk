use super::setup_eth_backend;
use crate::keccak_tree::{flatten_proof, KeccakTree};
use ethers::contract::abigen;
use ethers::core::types::U256;
use ethers::core::utils::{hex, keccak256};
use tokio::test;

abigen!(KeccackMT, "./src/contracts/out/KeccakMT.sol/KeccakMT.json",);

#[test]
pub async fn test_keccak_256() {
    let preimage = [0u8; 64];
    let hash = keccak256(preimage);
    assert_eq!(
        hex::encode(hash),
        "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"
    );

    let mut preimage = Vec::from(hash);
    let mut x = preimage.clone();
    preimage.append(&mut x);
    let r2 = keccak256(preimage);
    assert_eq!(
        hex::encode(r2),
        "b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30"
    );
}

#[tokio::test]
pub async fn test_keccak_mt() {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

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
        let result = keccak_mt_contract
            .gen_root_from_path(index, leaf, flattened_proof)
            .call()
            .await
            .unwrap();
        assert_eq!(hex::encode(tree.root()), hex::encode(result));
    }

    drop(anvil);
}
