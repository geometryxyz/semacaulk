use tokio::test;
use ethers::core::utils::keccak256;
use ethers::core::utils::hex;
use ethers::abi::Contract;
use ethers::providers::{Provider, Http};
use ethers::contract::abigen;

use ethers::{prelude::*, utils::Anvil};
// use eyre::Result;
use std::{convert::TryFrom, sync::Arc, time::Duration};


#[test]
pub async fn test_keccak_256() {
    // preimage = abi.encode[bytes32(0), bytes32(0)]
    let preimage = [0u8; 64];
    let hash = keccak256(preimage);
    assert_eq!(hex::encode(hash), "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5");
}

#[tokio::test]
pub async fn test_keccak_mt() {
    abigen!(KeccackMT, "./src/contracts/out/KeccakMT.sol/KeccakMT.json",);
    use keccack_mt::KeccackMT;

    // 1. compile the contract (note this requires that you are inside the `examples` directory) and
    // launch anvil
    let anvil = Anvil::new().spawn();

    // 2. instantiate our wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    // 3. connect to the network
    let provider =
        Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));

    // 4. instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id())));

    // 5. deploy contract
    let keccak_mt_contract = KeccackMT::deploy(client, ()).unwrap().send().await.unwrap();;

    // 6. call contract function
    let result = keccak_mt_contract.verify_merkle_path().call().await.unwrap();
    println!("{:?}", result);
    //assert_eq!(result, true);
}
