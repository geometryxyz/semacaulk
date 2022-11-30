use tokio::test;
use ethers::core::utils::keccak256;
use ethers::core::utils::hex;
use ethers::abi::Contract;
use ethers::providers::{Provider, Http};
use ethers::contract::abigen;
use hex::decode;

use ethers::{prelude::*, utils::Anvil};
// use eyre::Result;
use std::{convert::TryFrom, sync::Arc, time::Duration};


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

    //let preimage = [0u8; 64];
    //let r1 = keccak256(preimage);
    let r1_vec = hex::decode("ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5").unwrap();
    let r2_vec = hex::decode("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30").unwrap();

    let r1: [u8; 32] = r1_vec.try_into().unwrap();
    let r2: [u8; 32] = r2_vec.try_into().unwrap();

    let zero = [0u8; 32];
    let proof = vec![zero, r1];

    // 6. call contract function
    let index = ethers::core::types::U256::from(1u64);
    let result = keccak_mt_contract.gen_root_from_path(index, zero, proof).call().await.unwrap();
    assert_eq!(hex::encode(r2), hex::encode(result));
}

/*
 * r1 = keccak256([0, 0]) = ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5
 * r2 = keccak256([r1, r1]) = b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30
 * r3 = keccak256([r2, r2]) = 21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85
 * r4 = keccak256([r3, r3]) = e58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344
 */
