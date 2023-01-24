use crate::accumulator::{
    commit_to_lagrange_bases, compute_lagrange_tree, compute_zero_leaf, Accumulator,
};
use crate::kzg::unsafe_setup_g1;
use crate::{
    bn_solidity_utils::f_to_u256,
    keccak_tree::flatten_proof,
};
use ark_bn254::{Bn254, Fq, Fr};
use ark_ff::UniformRand;
use ark_std::{rand::rngs::StdRng, test_rng};
use ethers::contract::abigen;
use ethers::core::types::U256;
use ethers::core::utils::hex;
use ethers::middleware::SignerMiddleware;
use ethers::providers::Http;
use super::{
    setup_eth_backend,
    EthersClient,
};

abigen!(
    Semacaulk,
    "./src/contracts/out/Semacaulk.sol/Semacaulk.json",
);

type SemacaulkContract = semacaulk::Semacaulk<
    SignerMiddleware<
        ethers::providers::Provider<Http>,
        ethers::signers::Wallet<ethers::core::k256::ecdsa::SigningKey>,
    >,
>;

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
pub async fn test_semacaulk_insert() {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

    let domain_size = 8;
    let mut rng = test_rng();

    let semacaulk_contract_and_acc = deploy_semacaulk(domain_size, &mut rng, client).await;
    let semacaulk_contract = semacaulk_contract_and_acc.0;
    let mut acc = semacaulk_contract_and_acc.1;

    let tree = compute_lagrange_tree::<Bn254>(&acc.lagrange_comms);

    for index in 0..tree.num_leaves() {
        let proof = tree.proof(index).unwrap();
        let flattened_proof = flatten_proof(&proof);

        let l_i = acc.lagrange_comms[index];
        let l_i_x = f_to_u256(l_i.x);
        let l_i_y = f_to_u256(l_i.y);

        let new_leaf = Fr::rand(&mut rng);
        let new_leaf_u256 = f_to_u256(new_leaf);

        println!("index: {}", index);

        // Insert the leaf on chain
        let result = semacaulk_contract
            .insert_identity(new_leaf_u256, l_i_x, l_i_y, flattened_proof)
            .send()
            .await
            .unwrap()
            .await
            .unwrap()
            .expect("no receipt found");

        let event_index = result.logs[0].topics[1];
        let mut index_slice = [0u8; 32];
        index_slice[31] = index as u8;

        assert_eq!(index < 256, true);
        assert_eq!(hex::encode(index_slice), hex::encode(event_index));
        assert_eq!(result.status.unwrap(), ethers::types::U64::from(1));

        println!(
            "Gas used by insertIdentity(): {:?}",
            result.gas_used.unwrap()
        );

        // Check that currentIndex is incremented
        let new_index = semacaulk_contract.get_current_index().call().await.unwrap();
        assert_eq!(new_index, U256::from(index + 1));

        // Insert the leaf off-chain
        acc.update(index, new_leaf);

        let onchain_point = semacaulk_contract.get_accumulator().call().await.unwrap();
        assert_eq!(f_to_u256(acc.point.x), onchain_point.x);
        assert_eq!(f_to_u256(acc.point.y), onchain_point.y);
    }

    drop(anvil);
}
