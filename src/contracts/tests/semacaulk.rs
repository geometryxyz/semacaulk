use ark_ec::ProjectiveCurve;
use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::UniformRand;
use ark_std::{rand::rngs::StdRng, test_rng, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ethers::contract::abigen;
use ethers::core::types::U256;
use ethers::core::utils::hex;
use ethers::middleware::SignerMiddleware;
use ethers::providers::Http;
use crate::kzg::{commit, unsafe_setup};
use crate::mimc7::init_mimc7;
use crate::prover::{ProverPrecomputedData, ProvingKey, PublicData, Proof as SemacaulkProof};
use crate::prover::prover::{Prover, WitnessInput};
use crate::layouter::Layouter;
use crate::verifier::{Verifier as SemacaulkVerifier};
use crate::accumulator::{
    commit_to_lagrange_bases, compute_lagrange_tree, compute_zero_leaf, Accumulator,
};
use crate::{
    bn_solidity_utils::{f_to_u256, u256_to_f},
    keccak_tree::flatten_proof,
};
use crate::contracts::compute_signal_hash;
use crate::contracts::format::proof_for_semacaulk::{ProofForSemacaulk, format_proof};
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
    table_size: usize,
    rng: &mut StdRng,
    client: EthersClient,
) -> (
        SemacaulkContract, Accumulator<Bn254>, Vec<G1Affine>, Vec<G2Affine>
    ) {
    let zero = compute_zero_leaf::<Fr>();
    let (srs_g1, srs_g2) = unsafe_setup::<Bn254, StdRng>(table_size, table_size, rng);

    let lagrange_comms = commit_to_lagrange_bases::<Bn254>(table_size, &srs_g1);

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

    (semacaulk_contract, acc, srs_g1, srs_g2)
}

#[tokio::test]
pub async fn test_semacaulk_insert_and_broadcast() {
    let eth_backend = setup_eth_backend().await;
    let anvil = eth_backend.0;
    let client = eth_backend.1;

    // During development, remember to update Constants.sol's SRS values if you change the table
    // size!
    let table_size = 1024;
    let mut rng = test_rng();
    let mimc7 = init_mimc7::<Fr>();

    let r = deploy_semacaulk(table_size, &mut rng, client).await;
    let semacaulk_contract = r.0;
    let mut acc = r.1;
    let srs_g1 = r.2;
    let srs_g2 = r.3;

    let zero = compute_zero_leaf::<Fr>();
    let tree = compute_lagrange_tree::<Bn254>(&acc.lagrange_comms);
    let mut identity_nullifiers = Vec::<Fr>::new();
    let mut identity_trapdoors = Vec::<Fr>::new();
    let mut identity_commitments: Vec<Fr> = vec![zero; table_size];
    let external_nullifier = Fr::from (1234u64);

    let signal = "signal";
    let signal_hash = compute_signal_hash(signal);
    let signal_hash_f = u256_to_f(signal_hash);

    //for index in 0..tree.num_leaves() {
    for index in 0..8 {
        let proof = tree.proof(index).unwrap();
        let flattened_proof = flatten_proof(&proof);

        let l_i = acc.lagrange_comms[index];
        let l_i_x = f_to_u256(l_i.x);
        let l_i_y = f_to_u256(l_i.y);

        let identity_nullifier = Fr::rand(&mut rng);
        let identity_trapdoor = Fr::rand(&mut rng);
        let new_leaf = mimc7.multi_hash(&[identity_nullifier, identity_trapdoor], Fr::zero());

        identity_nullifiers.push(identity_nullifier);
        identity_trapdoors.push(identity_trapdoor);
        //identity_commitments.push(new_leaf);
        identity_commitments[index] = new_leaf;

        // Insert the leaf on chain
        let result = semacaulk_contract
            .insert_identity(f_to_u256(new_leaf), l_i_x, l_i_y, flattened_proof)
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

    // Broadcast a signal using the identity behind leaf 1
    let pk = ProvingKey::<Bn254> { srs_g1, srs_g2: srs_g2.clone() };
    let mut rng = test_rng();

    let index = 1;
    let nullifier_hash =
        mimc7.multi_hash(&[identity_nullifiers[index], external_nullifier], Fr::zero());

    let assignment = Layouter::assign(
        identity_nullifiers[index],
        identity_trapdoors[index],
        external_nullifier,
        &mimc7.cts,
        &mut rng,
    );

    let domain = GeneralEvaluationDomain::<Fr>::new(table_size).unwrap();
    let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&identity_commitments));

    let accumulator = commit(&pk.srs_g1, &c).into_affine();
    assert_eq!(accumulator, acc.point);

    let precomputed = ProverPrecomputedData::index(&pk, &mimc7.cts, index, &c, table_size);

    let witness = WitnessInput {
        identity_nullifier: identity_nullifiers[index],
        identity_trapdoor: identity_trapdoors[index],
        identity_commitment: identity_commitments[index],
        index,
    };

    let public_input = PublicData::<Bn254> {
        accumulator: acc.point,
        external_nullifier,
        nullifier_hash,
        signal_hash: signal_hash_f,
    };

    let proof: SemacaulkProof<Bn254> = Prover::prove(
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
        acc.point,
        &public_input,
    );

    assert_eq!(is_valid, true);

    let result = semacaulk_contract
        .broadcast_signal(
            ethers::types::Bytes::from(String::from(signal).as_bytes().to_vec()),
            p_to_p(&format_proof(&proof)),
            f_to_u256(nullifier_hash),
            f_to_u256(external_nullifier),
        )
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .expect("no receipt found");

    assert_eq!(result.status.unwrap(), ethers::types::U64::from(1));
    println!(
        "Gas used by broadcastSignal(): {:?}",
        result.gas_used.unwrap()
    );

    // Attempt to double-signal
    let result = semacaulk_contract
        .broadcast_signal(
            ethers::types::Bytes::from(String::from(signal).as_bytes().to_vec()),
            p_to_p(&format_proof(&proof)),
            f_to_u256(nullifier_hash),
            f_to_u256(external_nullifier),
        )
        .send()
        .await
        .unwrap_err();

    drop(anvil);
}

fn p_to_p(p: &ProofForSemacaulk) -> Proof {
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
