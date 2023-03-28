use ark_bn254::{Bn254, Fq, Fr};
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read};
use ark_std::{test_rng, Zero};
use clap::{arg, command, Parser, Subcommand};
use clap_num::number_range;
use ethers::contract::abigen;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::Wallet;
use ethers::providers::{Http, Middleware, Provider, StreamExt};
use ethers::signers::{LocalWallet, Signer};
use semacaulk::prover::prover::{Prover, WitnessInput};
use semacaulk::{
    accumulator::{compute_lagrange_tree, compute_zero_leaf, Accumulator},
    bn_solidity_utils::{f_to_u256, u256_to_f, f_to_hex},
    contracts::compute_signal_hash,
    keccak_tree::flatten_proof,
    layouter::Layouter,
    mimc7::init_mimc7,
    prover::{Proof as SemacaulkProof, ProverPrecomputedData, PublicData},
    setup::{g2_str_to_g2, setup},
    verifier::Verifier as SemacaulkVerifier,
};
use std::convert::TryFrom;
use std::process;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;

/*
RPC: https://rpc2.sepolia.org
Address: 0xaaaa553ECd8C7cFBcA9396A5746956ef738BeEd4
Private key: cf3a4fe3eaa7533fd3a5b19f874a0ff67749a926b80d4074 cc3b1c634b536c47 (remove the space)
*/

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidSk,
    InvalidLog2Capacity,
    InvalidIdNulOrTrap,
}

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "client")]
#[command(about = "A Semacaulk client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn log_2_capacity_range(s: &str) -> Result<u8, String> {
    number_range(s, 10, 28)
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Deploy a Semacaulk contract
    Deploy {
        /// The Ethereum node URL
        #[arg(short, long, required = false, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// The deployer's Etheruem private key
        #[arg(
            short,
            long,
            required = false,
            default_value = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        )]
        sk: String,

        /// The powers of tau (PTAU) file containing a phase 1 trusted setup output
        #[arg(short, long, required = true)]
        ptau: String,

        /// The capacity of the accumulator expressed in log_2 (e.g. log_2(1024) = 10)
        #[arg(short, long, required = false, default_value = "10", value_parser=log_2_capacity_range)]
        log_2_capacity: u8,
    },
    /// Insert an identity into an existing Semacaulk contract
    Insert {
        /// The Ethereum node URL
        #[arg(short, long, required = false, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// The deployer's Etheruem private key
        #[arg(
            short,
            long,
            required = false,
            default_value = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        )]
        sk: String,

        /// The powers of tau (PTAU) file containing a phase 1 trusted setup output
        #[arg(short, long, required = true)]
        ptau: String,

        /// The Semacaulk contract
        #[arg(short, long, required = true)]
        contract: String,

        /// The identity nullifier, in hexadecimal
        #[arg(long = "id_nul", short = 'n', required = true)]
        id_nul: String,

        /// The identity trapdoor, in hexadecimal
        #[arg(long = "id_trap", short = 't', required = true)]
        id_trap: String,

        /// The capacity of the accumulator expressed in log_2 (e.g. log_2(1024) = 10)
        #[arg(short, long, required = false, default_value = "10", value_parser=log_2_capacity_range)]
        log_2_capacity: u8,
    },
    /// Insert an identity into an existing Semacaulk contract
    Prove {
        /// The Ethereum node URL
        #[arg(short, long, required = false, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// The powers of tau (PTAU) file containing a phase 1 trusted setup output
        #[arg(short, long, required = true)]
        ptau: String,

        /// The Semacaulk contract
        #[arg(short, long, required = true)]
        contract: String,

        /// The index of the value in the accumulator
        #[arg(short, long, required = false)]
        index: usize,

        /// The external_nullifier nullifier, in hexadecimal
        #[arg(long = "ext_nul", short = 'e', required = true)]
        ext_nul: String,

        /// The identity nullifier, in hexadecimal
        #[arg(long = "id_nul", short = 'n', required = true)]
        id_nul: String,

        /// The identity trapdoor, in hexadecimal
        #[arg(long = "id_trap", short = 't', required = true)]
        id_trap: String,

        /// The identity trapdoor, in hexadecimal
        #[arg(long = "signal", short, required = true)]
        signal: String,

        /// The capacity of the accumulator expressed in log_2 (e.g. log_2(1024) = 10)
        #[arg(short, long, required = false, default_value = "10", value_parser=log_2_capacity_range)]
        log_2_capacity: u8,

        /// If specified, use this semacaulk_precompute endpoint to privately retrieve precomputed data
        #[arg(short, long, required = false)]
        semacaulk_precompute_endpoint: Option<String>,
    },
    BroadcastSignal {
        /// The Ethereum node URL
        #[arg(short, long, required = false, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// The deployer's Etheruem private key
        #[arg(
            short,
            long,
            required = false,
            default_value = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        )]
        sk: String,

        /// The Semacaulk contract
        #[arg(short, long, required = true)]
        contract: String,

        /// The identity trapdoor, in hexadecimal
        #[arg(long = "signal", short, required = true)]
        signal: String,

        /// The nullifier hash, in hexadecimal
        #[arg(long = "nul_hash", short = 'h', required = true)]
        nul_hash: String,

        /// The external_nullifier nullifier, in hexadecimal
        #[arg(long = "ext_nul", short = 'e', required = true)]
        ext_nul: String,

        /// The serialised proof
        #[arg(long = "proof", short, required = true)]
        proof: String,
    },
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let result = match args.command {
        Commands::Deploy {
            rpc,
            sk,
            ptau,
            log_2_capacity,
        } => deploy(&rpc, &sk, &ptau, log_2_capacity).await,
        Commands::Insert {
            rpc,
            sk,
            ptau,
            contract,
            id_nul,
            id_trap,
            log_2_capacity,
        } => {
            insert(
                &rpc,
                &sk,
                &ptau,
                &contract,
                &id_nul,
                &id_trap,
                log_2_capacity,
            )
            .await
        }
        Commands::Prove {
            rpc,
            ptau,
            contract,
            index,
            ext_nul,
            id_nul,
            id_trap,
            signal,
            semacaulk_precompute_endpoint,
            log_2_capacity,
        } => {
            prove(
                &rpc,
                &ptau,
                &contract,
                index,
                &ext_nul,
                &id_nul,
                &id_trap,
                &signal,
                semacaulk_precompute_endpoint,
                log_2_capacity,
            )
            .await
        }
        Commands::BroadcastSignal {
            rpc,
            sk,
            contract,
            signal,
            nul_hash,
            ext_nul,
            proof,
        } => broadcast_signal(&rpc, &sk, &contract, &signal, &nul_hash, &ext_nul, &proof).await,
    };

    if result.is_err() {
        #[allow(clippy::unnecessary_unwrap)]
        match result.unwrap_err() {
            Error::InvalidLog2Capacity => {
                println!("--log2_capacity should be between 10 and 28 (inclusive).")
            }
            Error::InvalidSk => println!("--sk should be a valid hexadecimal value."),
            Error::InvalidIdNulOrTrap => println!("-n or -t should be a valid hexadecimal value."),
        };
        process::exit(1);
    }
}

abigen!(SemacaulkContract, "./src/contracts/Semacaulk.json");

type SemacaulkContract = semacaulk_contract::SemacaulkContract<
    SignerMiddleware<
        ethers::providers::Provider<Http>,
        ethers::signers::Wallet<ethers::core::k256::ecdsa::SigningKey>,
    >,
>;

fn parse_sk(s: &str) -> Result<String, Error> {
    let mut bytes = s.as_bytes();

    if s.starts_with("0x") {
        bytes = &bytes[2..];
    }

    let s = String::from_utf8(bytes.to_vec()).unwrap();

    let hex = hex::decode(&s);
    if hex.is_err() {
        return Err(Error::InvalidSk);
    }
    Ok(s)
}

fn get_provider(rpc: &str) -> Provider<Http> {
    Provider::<Http>::try_from(rpc)
        .unwrap()
        .interval(Duration::from_millis(10u64))
}

fn create_wallet(sk: &str) -> Result<LocalWallet, Error> {
    let wallet = sk.parse::<LocalWallet>();
    if wallet.is_err() {
        return Err(Error::InvalidSk);
    }
    Ok(wallet.unwrap())
}

pub type EthersClient = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

async fn create_client(rpc: &str, sk: &str) -> Result<EthersClient, Error> {
    let provider = get_provider(rpc);
    let wallet = create_wallet(sk)?;
    let chain_id: u64 = provider.get_chainid().await.unwrap().try_into().unwrap();
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.with_chain_id(chain_id),
    ));
    Ok(client)
}

fn parse_id_nul_or_trap<F: PrimeField>(s: &str) -> Result<F, Error> {
    let mut bytes = s.as_bytes();
    if s.starts_with("0x") {
        if s.len() > 66 {
            return Err(Error::InvalidIdNulOrTrap);
        }

        bytes = &bytes[2..];
    } else if s.len() > 64 {
        return Err(Error::InvalidIdNulOrTrap);
    }

    let hex_str = std::str::from_utf8(bytes);
    if hex_str.is_err() {
        return Err(Error::InvalidIdNulOrTrap);
    }
    let hex_str = hex_str.unwrap();
    let mut h = hex_str.to_string();
    while h.len() < 64 {
        h = format!("0{}", &h);
    }
    let hex_str = h;
    let hex_buf = hex::decode(hex_str).unwrap();
    let hex_buf: Vec<u8> = hex_buf.iter().copied().rev().collect();

    Ok(F::read(hex_buf.as_slice()).unwrap())
}

use semacaulk::contracts::format::proof_for_semacaulk::{format_proof, ProofForSemacaulk};
async fn broadcast_signal(
    rpc: &str,
    sk: &str,
    contract: &str,
    signal: &str,
    nul_hash: &str,
    ext_nul: &str,
    proof: &str,
) -> Result<(), Error> {
    let ext_nul = parse_id_nul_or_trap::<Fr>(ext_nul)?;
    let nul_hash = parse_id_nul_or_trap::<Fr>(nul_hash)?;

    let client = create_client(rpc, &parse_sk(sk)?).await?;

    let a = str_to_ethers_address(contract);
    let semacaulk_contract = SemacaulkContract::new(a, client);
    let proof =
        SemacaulkProof::<Bn254>::deserialize(hex::decode(proof).unwrap().as_slice()).unwrap();

    let result = semacaulk_contract
        .broadcast_signal(
            ethers::types::Bytes::from(String::from(signal).as_bytes().to_vec()),
            p_to_p(&format_proof(&proof)),
            f_to_u256(nul_hash),
            f_to_u256(ext_nul),
        )
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .expect("no receipt found");

    let tx_hash = result.transaction_hash;
    println!("Transaction hash:\n{:?}", tx_hash);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn prove(
    rpc: &str,
    ptau: &str,
    contract: &str,
    index: usize,
    ext_nul: &str,
    id_nul: &str,
    id_trap: &str,
    signal: &str,
    semacaulk_precompute_endpoint: Option<String>,
    log_2_capacity: u8,
) -> Result<(), Error> {
    let ext_nul = parse_id_nul_or_trap::<Fr>(ext_nul)?;
    let id_nul = parse_id_nul_or_trap::<Fr>(id_nul)?;
    let id_trap = parse_id_nul_or_trap::<Fr>(id_trap)?;

    let table_size = 2u64.pow(log_2_capacity as u32) as usize;
    let (pk, lagrange_comms) = setup(log_2_capacity as usize, ptau);

    let zero = compute_zero_leaf::<Fr>();
    let mut acc = Accumulator::<Bn254>::new(zero, &lagrange_comms);

    // Use a dummy secret key; we shouldn't be signing any txes anywaya
    let sk = "0000000000000000000000000000000000000000000000000000000000000001";
    let client = create_client(rpc, &parse_sk(sk)?).await?;
    let c = remove_address_prefix(String::from(contract));
    let address = hex::decode(c).unwrap();
    let a = ethers::types::H160::from_slice(address.as_slice());
    let semacaulk_contract = SemacaulkContract::new(a, client);
    let events = semacaulk_contract
        .event::<InsertIdentityFilter>()
        .from_block(0);
    let num_leaves = semacaulk_contract.get_current_index().call().await.unwrap();
    let mut stream = events.stream().await.unwrap().take(num_leaves.as_usize());

    let mut identity_commitments: Vec<Fr> = vec![zero; table_size];
    let mut i = 0;
    while let Some(Ok(f)) = stream.next().await {
        let id_comm = u256_to_f(f.identity_commitment);
        identity_commitments[i] = id_comm;
        acc.update(i, id_comm);
        i += 1;
    }

    let mimc7 = init_mimc7::<Fr>();

    let leaf = mimc7.multi_hash(&[id_nul, id_trap], Fr::zero());
    assert_eq!(identity_commitments[index], leaf);

    let acc_on_chain = semacaulk_contract.get_accumulator().call().await.unwrap();
    assert_eq!(u256_to_f::<Fq>(acc_on_chain.x), acc.point.x);
    assert_eq!(u256_to_f::<Fq>(acc_on_chain.y), acc.point.y);

    let nullifier_hash = mimc7.multi_hash(&[id_nul, ext_nul], Fr::zero());

    let mut rng = test_rng();

    let assignment = Layouter::assign(id_nul, id_trap, ext_nul, &mimc7.cts, &mut rng);

    let domain = GeneralEvaluationDomain::<Fr>::new(table_size).unwrap();
    let c = DensePolynomial::from_coefficients_slice(&domain.ifft(&identity_commitments));

    let mut precomputed = ProverPrecomputedData::precompute_fixed(&mimc7.cts);
    precomputed.precompute_w2(&pk, &[index], table_size);

    if semacaulk_precompute_endpoint.is_some() {
        let mut endpoint = semacaulk_precompute_endpoint.unwrap();
        while endpoint.ends_with('/') {
            endpoint.pop();
        }

        // Fetch precomputed data
        println!("Fetching precomputed data from the Blyss proxy at {endpoint}...");
        let url = format!("{endpoint}/{index}");
        let mut res = reqwest::blocking::get(url).unwrap();
        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();
        let w1 = g2_str_to_g2(&body);

        precomputed.update_w1(index, w1);
    } else {
        precomputed.precompute_w1(&pk, &[index], &c, table_size);
    }

    let witness = WitnessInput {
        identity_nullifier: id_nul,
        identity_trapdoor: id_trap,
        identity_commitment: identity_commitments[index],
        index,
    };

    let signal_hash = compute_signal_hash(signal);
    let signal_hash_f: Fr = u256_to_f(signal_hash);

    let public_input = PublicData::<Bn254> {
        accumulator: acc.point,
        external_nullifier: ext_nul,
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
        pk.srs_g1[table_size],
        pk.srs_g2[1],
        acc.point,
        &public_input,
    );

    assert!(is_valid);
    // Serialise and print proof
    let mut serialised_proof = vec![];
    let _ = proof.serialize(&mut serialised_proof);
    let proof_hex = hex::encode(serialised_proof.as_slice());
    println!("Nullifier hash:\n{}", f_to_hex(nullifier_hash));
    println!("Serialised proof:\n{}", proof_hex);
    Ok(())
}

pub fn remove_address_prefix(addr: String) -> String {
    if addr.starts_with("0x") {
        return addr.chars().skip(2).collect::<String>();
    }
    addr
}

pub fn str_to_ethers_address(addr: &str) -> ethers::types::H160 {
    let c = remove_address_prefix(String::from(addr));
    let address = hex::decode(c).unwrap();
    let a = ethers::types::H160::from_slice(address.as_slice());
    a
}

async fn insert(
    rpc: &str,
    sk: &str,
    ptau: &str,
    contract: &str,
    id_nul: &str,
    id_trap: &str,
    log_2_capacity: u8,
) -> Result<(), Error> {
    let id_nul = parse_id_nul_or_trap::<Fr>(id_nul)?;
    let id_trap = parse_id_nul_or_trap::<Fr>(id_trap)?;

    let (_pk, lagrange_comms) = setup(log_2_capacity as usize, ptau);

    let client = create_client(rpc, &parse_sk(sk)?).await?;

    let a = str_to_ethers_address(contract);
    let semacaulk_contract = SemacaulkContract::new(a, client);

    // Get the index to insert to
    let index: usize = semacaulk_contract
        .get_current_index()
        .call()
        .await
        .unwrap()
        .as_u64() as usize;

    let mimc7 = init_mimc7::<Fr>();
    let new_leaf = mimc7.multi_hash(&[id_nul, id_trap], Fr::zero());

    // Construct the tree of commitments to the Lagrange bases
    let tree = compute_lagrange_tree::<Bn254>(&lagrange_comms);

    let proof = tree.proof(index).unwrap();
    let flattened_proof = flatten_proof(&proof);
    let l_i = lagrange_comms[index];
    let l_i_x = f_to_u256(l_i.x);
    let l_i_y = f_to_u256(l_i.y);

    // Insert the leaf on chain
    let result = semacaulk_contract
        .insert_identity(f_to_u256(new_leaf), l_i_x, l_i_y, flattened_proof)
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .expect("no receipt found");

    let tx_hash = result.transaction_hash;
    let event_index = result.logs[0].topics[1];
    println!("Transaction hash:\n{:?}", tx_hash);
    println!("Identity index:\n{:?}", event_index);

    Ok(())
}

async fn deploy(rpc: &str, sk: &str, ptau: &str, log_2_capacity: u8) -> Result<(), Error> {
    if !(10..=28).contains(&log_2_capacity) {
        return Err(Error::InvalidLog2Capacity);
    }
    let client = create_client(rpc, &parse_sk(sk)?).await?;

    let (_pk, lagrange_comms) = setup(log_2_capacity as usize, ptau);

    let zero = compute_zero_leaf::<Fr>();
    let acc = Accumulator::<Bn254>::new(zero, &lagrange_comms);
    let empty_accumulator_x = f_to_u256::<Fq>(acc.point.x);
    let empty_accumulator_y = f_to_u256::<Fq>(acc.point.y);
    let tree = compute_lagrange_tree::<Bn254>(&lagrange_comms);
    let root = tree.root();

    // Deploy contract
    let semacaulk_contract =
        SemacaulkContract::deploy(client, (root, empty_accumulator_x, empty_accumulator_y))
            .unwrap()
            .send()
            .await
            .unwrap();
    println!("{:?}", semacaulk_contract.address());

    Ok(())
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
        mimc_cts: p.openings.mimc_cts,
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
        w_1: G1Point {
            x: p.commitments.w_1.x,
            y: p.commitments.w_1.y,
        },
        w_2: G1Point {
            x: p.commitments.w_2.x,
            y: p.commitments.w_2.y,
        },
        key: G1Point {
            x: p.commitments.key.x,
            y: p.commitments.key.y,
        },
        mimc_cts: G1Point {
            x: p.commitments.mimc_cts.x,
            y: p.commitments.mimc_cts.y,
        },
        quotient: G1Point {
            x: p.commitments.quotient.x,
            y: p.commitments.quotient.y,
        },
        u_prime: G1Point {
            x: p.commitments.u_prime.x,
            y: p.commitments.u_prime.y,
        },
        zi: G1Point {
            x: p.commitments.zi.x,
            y: p.commitments.zi.y,
        },
        ci: G1Point {
            x: p.commitments.ci.x,
            y: p.commitments.ci.y,
        },
        p_1: G1Point {
            x: p.commitments.p_1.x,
            y: p.commitments.p_1.y,
        },
        p_2: G1Point {
            x: p.commitments.p_2.x,
            y: p.commitments.p_2.y,
        },
        q_mimc: G1Point {
            x: p.commitments.q_mimc.x,
            y: p.commitments.q_mimc.y,
        },
        h: G1Point {
            x: p.commitments.h.x,
            y: p.commitments.h.y,
        },
        w: G2Point {
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

#[test]
pub fn test_parse_id_nul_or_trap() {
    let s = String::from("0x1");
    assert_eq!(parse_id_nul_or_trap::<Fr>(&s).unwrap(), Fr::from(1));

    let s = String::from("0x01");
    assert_eq!(parse_id_nul_or_trap::<Fr>(&s).unwrap(), Fr::from(1));

    let s = String::from("0x0000000000000000000000000000000000000000000000000000000000000001");
    assert_eq!(parse_id_nul_or_trap::<Fr>(&s).unwrap(), Fr::from(1));

    let s = String::from("0x0101");
    assert_eq!(parse_id_nul_or_trap::<Fr>(&s).unwrap(), Fr::from(257));

    let s = String::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        parse_id_nul_or_trap::<Fr>(&s).unwrap_err(),
        Error::InvalidIdNulOrTrap
    );
}
