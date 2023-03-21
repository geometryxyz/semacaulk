use ark_bn254::{Bn254, Fq, Fr};
use ark_std::Zero;
use ark_ff::PrimeField;
use clap::{arg, command, Parser, Subcommand};
use clap_num::number_range;
use std::string::String;
use ethers::signers::{LocalWallet, Signer};
use ethers::core::k256::ecdsa::SigningKey;
use ethers::prelude::Wallet;
use ethers::providers::{Http, Provider, Middleware};
use ethers::contract::abigen;
use ethers::middleware::SignerMiddleware;
use std::sync::Arc;
use std::time::Duration;
use std::process;
use std::convert::TryFrom;
use semacaulk::setup::setup;
use semacaulk::mimc7::init_mimc7;
use semacaulk::accumulator::{compute_lagrange_tree, compute_zero_leaf, Accumulator};
use semacaulk::{
    bn_solidity_utils::{f_to_u256},
    keccak_tree::flatten_proof,
};

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
        #[arg(short, long, required = false, default_value = "http://127.0.0.1:8545",)]
        rpc: String,

        /// The deployer's Etheruem private key 
        #[arg(short, long, required = false, default_value = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",)]
        sk: String,

        /// The powers of tau (PTAU) file containing a phase 1 trusted setup output
        #[arg(short, long, required = true,)]
        ptau: String,

        /// The capacity of the accumulator expressed in log_2 (e.g. log_2(1024) = 10)
        #[arg(short, long, required = false, default_value = "10", value_parser=log_2_capacity_range)]
        log_2_capacity: u8,
    },
    /// Insert an identity into an existing Semacaulk contract
    Insert{
        /// The Ethereum node URL
        #[arg(short, long, required = false, default_value = "http://127.0.0.1:8545",)]
        rpc: String,

        /// The deployer's Etheruem private key 
        #[arg(short, long, required = false, default_value = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",)]
        sk: String,

        /// The powers of tau (PTAU) file containing a phase 1 trusted setup output
        #[arg(short, long, required = true,)]
        ptau: String,

        /// The Semacaulk contract
        #[arg(short, long, required = true,)]
        contract: String,

        /// The identity nullifier, in hexadecimal
        #[arg(long = "id_nul", short = 'n', required = true,)]
        id_nul: String,

        /// The identity trapdoor, in hexadecimal
        #[arg(long = "id_trap", short = 't', required = true,)]
        id_trap: String,

        /// The capacity of the accumulator expressed in log_2 (e.g. log_2(1024) = 10)
        #[arg(short, long, required = false, default_value = "10", value_parser=log_2_capacity_range)]
        log_2_capacity: u8,
    }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let result;
    match args.command {
        Commands::Deploy { rpc, sk, ptau, log_2_capacity } => {
            result = deploy(&rpc, &sk, &ptau, log_2_capacity).await;
        },
        Commands::Insert { rpc, sk, ptau, contract, id_nul, id_trap, log_2_capacity } => {
            result = insert(&rpc, &sk, &ptau, &contract, &id_nul, &id_trap, log_2_capacity).await;
        }
    };

    if result.is_err() {
        match result.unwrap_err() {
            Error::InvalidLog2Capacity => println!("--log2_capacity should be between 10 and 28 (inclusive)."),
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

fn parse_sk(s: &String) -> Result<String, Error> {
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

fn get_provider(rpc: &String) -> Provider<Http> {
    Provider::<Http>::try_from(rpc)
        .unwrap()
        .interval(Duration::from_millis(10u64))
}

fn create_wallet(sk: &String) -> Result<LocalWallet, Error> {
    let wallet = sk.parse::<LocalWallet>();
    if wallet.is_err() {
        return Err(Error::InvalidSk);
    }
    Ok(wallet.unwrap())
}

pub type EthersClient = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

async fn create_client(rpc: &String, sk: &String) -> Result<EthersClient, Error> {
    let provider = get_provider(rpc);
    let wallet = create_wallet(sk)?;
    let chain_id: u64 = provider.get_chainid().await.unwrap().try_into().unwrap();
    let client = Arc::new(SignerMiddleware::new(provider, wallet.with_chain_id(chain_id)));
    Ok(client)
}

fn parse_id_nul_or_trap<F: PrimeField>(s: &String) -> Result<F, Error> {
    let mut bytes = s.as_bytes();
    if s.starts_with("0x") {
        if s.len() > 66 {
            return Err(Error::InvalidIdNulOrTrap);
        }

        bytes = &bytes[2..];
    } else {
        if s.len() > 64 {
            return Err(Error::InvalidIdNulOrTrap);
        }
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

async fn insert(
    rpc: &String,
    sk: &String,
    ptau: &String,
    contract: &String,
    id_nul: &String,
    id_trap: &String,
    log_2_capacity: u8,
) -> Result<(), Error> {
    let id_nul = parse_id_nul_or_trap::<Fr>(id_nul)?;
    let id_trap = parse_id_nul_or_trap::<Fr>(id_trap)?;

    let (_pk, lagrange_comms) = setup(log_2_capacity as usize, ptau);

    let client = create_client(rpc, &parse_sk(&sk)?).await?;

    let mut c: String = contract.clone();
    if contract.starts_with("0x") {
        c = contract.chars().skip(2).collect::<String>();
    }
    let address = hex::decode(c).unwrap();
    let a = ethers::types::H160::from_slice(address.as_slice());
    let semacaulk_contract = SemacaulkContract::new(a, client);

    // Get the index to insert to
    let index: usize = semacaulk_contract.get_current_index().call().await.unwrap().as_u64() as usize;

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

async fn deploy(
    rpc: &String,
    sk: &String,
    ptau: &String,
    log_2_capacity: u8,
) -> Result<(), Error> {
    if log_2_capacity < 10 || log_2_capacity > 28 {
        return Err(Error::InvalidLog2Capacity);
    }
    let client = create_client(rpc, &parse_sk(&sk)?).await?;

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
    assert_eq!(parse_id_nul_or_trap::<Fr>(&s).unwrap_err(), Error::InvalidIdNulOrTrap);
}
