use ark_bn254::{Bn254, Fq, Fr};
use ark_std::Zero;
use ark_ff::bytes::FromBytes;
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
};

#[derive(Debug)]
pub enum Error {
    InvalidSk,
    InvalidLog2Capacity,
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

        // The capacity of the accumulator expressed in log_2 (e.g. log_2(1024) = 10)
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

        /// The Semacaulk contract
        #[arg(short, long, required = true,)]
        contract: String,

        /// The identity nullifier, in hexadecimal
        #[arg(long = "id_nul", short = 'n', required = true,)]
        id_nul: String,

        /// The identity trapdoor, in hexadecimal
        #[arg(long = "id_trap", short = 't', required = true,)]
        id_trap: String,
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
        Commands::Insert { rpc, sk, contract, id_nul, id_trap } => {
            result = insert(&rpc, &sk, &contract, &id_nul, &id_trap).await;
        }
    };

    if result.is_err() {
        match result.unwrap_err() {
            Error::InvalidLog2Capacity => println!("--log2_capacity should be between 10 and 28 (inclusive)."),
            Error::InvalidSk => println!("--sk should be a valid hexadecimal value."),
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

fn parse_hex(s: &String) -> Result<String, Error> {
    //let mut bytes = Vec::with_capacity(s.len());
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

fn hex_to_fr(hex: &String) -> Result<Fr, Error> {
    let hex = parse_hex(&hex)?;

    let bytes_vec = hex::decode(hex).unwrap();
    let bytes_slice: &[u8] = bytes_vec.as_slice();
    Ok(Fr::read(bytes_slice).unwrap())
}

async fn insert(
    rpc: &String,
    sk: &String,
    contract: &String,
    id_nul: &String,
    id_trap: &String,
) -> Result<(), Error> {
    let id_nul = hex_to_fr(id_nul)?;
    let id_trap = hex_to_fr(id_trap)?;

    let client = create_client(rpc, &parse_hex(&sk)?).await?;

    let mut c: String = contract.clone();
    if contract.starts_with("0x") {
        c = contract.chars().skip(2).collect::<String>();
    }
    let address = hex::decode(c).unwrap();
    let a = ethers::types::H160::from_slice(address.as_slice());
    let semacaulk_contract = SemacaulkContract::new(a, client);

    let index: usize = semacaulk_contract.get_current_index().call().await.unwrap().as_u64() as usize;

    let mimc7 = init_mimc7::<Fr>();
    let new_leaf = mimc7.multi_hash(&[id_nul, id_trap], Fr::zero());

    // Compute Lagrange commitment
    /*
    // Insert the leaf on chain
    let result = semacaulk_contract
        .insert_identity(f_to_u256(new_leaf), l_i_x, l_i_y, flattened_proof)
        .send()
        .await
        .unwrap()
        .await
        .unwrap()
        .expect("no receipt found");

    */
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
    let client = create_client(rpc, &parse_hex(&sk)?).await?;

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
