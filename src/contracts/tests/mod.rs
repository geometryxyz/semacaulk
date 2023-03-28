use ethers::core::k256::ecdsa::SigningKey;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::Signer;
use ethers::utils::AnvilInstance;
use ethers::{
    prelude::{LocalWallet, Wallet},
    utils::Anvil,
};
use std::{convert::TryFrom, sync::Arc, time::Duration};

#[cfg(test)]
pub mod semacaulk;

#[cfg(test)]
mod keccak_mt;

#[cfg(test)]
mod crypto;

#[cfg(test)]
mod verifier;

#[cfg(test)]
mod transcript;

pub type EthersClient = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

pub async fn setup_eth_backend() -> (AnvilInstance, EthersClient) {
    // Launch anvil
    let anvil = Anvil::new().spawn();

    // Instantiate the wallet
    let wallet: LocalWallet = anvil.keys()[0].clone().into();

    // Connect to the network
    let provider = Provider::<Http>::try_from(anvil.endpoint())
        .unwrap()
        .interval(Duration::from_millis(10u64));

    // Instantiate the client with the wallet
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.with_chain_id(anvil.chain_id()),
    ));

    (anvil, client)
}
