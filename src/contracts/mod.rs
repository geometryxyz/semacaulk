pub mod tests;
pub mod format;

use std::ops::Shr;
use ethers::core::utils::keccak256;
use ethers::types::U256;

pub fn compute_signal_hash(signal: &str) -> U256 {
    let signal_bytes = signal.as_bytes();
    let signal_hash_bytes = keccak256(signal_bytes);
    U256::from(signal_hash_bytes).shr(8)
}
