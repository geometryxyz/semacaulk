/*
    Implementation of transcript with keccak256 that is compatible with Transcript.sol
*/

use crate::bn_solidity_utils::f_to_u256;
use ark_bn254::{Fr, G1Affine};
use ark_ff::{BigInteger, PrimeField};
use ethers::types::U256;
use tiny_keccak::{Hasher, Keccak};

pub struct Transcript {
    data: Vec<u8>,
}

impl Transcript {
    pub fn new_transcript() -> Self {
        let initial_challenge = Self::compute_initial_challenge();
        Self {
            data: initial_challenge.to_vec(),
        }
    }

    fn compute_initial_challenge() -> [u8; 32] {
        [0u8; 32]
    }

    pub fn update_with_u256(&mut self, x: Fr) {
        let mut x_bytes = x.into_repr().to_bytes_be();
        self.data.append(&mut x_bytes);
    }

    pub fn update_with_g1(&mut self, pt: G1Affine) {
        let mut x_bytes = pt.x.into_repr().to_bytes_be();
        let mut y_bytes = pt.y.into_repr().to_bytes_be();

        self.data.append(&mut x_bytes);
        self.data.append(&mut y_bytes);
    }

    pub fn get_challenge(&mut self) -> U256 {
        let mut buff = vec![0u8; 32];
        let mut hasher = Keccak::v256();

        hasher.update(&self.data);
        hasher.finalize(&mut buff);

        let challenge = Fr::from_be_bytes_mod_order(&buff);

        self.data.clear();
        self.data.append(&mut buff);

        f_to_u256(challenge)
    }
}

#[cfg(test)]
mod test_transcript {
    use ark_bn254::{Fr, G1Affine};
    use ark_ec::AffineCurve;
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn test_fr_bytes_len() {
        let x = Fr::from(1231);
        let x_bytes = x.into_repr().to_bytes_be();
        assert_eq!(x_bytes.len(), 32);
    }

    #[test]
    fn test_fq_bytes_len() {
        let pt = G1Affine::prime_subgroup_generator();
        let x_bytes = pt.x.into_repr().to_bytes_be();
        let y_bytes = pt.y.into_repr().to_bytes_be();

        assert_eq!(x_bytes.len(), 32);
        assert_eq!(y_bytes.len(), 32);

    }
}
