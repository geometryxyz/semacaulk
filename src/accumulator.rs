use crate::keccak_tree::KeccakTree;
use crate::kzg::commit;
use crate::utils::construct_lagrange_basis;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, ToBytes};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ethers::core::utils::keccak256;
use ethers::types::U256;
use serde::{Deserialize, Serialize};
use std::ops::Add;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Accumulator<E: PairingEngine> {
    pub zero: E::Fr,
    pub lagrange_comms: Vec<E::G1Affine>,
    pub point: E::G1Affine,
}

pub fn compute_empty_accumulator<E: PairingEngine>(
    zero: E::Fr,
    lagrange_comms: &Vec<E::G1Affine>,
) -> E::G1Affine {
    let mut c = lagrange_comms[0].mul(zero).into_affine();
    for i in 1..lagrange_comms.len() {
        let l_i = lagrange_comms[i];
        c = c.add(l_i.mul(zero).into_affine());
    }

    c
}

impl<E: PairingEngine> Accumulator<E> {
    pub fn new(zero: E::Fr, lagrange_comms: &Vec<E::G1Affine>) -> Self {
        let point = compute_empty_accumulator::<E>(zero, &lagrange_comms);

        Self {
            lagrange_comms: lagrange_comms.clone(),
            point,
            zero,
        }
    }

    pub fn update(&mut self, index: usize, value: E::Fr) {
        assert_eq!(index < self.lagrange_comms.len(), true);

        // C - (v - zero) * li_comm
        let v_minus_zero = value - self.zero;
        let v_minus_zero_mul_li_comm = self.lagrange_comms[index].mul(v_minus_zero);
        let p = self.point + v_minus_zero_mul_li_comm.into_affine();
        self.point = p.clone()
    }
}

// Convert an F value to U256 for use with ethers-rs
pub fn f_modulus_as_u256<F: PrimeField>() -> U256 {
    let m = F::zero() - F::one();

    let mut p_bytes = Vec::with_capacity(32);
    let _ = m.write(&mut p_bytes);
    p_bytes[0] += 1;

    let r = U256::from_little_endian(p_bytes.as_slice());
    r
}

// Compute the keccak256 hash of "Semacaulk" using ethers-rs, and return the result mod F.
pub fn compute_zero_leaf<F: PrimeField>() -> F {
    let preimage = "Semacaulk".as_bytes();
    let hash_bytes = keccak256(preimage);

    // the hash of "Semacaulk" % field order
    let hash = U256::from_big_endian(hash_bytes.as_slice())
        .div_mod(f_modulus_as_u256::<F>())
        .1;

    let mut z = [0u8; 32];
    hash.to_big_endian(&mut z);

    let zero_bigint = F::from_be_bytes_mod_order(&z);

    zero_bigint
}

// In production, this would be taken from an existing trusted setup, so srs_g1 is an argument
// to this function
pub fn commit_to_lagrange_bases<E: PairingEngine>(
    domain_size: usize,
    srs_g1: &Vec<E::G1Affine>,
) -> Vec<E::G1Affine> {
    let domain = GeneralEvaluationDomain::<E::Fr>::new(domain_size).unwrap();
    let elems: Vec<E::Fr> = domain.elements().collect();
    let bases = construct_lagrange_basis(&elems);

    let comm_lagrnage_bases: Vec<_> = bases
        .iter()
        .map(|base| commit(&srs_g1, base).into_affine())
        .collect();

    comm_lagrnage_bases
}

// Hash the X and Y values of a vector of Lagrange commitments, and insert them into a tree.
pub fn compute_lagrange_tree<E: PairingEngine>(lagrange_comms: &Vec<E::G1Affine>) -> KeccakTree {
    let mut pow = 1u32;
    let target = lagrange_comms.len() as u64;
    while 2u64.pow(pow) < target {
        pow += 1;
    }
    pow += 1;

    let mut tree = KeccakTree::new(pow as usize, [0; 32]);

    assert_eq!(tree.num_leaves(), lagrange_comms.len());

    for (i, p) in lagrange_comms.iter().enumerate() {
        let mut b = Vec::with_capacity(65);
        let _ = p.write(&mut b);

        // Slice to the first 64 bytes, since the 65th byte indicates whether the point is the
        // point at infinity and we don't need it
        let b = &b.get(0..64).unwrap();

        let mut preimage = Vec::with_capacity(64);
        for i in 0..32 {
            preimage.push(b[31 - i]);
        }
        for i in 0..32 {
            preimage.push(b[63 - i]);
        }

        let leaf = keccak256(preimage);

        tree.set(i, leaf);
    }

    tree
}

#[cfg(test)]
mod tests {
    use super::{
        commit_to_lagrange_bases, compute_empty_accumulator, compute_zero_leaf, Accumulator,
    };
    use crate::kzg::unsafe_setup_g1;
    use ark_bn254::{Bn254, Fr};
    use ark_ff::ToBytes;
    use ark_std::{rand::rngs::StdRng, test_rng};

    #[test]
    pub fn test_compute_zero_leaf() {
        let zero = compute_zero_leaf::<Fr>();
        let mut z = Vec::with_capacity(32);
        let _ = zero.write(&mut z);

        /*
            To reproduce this value, run the following in a JS console:
            e = require('ethers')
            (
                BigInt(e.utils.solidityKeccak256(['string'], ['Semacaulk'])) %
                    BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
            ).toString(16)
        */

        assert_eq!(
            hex::encode(z),
            "251a679ce76f71008e8f811649361985e499a17da6411eef0ba206cd72b3771f"
        );
    }

    #[test]
    fn test_accumulator() {
        let domain_size = 8;
        let mut rng = test_rng();

        let srs_g1 = unsafe_setup_g1::<Bn254, StdRng>(domain_size, &mut rng);
        let zero = compute_zero_leaf::<Fr>();
        let lagrange_comms = commit_to_lagrange_bases::<Bn254>(domain_size, &srs_g1);

        let mut acc = Accumulator::<Bn254>::new(zero, &lagrange_comms);

        let point = compute_empty_accumulator::<Bn254>(zero, &lagrange_comms);
        assert_eq!(acc.point, point);

        acc.update(0, Fr::from(123));
    }
}
