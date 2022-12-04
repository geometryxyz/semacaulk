pub mod contracts;
pub mod caulk_plus;
pub mod error;
pub mod gates;
pub mod rng;
pub mod utils;
pub mod kzg;
pub mod keccak_tree;

use crate::utils::construct_lagrange_basis;
use crate::kzg::{unsafe_setup_g1, commit};
use crate::keccak_tree::KeccakTree;
use std::ops::Add;
use ark_ff::FpParameters;
use ark_ff::BigInteger;
use ark_ff::bytes::ToBytes;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_bn254::{Bn254, Fr, FrParameters};
use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
use ark_std::{rand::rngs::StdRng, test_rng};
use ethers::core::utils::keccak256;
use ethers::types::U256;

use ark_ff::PrimeField;

pub fn compute_zero_leaf<F: PrimeField>() -> [u8; 32] {
    let preimage = "Semacaulk".as_bytes();
    let hash_bytes = keccak256(preimage);
    let hash = U256::from_big_endian(hash_bytes.as_slice()).div_mod(fr_modulus_as_u256()).1;

    let mut result = [0u8; 32];
    hash.to_big_endian(&mut result);

    result
}

pub fn fr_modulus_as_u256() -> U256 {
    // TODO: check if it should be FrParameters or FqParameters
    let p_bytes = FrParameters::MODULUS.to_bytes_be();

    U256::from_big_endian(p_bytes.as_slice())
}

// In production, this would be taken from an existing trusted setup, so srs_g1 is an argument
// to this function
pub fn commit_to_lagrange_bases<E: PairingEngine>(
    domain_size: usize,
    srs_g1: Vec<E::G1Affine>,
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

pub fn compute_empty_accumulator<E: PairingEngine>(
    lagrange_comms: &Vec<E::G1Affine>,
) -> E::G1Affine {
    let zero: [u8; 32] = compute_zero_leaf::<E::Fr>();
    let zero_bigint = <<E as PairingEngine>::Fr as PrimeField>::from_be_bytes_mod_order(&zero);

    let mut c = lagrange_comms[0].mul(zero_bigint).into_affine();
    for i in 1..lagrange_comms.len() {
        let l_i = lagrange_comms[i];
        c = c.add(l_i.mul(zero_bigint).into_affine());
    }

    c
}

#[test]
pub fn test_compute_zero_leaf() {
    let zero = compute_zero_leaf::<Fr>();

    /*
         To reproduce this value, run the following in a JS console:
         e = require('ethers')
         (
             BigInt(e.utils.solidityKeccak256(['string'], ['Semacaulk'])) %
                 BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
         ).toString(16)
     */

    assert_eq!(hex::encode(zero), "1f77b372cd06a20bef1e41a67da199e48519364916818f8e00716fe79c671a25");
}

#[test]
pub fn test_compute_empty_accumulator() {
    let domain_size = 8;
    let mut rng = test_rng();

    let srs_g1 = unsafe_setup_g1::<Bn254, StdRng>(domain_size, &mut rng);
    let lagrange_comms = commit_to_lagrange_bases::<Bn254>(domain_size, srs_g1);
    let empty_accumulator = compute_empty_accumulator::<Bn254>(&lagrange_comms);
    println!("{}", empty_accumulator);
}

pub fn compute_lagrange_tree<E: PairingEngine>(
    lagrange_comms: &Vec<E::G1Affine>,
) -> KeccakTree {

    let mut tree = KeccakTree::new(4, [0; 32]);

    assert_eq!(tree.num_leaves(), lagrange_comms.len());

    for (i, p) in lagrange_comms.iter().enumerate() {
        let mut b = Vec::with_capacity(64);
        let _ = p.write(&mut b);

        // Slice to the first 64 bytes, since the 65th byte indicates whether the point is the
        // point at infinity and we don't need it
        let b = &b.get(0..64).unwrap();

        let leaf = keccak256(b);

        tree.set(i, leaf);
    }

    tree
}
    
#[test]
pub fn test_compute_lagrange_tree() {
    let domain_size = 8;
    let mut rng = test_rng();

    let srs_g1 = unsafe_setup_g1::<Bn254, StdRng>(domain_size, &mut rng);
    let lagrange_comms = commit_to_lagrange_bases::<Bn254>(domain_size, srs_g1);

    let tree = compute_lagrange_tree::<Bn254>(&lagrange_comms);
    println!("{}", hex::encode(tree.root()));
}
