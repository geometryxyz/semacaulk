use ark_bn254::{G1Affine, G2Affine};
use ark_ff::PrimeField;
use ethers::types::U256;

pub fn f_to_u256<F: PrimeField>(val: F) -> U256 {
    let mut b = Vec::with_capacity(32);
    let _ = val.write(&mut b);
    let b_as_arr: [u8; 32] = b.try_into().unwrap();
    U256::from_little_endian(&b_as_arr)
}

pub fn format_g1(pt: G1Affine) -> [U256; 2] {
    [f_to_u256(pt.x), f_to_u256(pt.y)]
}

pub fn format_g2(pt: G2Affine) -> [[U256; 2]; 2] {
    [
        [f_to_u256(pt.x.c1), f_to_u256(pt.x.c0)],
        [f_to_u256(pt.y.c1), f_to_u256(pt.y.c0)],
    ]
}
