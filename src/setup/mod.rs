use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::bytes::FromBytes;
use crate::prover::ProvingKey;
use crate::bn_solidity_utils::f_to_hex;
use crate::accumulator::commit_to_lagrange_bases;

pub mod tests;

pub fn setup(
    log_2_table_size: usize,
    srs_hex_filename: &str,
) -> (
        ProvingKey::<Bn254>,
        Vec<G1Affine>,
     ) {
    assert!(log_2_table_size < 28 && log_2_table_size > 0);
    let table_size: usize = 2u64.pow(log_2_table_size as u32) as usize;

    let (srs_g1, srs_g2) = load_srs_from_hex(srs_hex_filename);
    println!("{}, {}", srs_g1.len(), table_size);
    assert!(srs_g1.len() > table_size);
    assert!(srs_g2.len() >= table_size);

    println!("Update Constants.sol with these values:"); 
    println!("uint256 constant SRS_G1_T_X = 0x{};", f_to_hex(srs_g1[table_size].x));
    println!("uint256 constant SRS_G1_T_Y = 0x{};", f_to_hex(srs_g1[table_size].y));
    println!("uint256 constant SRS_G2_1_X_0 = 0x{};", f_to_hex(srs_g2[1].x.c1));
    println!("uint256 constant SRS_G2_1_X_1 = 0x{};", f_to_hex(srs_g2[1].x.c0));
    println!("uint256 constant SRS_G2_1_Y_0 = 0x{};", f_to_hex(srs_g2[1].y.c1));
    println!("uint256 constant SRS_G2_1_Y_1 = 0x{};", f_to_hex(srs_g2[1].y.c0));

    println!();
    println!("Computing commitments to Lagrange basis polynomials...");
    let lagrange_comms = commit_to_lagrange_bases::<Bn254>(table_size, &srs_g1);

    (ProvingKey::<Bn254> { srs_g1, srs_g2: srs_g2.clone() }, lagrange_comms)
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn load_lagrange_comms_from_file(
    filename: &str,
) -> Vec<G1Affine> {
    let mut lagrange_comms = vec![];
    if let Ok(lines) = read_lines(filename) {
        for line in lines {
            if let Ok(val) = line {
                if val.len() == 128 {
                    lagrange_comms.push(g1_str_to_g1(&String::from(val)));
                }
            }
        }
    }
    lagrange_comms
}

pub fn load_srs_from_hex(filename: &str) -> (Vec<G1Affine>, Vec<G2Affine>) {
    let mut srs_g1 = vec![];
    let mut srs_g2 = vec![];
    if let Ok(lines) = read_lines(filename) {
        for line in lines {
            if let Ok(val) = line {
                if val.len() == 128 {
                    let g1 = g1_str_to_g1(&String::from(val));
                    srs_g1.push(g1);
                } else if val.len() == 256 {
                    let g2 = g2_str_to_g2(&String::from(val));
                    srs_g2.push(g2);
                } else if val.len() == 0 {
                    // do nothing
                } else {
                    panic!("Invalid line detected - was this file generated correctly?");
                }
            }
        }
    }
    assert!(srs_g1.len() > 0);
    assert!(srs_g2.len() > 0);
    return (srs_g1, srs_g2);
}

pub fn hex_to_fq(val: &str) -> Fq {
    assert_eq!(val.len(), 64);
    let bytes_vec = hex::decode(val).unwrap();
    let bytes_slice: &[u8] = bytes_vec.as_slice();

    Fq::read(bytes_slice).unwrap()
}

pub fn g1_str_to_g1(v: &str) -> G1Affine {
    assert_eq!(v.len(), 128);
    let val: String = v.to_string();
    let x;
    let y;
    unsafe {
        let x_str = val.get_unchecked(0..64);
        let y_str = val.get_unchecked(64..128);
        x = hex_to_fq(&x_str);
        y = hex_to_fq(&y_str);
    }
    let g1 = G1Affine::new(x, y, false);
    assert!(g1.is_on_curve());
    g1
}

pub fn g2_str_to_g2(val: &str) -> G2Affine {
    assert_eq!(val.len(), 256);
    let val = val.to_string();
    let x0_str;
    let x1_str;
    let y0_str;
    let y1_str;

    unsafe {
        x0_str = val.get_unchecked(0..64);
        x1_str = val.get_unchecked(64..128);
        y0_str = val.get_unchecked(128..192);
        y1_str = val.get_unchecked(192..256);
    }

    let x0 = hex_to_fq(&x0_str);
    let x1 = hex_to_fq(&x1_str);
    let y0 = hex_to_fq(&y0_str);
    let y1 = hex_to_fq(&y1_str);

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);
    
    let g2 = G2Affine::new(x, y, false);
    assert!(g2.is_on_curve());
    g2
}
