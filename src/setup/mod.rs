use crate::accumulator::commit_to_lagrange_bases;
use crate::prover::ProvingKey;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::bytes::FromBytes;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[cfg(test)]
pub mod tests;

pub fn setup(log_2_table_size: usize, ptau_filepath: &str) -> (ProvingKey<Bn254>, Vec<G1Affine>) {
    assert!((10..28).contains(&log_2_table_size));
    let table_size: usize = 2u64.pow(log_2_table_size as u32) as usize;
    let num_g1_points = table_size + 1;
    let num_g2_points = table_size;

    let (srs_g1, srs_g2) =
        ppot_rs::ptau::read(ptau_filepath, num_g1_points, num_g2_points).unwrap();

    let lagrange_comms = commit_to_lagrange_bases::<Bn254>(table_size, &srs_g1);
    (ProvingKey::<Bn254> { srs_g1, srs_g2 }, lagrange_comms)
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn load_lagrange_comms_from_file(filename: &str) -> Vec<G1Affine> {
    let mut lagrange_comms = vec![];
    let lines = read_lines(filename).unwrap();
    for line in lines {
        let val = line.unwrap();
        if val.len() == 128 {
            lagrange_comms.push(g1_str_to_g1(&val));
        }
    }
    lagrange_comms
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
        x = hex_to_fq(x_str);
        y = hex_to_fq(y_str);
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

    let x0 = hex_to_fq(x0_str);
    let x1 = hex_to_fq(x1_str);
    let y0 = hex_to_fq(y0_str);
    let y1 = hex_to_fq(y1_str);

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    let g2 = G2Affine::new(x, y, false);
    assert!(g2.is_on_curve());
    g2
}
