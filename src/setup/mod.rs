use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ff::bytes::FromBytes;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub mod tests;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
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
                }
            }
        }
    }
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
