use semacaulk::bn_solidity_utils::{f_to_hex, f_to_hex_le};
use semacaulk::setup::setup;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::LineWriter;

/*
 * Usage: cargo run setup <table_size> <ptau_filename> <lagrange_comms_out>
 * Reads the SRS G1 and G2 points from <ptau_filename>, and writes the commitments to the Lagrange
 * basis polynomials to <lagrange_comms_out>.
 */
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 3 {
        println!("Usage: cargo run setup <table_size> <ptau_filename> <lagrange_comms_out>");
        println!(
            "Reads the SRS G1 and G2 points from <ptau_filename>, and writes the commitments to the Lagrange basis polynomials to <lagrange_comms_out>."
        );
        return;
    }
    assert!(args.len() > 3);
    let log_2_table_size = &args[args.len() - 3];
    let ptau_filename = &args[args.len() - 2];
    let lagrange_comms_out = &args[args.len() - 1];

    let log_2_table_size: usize = log_2_table_size.parse().unwrap();

    let (pk, lagrange_comms) = setup(log_2_table_size, ptau_filename.as_str());
    let srs_g1 = pk.srs_g1;
    let srs_g2 = pk.srs_g2;

    let file = File::create(lagrange_comms_out).unwrap();
    let mut file = LineWriter::new(file);

    for comm in lagrange_comms {
        let line = format!("{}{}", f_to_hex_le(comm.x), f_to_hex_le(comm.y));
        file.write_all(line.as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.flush().unwrap();

    let table_size: usize = 2u64.pow(log_2_table_size as u32) as usize;
    println!("Update Constants.sol with these values:");
    println!(
        "uint256 constant SRS_G1_T_X = 0x{};",
        f_to_hex(srs_g1[table_size].x)
    );
    println!(
        "uint256 constant SRS_G1_T_Y = 0x{};",
        f_to_hex(srs_g1[table_size].y)
    );
    println!(
        "uint256 constant SRS_G2_1_X_0 = 0x{};",
        f_to_hex(srs_g2[1].x.c1)
    );
    println!(
        "uint256 constant SRS_G2_1_X_1 = 0x{};",
        f_to_hex(srs_g2[1].x.c0)
    );
    println!(
        "uint256 constant SRS_G2_1_Y_0 = 0x{};",
        f_to_hex(srs_g2[1].y.c1)
    );
    println!(
        "uint256 constant SRS_G2_1_Y_1 = 0x{};",
        f_to_hex(srs_g2[1].y.c0)
    );
}
