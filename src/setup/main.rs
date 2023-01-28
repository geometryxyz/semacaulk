use semacaulk::bn_solidity_utils::f_to_hex_le;
use semacaulk::setup::setup;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::LineWriter;

/*
 * Usage: cargo run setup <table_size> <hex_filename> <lagrange_comms_out>
 * Reads the SRS G1 and G2 points from <hex_filename>, and writes the commitments to the Lagrange
 * basis polynomials to <lagrange_comms_out>.
 */
fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() > 3);
    let log_2_table_size = &args[args.len() - 3];
    let hex_filename = &args[args.len() - 2];
    let lagrange_comms_out = &args[args.len() - 1];

    let log_2_table_size: usize = log_2_table_size.parse().unwrap();

    let (_pk, lagrange_comms) = setup(log_2_table_size, hex_filename.as_str());

    let file = File::create(lagrange_comms_out).unwrap();
    let mut file = LineWriter::new(file);

    for comm in lagrange_comms {
        let line = format!("{}{}", f_to_hex_le(comm.x), f_to_hex_le(comm.y));
        file.write_all(line.as_bytes()).unwrap();
        file.write_all(b"\n").unwrap();
    }
    file.flush().unwrap();
}
