use std::env;
use semacaulk::setup::load_srs_from_hex;

fn main () {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() > 3);
    let log_2_table_size = &args[args.len() - 3];
    let srs_hex_filename = &args[args.len() - 2];
    let lagrange_comms_filename = &args[args.len() - 1];

    let (srs_g1, srs_g2) = load_srs_from_hex(srs_hex_filename);
    //let lagrange_comms = load_lagrange_comms_from_file("./lagrangeComms_11");

    //let table_size = (2u64.pow(log_2_table_size as u32) as usize);
}
