use super::{g1_str_to_g1, g2_str_to_g2, setup};

#[test]
pub fn test_g1() {
    //let g1_str = "01000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000";
    let g1_str = "65C58017927150D104B032050F73EC6A18D1135615069F6A4AFF45847C0D29274A46B7E1C915691021D130F9837D066F30CCCFB9CCBD78EB335382F4591E7E20";
    let g1 = g1_str_to_g1(&String::from(g1_str));
    assert!(g1.is_on_curve());
}

#[test]
pub fn test_g2() {
    let g2_str = "edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19aa7dfa6601cce64c7bd3430c69e7d1e38f40cb8d8071ab4aeb6d8cdba55ec8125b9722d1dcdaac55f38eb37033314bbc95330c69ad999eec75f05f58d0890609";
    let g2 = g2_str_to_g2(&String::from(g2_str));
    assert!(g2.is_on_curve());
}

#[test]
pub fn test_setup() {
    let pk = setup(11, "./11.ptau");
    assert_eq!(pk.0.srs_g1.len(), pk.0.srs_g2.len() + 1);
    assert_eq!(pk.1.len(), pk.0.srs_g2.len());
}
