use crate::utils::{
    fill_zeroes,
    fill_blinds,
    fill_dummy,
};
use crate::mimc7::{
    Mimc7,
    compute_round_digests,
};
use crate::gate_sanity_checks::{
    gate_1 as gate_1_sanity_check,
};
use ark_bn254::{Fr as F};
use ark_std::test_rng;
use ark_ff::{
    Zero,
    Field,
    field_new,
};

#[test]
fn gate_1() {
    /*
       q_mimc * (
           (w_0 + c) ^ 7 - w_1_next
       )
    */

    let dummy = F::from(12345u64);
    let mut rng = test_rng();
    let n_rounds = 91;
    let domain_size = 128; // the next power of 2

    // When the number of mimc rounds = 4 and the domain size is 6, q_mimc
    // should be [1, 1, 1, 1, 0, 0]
    
    let mut q_mimc_evals = vec![F::zero(); n_rounds];
    fill_zeroes(&mut q_mimc_evals, domain_size);

    let seed: &str = "mimc";
    let mimc7 = Mimc7::<F>::new(seed, n_rounds);
    let mut c_evals = mimc7.cts.clone();
    fill_dummy(&mut c_evals, dummy, domain_size);

    let id_nullifier = F::from(1000u64);
    let h_s = mimc7.hash(id_nullifier, F::zero());

    let round_digests = compute_round_digests(
        id_nullifier,
        c_evals.clone(),
        n_rounds,
    );
    assert_eq!(*round_digests.last().unwrap(), h_s);
    assert_eq!(h_s, field_new!(F, "16067226203059564164358864664785075013352803000046344251956454165853453063400"));

    let mut w_evals = vec![id_nullifier; 1];
    w_evals.extend_from_slice(&round_digests);
    fill_blinds(&mut w_evals, &mut rng, domain_size);

    gate_1_sanity_check(
        q_mimc_evals,
        w_evals,
        c_evals,
        dummy,
        domain_size,
    );
}

//#[test]
//fn gate_2() {
    //[>
       //q_mimc * (
           //(w_1 + key + c) ^ 7 - w_1_next
       //)
    //*/

    //let dummy = F::from(12345u64);
    //let mut rng = test_rng();
    //let n_rounds = 91;
    //let domain_size = 128; // the next power of 2

    //let mut q_mimc_evals = vec![F::zero(); n_rounds];
    //fill_zeroes(&mut q_mimc_evals, domain_size);

    //let seed: &str = "mimc";
    //let mimc7 = Mimc7::<F>::new(seed, n_rounds);
    //let mut c_evals = mimc7.cts.clone();
    //fill_dummy(&mut c_evals, dummy, domain_size);

    //let id_nullifier = F::from(1);
    //let id_trapdoor = F::from(2);

    //let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());

    //let key = id_nullifier + id_nullifier_hash;
    //println!("key: {}", key);

    //let mut round_digests = vec![];
    //round_digests.push((id_trapdoor + key).pow(&[7u64, 0, 0, 0]));
    //for i in 1..n_rounds {
        //let w_prev = round_digests[i - 1];
        //let c = c_evals[i];

        //let d = (w_prev + key + c).pow(&[7u64, 0, 0, 0]);
        //round_digests.push(d);
        //println!("\td: {}", d);
    //}

    //let expected = mimc7.multi_hash(&[id_nullifier, id_trapdoor], F::zero());
    //assert_eq!(expected, round_digests[90] * F::from(2) + id_trapdoor);
    //println!("{}", expected);
    // 0b91ebbd35d7448ecc13e75a7ceb1ce5bbe428090acfae0da2c3867a874ce6ea
//}
