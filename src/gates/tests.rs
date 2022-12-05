use crate::gates::gate_sanity_checks::{
    gate_10_key_constant as gate_10_key_constant_check, gate_4_key_sum as gate_4_key_sum_check,
    gate_5_id_comm_final as gate_5_id_comm_final_check,
    gate_6_nullifier_hash_final as gate_6_nullifier_hash_final_check,
    gate_7_key_col as gate_7_key_col_check,
    gate_8_nullifier_hash_col as gate_8_nullifier_hash_col_check, gate_9 as gate_9_check,
    mimc as mimc_check,
};
use crate::gates::mimc7::{compute_round_digests, Mimc7};
use crate::gates::utils::{fill_blinds, fill_dummy, fill_zeroes};
use ark_bn254::Fr as F;
use ark_ff::{field_new, One, PrimeField, Zero};
use ark_std::test_rng;
use rand::rngs::StdRng;

struct MiMCGateTestVals<F: PrimeField> {
    dummy: F,
    n_rounds: usize,
    domain_size: usize,
    q_mimc_evals: Vec<F>,
    c_evals: Vec<F>,
    mimc7: Mimc7<F>,
}

fn prepare_mimc_gate_tests() -> MiMCGateTestVals<F> {
    let dummy = F::from(12345u64);
    let n_rounds = 91;
    // TODO: write a next_pow_2 function in utils.rs
    let domain_size = 128; // the next power of 2

    // When the number of mimc rounds = 4 and the domain size is 6, q_mimc
    // should be [1, 1, 1, 1, 0, 0]
    let mut q_mimc_evals = vec![F::one(); n_rounds];
    fill_zeroes(&mut q_mimc_evals, domain_size);

    let seed: &str = "mimc";
    let mimc7 = Mimc7::<F>::new(seed, n_rounds);
    let mut c_evals = mimc7.cts.clone();
    fill_dummy(&mut c_evals, dummy, domain_size);

    return MiMCGateTestVals {
        dummy,
        n_rounds,
        domain_size,
        q_mimc_evals,
        c_evals,
        mimc7,
    };
}

fn gen_l_evals(domain_size: usize) -> Vec<F> {
    let mut l_evals = vec![F::zero(); domain_size];
    l_evals.extend_from_slice(&[F::zero(), F::one()]);
    l_evals
}

fn gen_w0_evals(
    id_nullifier: F,
    mut rng: StdRng,
    n_rounds: usize,
    domain_size: usize,
    c_evals: &Vec<F>,
    mimc7: &Mimc7<F>,
) -> Vec<F> {
    let key = F::zero();

    let round_digests = compute_round_digests(id_nullifier, key, &c_evals, n_rounds);
    let mut w_evals = vec![id_nullifier; 1];
    w_evals.extend_from_slice(&round_digests);

    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());
    w_evals.push(id_nullifier + id_nullifier_hash);
    fill_blinds(&mut w_evals, &mut rng, domain_size);

    w_evals
}

fn gen_w1_evals(
    id_nullifier: F,
    id_trapdoor: F,
    mut rng: StdRng,
    n_rounds: usize,
    domain_size: usize,
    c_evals: &Vec<F>,
    mimc7: &Mimc7<F>,
) -> Vec<F> {
    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());

    let key = id_nullifier_hash + id_nullifier;

    let round_digests = compute_round_digests(id_trapdoor, key, &c_evals, n_rounds);

    let mut w_evals = vec![id_trapdoor; 1];
    w_evals.extend_from_slice(&round_digests);

    w_evals.push(
        id_trapdoor + round_digests[n_rounds - 1] + (id_nullifier + id_nullifier_hash) * F::from(2),
    );

    fill_blinds(&mut w_evals, &mut rng, domain_size);

    w_evals
}

fn gen_w2_evals(
    id_nullifier: F,
    ext_nullifier: F,
    rng: StdRng,
    n_rounds: usize,
    domain_size: usize,
    c_evals: &Vec<F>,
    mimc7: &Mimc7<F>,
) -> Vec<F> {
    gen_w1_evals(
        id_nullifier,
        ext_nullifier,
        rng,
        n_rounds,
        domain_size,
        c_evals,
        mimc7,
    )
}

fn gen_pi_evals(nullifier_hash: F, w_evals: &Vec<F>) -> Vec<F> {
    let mut pi_evals = vec![nullifier_hash; 1];
    for i in 1..w_evals.len() {
        pi_evals.push(w_evals[i - 1]);
    }
    pi_evals
}

fn gen_q_key_evals(n_rounds: usize, domain_size: usize) -> Vec<F> {
    let mut q_key_evals = vec![F::zero(); n_rounds];
    fill_zeroes(&mut q_key_evals, domain_size);
    q_key_evals
}

#[test]
fn id_nullifier_gate() {
    /*
       Gate 1:

       q_mimc * (
           (w_0 + key + c) ^ 7 - w_0_next
       )

       Note that key = 0 here
    */

    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let q_mimc_evals = test_vals.q_mimc_evals;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let id_nullifier = F::from(1000u64);
    let key = F::zero();
    let h_s = mimc7.hash(id_nullifier, key);

    let round_digests = compute_round_digests(id_nullifier, key, &c_evals, n_rounds);
    assert_eq!(*round_digests.last().unwrap(), h_s);
    assert_eq!(
        h_s,
        field_new!(
            F,
            "16067226203059564164358864664785075013352803000046344251956454165853453063400"
        )
    );

    let w_evals = gen_w0_evals(id_nullifier, rng, n_rounds, domain_size, &c_evals, &mimc7);

    mimc_check(
        key,
        &q_mimc_evals,
        &w_evals,
        &c_evals,
        test_vals.dummy,
        domain_size,
    );
}

#[test]
fn id_comm_lrd() {
    /*
     Gate 2:
       q_mimc * (
           (w_1 + key + c) ^ 7 - w_1_next
       )
    */
    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let q_mimc_evals = test_vals.q_mimc_evals;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let id_nullifier = F::from(1);
    let id_trapdoor = F::from(2);

    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());

    let key = id_nullifier_hash + id_nullifier;

    let round_digests = compute_round_digests(id_trapdoor, key, &c_evals, n_rounds);

    let w_evals = gen_w1_evals(
        id_nullifier,
        id_trapdoor,
        rng,
        n_rounds,
        domain_size,
        &c_evals,
        &mimc7,
    );

    mimc_check(
        key,
        &q_mimc_evals,
        &w_evals,
        &c_evals,
        test_vals.dummy,
        domain_size,
    );

    let id_commitment = mimc7.multi_hash(&[id_nullifier, id_trapdoor], F::zero());
    assert_eq!(
        id_commitment,
        field_new!(
            F,
            "5233261170300319370386085858846328736737478911451874673953613863492170606314"
        )
    );

    // Gate 2 does not compute the *final* MiMC7 multihash, but for completeness, check it as such:
    let last_round_digest = round_digests[n_rounds - 1];
    assert_eq!(
        id_commitment,
        id_nullifier_hash + id_nullifier + id_trapdoor + last_round_digest + key
    );
}

#[test]
fn nullifier_hash_lrd() {
    /*
       Gate 3:

       q_mimc * (
           (w_2 + key + c) ^ 7 - w_2_next
       )
    */
    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let q_mimc_evals = test_vals.q_mimc_evals;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let id_nullifier = F::from(1);
    let ext_nullifier = F::from(3);

    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());

    let key = id_nullifier_hash + id_nullifier;

    let round_digests = compute_round_digests(ext_nullifier, key, &c_evals, n_rounds);

    let w_evals = gen_w2_evals(
        id_nullifier,
        ext_nullifier,
        rng,
        n_rounds,
        domain_size,
        &c_evals,
        &mimc7,
    );

    mimc_check(
        key,
        &q_mimc_evals,
        &w_evals,
        &c_evals,
        test_vals.dummy,
        domain_size,
    );

    let nullifier_hash = mimc7.multi_hash(&[id_nullifier, ext_nullifier], F::zero());
    assert_eq!(
        nullifier_hash,
        field_new!(
            F,
            "2778328833414940327165159797352134351544660530548983879289181965284146860516"
        )
    );

    // Gate 3 does not compute the *final* MiMC7 multihash, but for completeness, check it as such:
    let last_round_digest = round_digests[n_rounds - 1];
    assert_eq!(
        nullifier_hash,
        id_nullifier_hash + id_nullifier + ext_nullifier + last_round_digest + key
    );
}

#[test]
fn key_sum() {
    /*
       Gate 4:

       L_0 * (w_0_next_n1 - w_0 - w_0_next_n)

       This means that w_0_next_n1 should equal to the sum of id_nullifier and id_nullifier_hash.
    */

    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let l_evals = gen_l_evals(domain_size);

    let id_nullifier = F::from(1);

    let key = F::zero();

    let round_digests = compute_round_digests(id_nullifier, key, &c_evals, n_rounds);

    assert_eq!(round_digests.len(), n_rounds);

    let w_evals = gen_w0_evals(id_nullifier, rng, n_rounds, domain_size, &c_evals, &mimc7);

    gate_4_key_sum_check(l_evals, w_evals, test_vals.dummy, domain_size, n_rounds);
}

#[test]
fn id_comm_final() {
    /*
       Gate 5:

       L_0 * (w_1_next_n1 - w_1 - w_1_next - 2 * key)

       This means that w1_next_n1 should be the full (completed) MiMC7 hash of the identity
       nullifier and the identity trapdoor.
    */
    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let l_evals = gen_l_evals(domain_size);

    let id_nullifier = F::from(1);
    let id_trapdoor = F::from(2);

    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());
    let key = id_nullifier_hash + id_nullifier;

    let w_evals = gen_w1_evals(
        id_nullifier,
        id_trapdoor,
        rng,
        n_rounds,
        domain_size,
        &c_evals,
        &mimc7,
    );

    let key_evals = vec![key; domain_size];

    gate_5_id_comm_final_check(
        l_evals,
        w_evals,
        key_evals,
        test_vals.dummy,
        domain_size,
        n_rounds,
    );
}

#[test]
fn nullifier_hash_final() {
    /*
       Gate 6:

       L_0 * (w_2_next_n1 - w_2 - w_2_next - 2 * key)

       This means that w2_next_n1 should be the full (completed) MiMC7 hash of the identity
       nullifier and the external nullifier.
    */
    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let l_evals = gen_l_evals(domain_size);

    let id_nullifier = F::from(1);
    let ext_nullifier = F::from(3);

    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());
    let key = id_nullifier_hash + id_nullifier;

    let w_evals = gen_w2_evals(
        id_nullifier,
        ext_nullifier,
        rng,
        n_rounds,
        domain_size,
        &c_evals,
        &mimc7,
    );

    let key_evals = vec![key; domain_size];

    gate_6_nullifier_hash_final_check(
        l_evals,
        w_evals,
        key_evals,
        test_vals.dummy,
        domain_size,
        n_rounds,
    );
}

#[test]
fn key_col() {
    /*
       Gate 7:

       L_0 * (key - w_0_next_n1)

       This means that the key should equal the sum of id_nullifier and id_nullifier_hash.

    */
    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let l_evals = gen_l_evals(domain_size);

    let id_nullifier = F::from(1);

    let round_digests = compute_round_digests(id_nullifier, F::zero(), &c_evals, n_rounds);

    assert_eq!(round_digests.len(), n_rounds);

    let w_evals = gen_w0_evals(id_nullifier, rng, n_rounds, domain_size, &c_evals, &mimc7);

    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());
    let key = id_nullifier_hash + id_nullifier;

    let key_evals = vec![key; domain_size];

    gate_7_key_col_check(
        l_evals,
        w_evals,
        key_evals,
        test_vals.dummy,
        domain_size,
        n_rounds,
    );
}

#[test]
fn nullifier_hash_col() {
    /*
       Gate 8:

       L_0 * (PI - w_2_next_n1)

       This means that the public input should be the nullifier hash.

    */
    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let l_evals = gen_l_evals(domain_size);

    let id_nullifier = F::from(1);
    let ext_nullifier = F::from(3);
    let nullifier_hash = mimc7.multi_hash(&[id_nullifier, ext_nullifier], F::zero());

    let w_evals = gen_w2_evals(
        id_nullifier,
        ext_nullifier,
        rng,
        n_rounds,
        domain_size,
        &c_evals,
        &mimc7,
    );

    let pi_evals = gen_pi_evals(nullifier_hash, &w_evals);

    gate_8_nullifier_hash_col_check(
        &l_evals,
        &pi_evals,
        &w_evals,
        test_vals.dummy,
        domain_size,
        n_rounds,
    );
}

#[test]
fn gate_9() {
    /*
       Gate 9:

       L_0 * (PI - w_2)

    */
    let rng = test_rng();

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let c_evals = test_vals.c_evals;
    let mimc7 = test_vals.mimc7;

    let l_evals = gen_l_evals(domain_size);

    let id_nullifier = F::from(1);
    let ext_nullifier = F::from(3);
    let nullifier_hash = mimc7.multi_hash(&[id_nullifier, ext_nullifier], F::zero());

    let w_evals = gen_w2_evals(
        id_nullifier,
        ext_nullifier,
        rng,
        n_rounds,
        domain_size,
        &c_evals,
        &mimc7,
    );

    let pi_evals = gen_pi_evals(nullifier_hash, &w_evals);

    gate_9_check(&l_evals, &pi_evals, &w_evals, test_vals.dummy, domain_size);
}

#[test]
fn key_constant() {
    /*
       Gate 10:

       q_key * (key - key_next)

       This means that w1_next_n1 should be the full (completed) MiMC7 hash of the identity
       nullifier and the identity trapdoor.
    */

    let test_vals = prepare_mimc_gate_tests();
    let n_rounds = test_vals.n_rounds;
    let domain_size = test_vals.domain_size;
    let mimc7 = test_vals.mimc7;

    let q_key_evals = gen_q_key_evals(n_rounds, domain_size);

    let id_nullifier = F::from(1);

    let id_nullifier_hash = mimc7.hash(id_nullifier, F::zero());
    let key = id_nullifier_hash + id_nullifier;

    let key_evals = vec![key; domain_size];

    gate_10_key_constant_check(&q_key_evals, &key_evals, test_vals.dummy, domain_size);
}
