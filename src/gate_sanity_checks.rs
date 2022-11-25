use ark_ff::PrimeField;

/*
 * Checks whether the evals satisfy the gate with the following equation:
 * q_mimc * (w0 + key + c)^7 - w0_next = 0
 */
pub fn mimc<F: PrimeField>(
    key: F,
    q_mimc_evals: Vec<F>,
    w0_evals: Vec<F>,
    c_evals: Vec<F>,
    dummy: F,
    domain_size: usize,
) {
    for i in 0..domain_size {
        let w0_next_i = if i == domain_size - 1 {
            dummy
        } else {
            w0_evals[i + 1]
        };

        let result = q_mimc_evals[i] * (
            w0_next_i - (w0_evals[i] + key + c_evals[i]).pow(&[7, 0, 0, 0])
        );

        assert_eq!(result, F::zero());
    }
}

/*
 * Checks whether the evals satisfy the gate with the following equation:
 * 
 * L_0 * (w0_next_n1 - w0 - w0_next_n)
 */
//pub fn gate_4<F: PrimeField>(
    //w0_evals: Vec<F>,
    //dummy: F,
    //domain_size: usize,
    //n_rounds: usize,
//) {
    //for i in 0..domain_size {
        //let w0_next_n1 = if i == n_rounds - 1 {
            //dummy
        //} else {
            //w0_evals[i + 1]
        //};

        //let w0_next_n = if i == n_rounds - 1 {
            //dummy
        //} else {
            //w0_evals[i]
        //};
    //}
//}
