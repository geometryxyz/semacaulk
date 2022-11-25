use ark_ff::PrimeField;

/*
 * Checks whether the evals satisfy the gate with the following equation:
 * q_mimc * (w0 + key + c)^7 - w0_next = 0
 */
pub fn mimc<F: PrimeField>(
    key: F,
    q_mimc_evals: &Vec<F>,
    w0_evals: &Vec<F>,
    c_evals: &Vec<F>,
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

        println!("{}", i);
        assert_eq!(result, F::zero());
    }
}

/*
 * Checks whether the evals satisfy the gate with the following equation:
 * 
 * L_0 * (w0_next_n1 - w0 - w0_next_n)
 */
pub fn gate_4<F: PrimeField>(
    l_evals: Vec<F>,
    w0_evals: Vec<F>,
    dummy: F,
    domain_size: usize,
    n_rounds: usize,
) {
    for i in 0..domain_size {
        // offset by n + 1
        let w0_next_n1 = if (n_rounds + i + 1) < domain_size {
            w0_evals[n_rounds + i + 1]
        } else {
            dummy
        };

        // offset by n
        let w0_next_n = if (n_rounds + i) < domain_size {
            w0_evals[n_rounds + i]
        } else {
            dummy
        };

        assert_eq!(
            l_evals[i] * (w0_next_n1 - w0_evals[i] - w0_next_n),
            F::zero(),
        );

    }
}

/*
 * Checks whether the evals satisfy the gate with the following equation:
 * 
 * L_0 * (w_1_next_n1 - w_1 - w_1_next - 2 * key)
 */
pub fn gate_5<F: PrimeField>(
    l_evals: Vec<F>,
    w1_evals: Vec<F>,
    key_evals: Vec<F>,
    dummy: F,
    domain_size: usize,
    n_rounds: usize,
) {
    for i in 0..domain_size {
        // offset by n
        let w1_next_n1 = if (n_rounds + i + 1) < domain_size {
            w1_evals[n_rounds + i + 1]
        } else {
            dummy
        };

        // offset by n + 1
        let w1_next_n = if (n_rounds + i) < domain_size {
            w1_evals[n_rounds + i]
        } else {
            dummy
        };

        assert_eq!(
            l_evals[i] * (w1_next_n1 - w1_evals[i] - w1_next_n - (key_evals[i] * F::from(2u64))),
            F::zero(),
        );
    }
}

/*
 * Checks whether the evals satisfy the gate with the following equation:
 * 
 * L_0 * (key - w0_next_n1)
 */
pub fn gate_7<F: PrimeField>(
    l_evals: Vec<F>,
    w0_evals: Vec<F>,
    key_evals: Vec<F>,
    dummy: F,
    domain_size: usize,
    n_rounds: usize,
) {
    for i in 0..domain_size {
        // offset by n + 1
        let w0_next_n1 = if (n_rounds + i + 1) < domain_size {
            w0_evals[n_rounds + i + 1]
        } else {
            dummy
        };
        assert_eq!(
            l_evals[i] * (key_evals[i] - w0_next_n1),
            F::zero(),
        );
    }
}
