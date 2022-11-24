use ark_ff::PrimeField;

pub fn gate_1<F: PrimeField>(
    q_mimc_evals: Vec<F>,
    w_evals: Vec<F>,
    c_evals: Vec<F>,
    dummy: F,
    domain_size: usize,
) {
    for i in 0..domain_size {
        let w_next_i = if i == domain_size - 1 {
            dummy
        } else {
            w_evals[i + 1]
        };
        let result = q_mimc_evals[i] * (
            w_next_i - (w_evals[i] + c_evals[i]).pow(&[7, 0, 0, 0])
        );

        assert_eq!(result, F::zero());
    }
}
