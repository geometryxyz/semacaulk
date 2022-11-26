use ark_ff::PrimeField;
use rand::rngs::StdRng;

pub fn fill_zeroes<F: PrimeField>(evals: &mut Vec<F>, domain_size: usize) {
    // [1, 2, 3] becomes [1, 2, 3, 0, 0, ...] up to domain_size
    let zeroes = vec![F::zero(); domain_size - evals.len()];
    evals.extend_from_slice(&zeroes);
}

pub fn fill_blinds<F: PrimeField>(evals: &mut Vec<F>, rng: &mut StdRng, domain_size: usize) {
    // [1, 2, 3] becomes [1, 2, 3, r0, r1, ...] up to domain_size where rn is a random value
    let blinds = vec![F::rand(rng); domain_size - evals.len()];
    evals.extend_from_slice(&blinds);
}

pub fn fill_dummy<F: PrimeField>(evals: &mut Vec<F>, dummy: F, domain_size: usize) {
    // [1, 2, 3] becomes [1, 2, 3, 1234, 1234, ...] up to domain_size
    let dummys = vec![dummy.clone(); domain_size - evals.len()];
    evals.extend_from_slice(&dummys);
}
