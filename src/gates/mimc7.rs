use ark_ff::{PrimeField};
use ark_std::io::Cursor;
use tiny_keccak::{Keccak, Hasher};

pub fn compute_round_digests<F: PrimeField>(
    preimage: F,
    key: F,
    c_evals: &Vec<F>,
    n_rounds: usize,
) -> Vec<F> {
    // The first 
    assert_eq!(c_evals[0], F::zero());

    let mut round_digests = vec![];
    round_digests.push((preimage + key).pow(&[7u64, 0, 0, 0]));
    for i in 1..n_rounds {
        let w_prev = round_digests[i - 1];
        let c = c_evals[i];

        round_digests.push((w_prev + c + key).pow(&[7u64, 0, 0, 0]));
    }

    round_digests
}

pub struct Mimc7<F: PrimeField> {
    pub seed: String,
    pub n_rounds: usize,
    pub cts: Vec<F>
}

impl<F: PrimeField> Mimc7<F> {
    pub fn new(seed: &str, n_rounds: usize) -> Self {
        Self {
            seed: seed.into(),
            n_rounds,
            cts: Self::initialize_constants(seed, n_rounds)
        }
    }

    pub fn multi_hash(&self, arr: &[F], key: F) -> F {
        let mut r = key;
        for x in arr {
            let h = self.hash(*x, r);
            r += x;
            r += h;
        }
        r
    }

    pub fn hash(&self, x: F, k: F) -> F {
        let seven = [7u64, 0, 0, 0];
        let mut round_digest = (x + k).pow(seven);
        for i in 1..self.n_rounds {
            round_digest = (round_digest + self.cts[i] + k).pow(seven);
        }
        round_digest + k
    }

    fn initialize_constants(seed: &str, n_rounds: usize) -> Vec<F> {
        let mut cts = Vec::<F>::with_capacity(n_rounds);
        cts.push(F::zero());

        let mut out_buff = Cursor::new(vec![0u8; 32]);

        let mut hasher = Keccak::v256();
        hasher.update(seed.as_bytes());
        hasher.finalize(&mut out_buff.get_mut());

        for _ in 1..n_rounds {
            let mut hasher = Keccak::v256();
            hasher.update(out_buff.get_ref());
            out_buff.set_position(0);
            hasher.finalize(&mut out_buff.get_mut());

            cts.push(F::from_be_bytes_mod_order(out_buff.get_ref()));
        }

        cts
    }
}

#[cfg(test)]
mod mimc7_tests {
    use super::Mimc7;
    use ark_bn254::Fr as F;
    use ark_ff::{field_new, Zero};

    #[test]
    fn test_simple_hash() {
        let f: F = field_new!(F, "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        assert_eq!(f, F::zero());

        let seed: &str = "mimc";
        let n_rounds = 91; 

        let mimc7 = Mimc7::<F>::new(seed, n_rounds);

        let hash = mimc7.hash(F::from(1000u64), F::from(0));
        assert_eq!(hash, field_new!(F, "16067226203059564164358864664785075013352803000046344251956454165853453063400"));
    }

    #[test]
    fn test_multi_hash() {
        let f: F = field_new!(F, "21888242871839275222246405745257275088548364400416034343698204186575808495617");
        assert_eq!(f, F::zero());

        let seed: &str = "mimc";
        let n_rounds = 91; 

        let mimc7 = Mimc7::<F>::new(seed, n_rounds);

        // From https://github.com/iden3/circomlibjs/blob/main/test/mimc7.js
        let hash = mimc7.multi_hash(&[F::from(1), F::from(2)], F::from(0));
        assert_eq!(hash, field_new!(F, "5233261170300319370386085858846328736737478911451874673953613863492170606314"));
    }
}

