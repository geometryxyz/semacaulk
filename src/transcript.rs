/*
    Implementation of transcript with keccak256 that is compatible with Transcript.sol
*/
use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use tiny_keccak::{Hasher, Keccak};

pub struct Transcript {
    data: Vec<u8>,
}

impl Transcript {
    pub fn new_transcript() -> Self {
        let initial_challenge = Self::compute_initial_challenge();
        Self {
            data: initial_challenge.to_vec(),
        }
    }

    fn compute_initial_challenge() -> [u8; 32] {
        [0u8; 32]
    }

    pub fn round_0_public_inputs(&mut self, f_vals: [Fr; 3]) {
        for val in f_vals {
            self.update_with_f(val);
        }
    }

    pub fn round_1(&mut self, g1_vals: [&G1Affine; 4]) {
        for val in g1_vals {
            self.update_with_g1(val);
        }
    }

    pub fn round_2(&mut self, g1_vals: [&G1Affine; 4]) {
        for val in g1_vals {
            self.update_with_g1(val);
        }
    }

    pub fn round_3(&mut self, w: &G2Affine, h: &G1Affine) {
        self.update_with_g2(w);
        self.update_with_g1(h);
    }

    pub fn round_4(&mut self, f_vals: [Fr; 17]) {
        for val in f_vals {
            self.update_with_f(val);
        }
    }

    pub fn round_5(&mut self, f_cm: &G1Affine) {
        self.update_with_g1(f_cm);
    }

    pub fn update_with_f(&mut self, x: Fr) {
        let mut x_bytes = x.into_repr().to_bytes_be();
        self.data.append(&mut x_bytes);
    }

    pub fn update_with_g1(&mut self, pt: &G1Affine) {
        let mut x_bytes = pt.x.into_repr().to_bytes_be();
        let mut y_bytes = pt.y.into_repr().to_bytes_be();

        self.data.append(&mut x_bytes);
        self.data.append(&mut y_bytes);
    }

    pub fn update_with_g2(&mut self, pt: &G2Affine) {
        let mut x_0_bytes = pt.x.c0.into_repr().to_bytes_be();
        let mut x_1_bytes = pt.x.c1.into_repr().to_bytes_be();
        let mut y_0_bytes = pt.y.c0.into_repr().to_bytes_be();
        let mut y_1_bytes = pt.y.c1.into_repr().to_bytes_be();
        self.data.append(&mut x_0_bytes);
        self.data.append(&mut x_1_bytes);
        self.data.append(&mut y_0_bytes);
        self.data.append(&mut y_1_bytes);
    }

    pub fn get_challenge(&mut self) -> Fr {
        let mut buff = vec![0u8; 32];
        let mut hasher = Keccak::v256();

        hasher.update(&self.data);
        hasher.finalize(&mut buff);

        let challenge = Fr::from_be_bytes_mod_order(&buff);

        self.data.clear();
        self.data.append(&mut buff);

        // f_to_u256(challenge)
        challenge
    }
}

#[cfg(test)]
mod test_transcript {
    use ark_bn254::{Fr, G1Affine};
    use ark_ec::AffineCurve;
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn test_fr_bytes_len() {
        let x = Fr::from(1231);
        let x_bytes = x.into_repr().to_bytes_be();
        assert_eq!(x_bytes.len(), 32);
    }

    #[test]
    fn test_fq_bytes_len() {
        let pt = G1Affine::prime_subgroup_generator();
        let x_bytes = pt.x.into_repr().to_bytes_be();
        let y_bytes = pt.y.into_repr().to_bytes_be();

        assert_eq!(x_bytes.len(), 32);
        assert_eq!(y_bytes.len(), 32);
    }
}
