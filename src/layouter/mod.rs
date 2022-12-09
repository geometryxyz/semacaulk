use std::{iter, marker::PhantomData};

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use rand::RngCore;

use crate::constants::{NUMBER_OF_MIMC_ROUNDS, SUBGROUP_SIZE};

/*
   TODO: Add assignment hackmd table
   Full assignment of (blinded) wires of the circuit
*/
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Assignment<F: PrimeField> {
    pub(crate) nullifier: Vec<F>,
    pub(crate) key: Vec<F>,
    pub(crate) nullifier_trapdoor: Vec<F>,
    pub(crate) nullifier_external: Vec<F>,
}

pub struct Layouter<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Layouter<F> {
    pub fn assign<R: RngCore>(
        identity_nullifier: F,
        identity_trapdoor: F,
        external_nullifier: F,
        c: &Vec<F>, // round constants in mimc
        rng: &mut R,
    ) -> Assignment<F> {
        let pow_7 = |x: F| x.pow(&[7, 0, 0, 0]);

        /* Begin assign nullifier  */
        let mut nullifier = Vec::<F>::with_capacity(SUBGROUP_SIZE);

        nullifier.push(pow_7(identity_nullifier + c[0]));
        for i in 1..NUMBER_OF_MIMC_ROUNDS {
            nullifier.push(pow_7(nullifier[i - 1] + c[i]));
        }

        nullifier.insert(0, identity_nullifier);
        Self::blind(&mut nullifier, rng);
        /* End assign nullifier  */

        /* Begin assign key */
        let mut key = iter::repeat(nullifier[NUMBER_OF_MIMC_ROUNDS] + identity_nullifier)
            .take(NUMBER_OF_MIMC_ROUNDS + 1)
            .collect();
        Self::blind(&mut key, rng);
        /* End assign key */

        /* Begin assign nullifier_trapdoor */
        let mut nullifier_trapdoor = Vec::<F>::with_capacity(SUBGROUP_SIZE);
        nullifier_trapdoor.push(pow_7(identity_trapdoor + key[0] + c[0]));
        for i in 1..NUMBER_OF_MIMC_ROUNDS {
            nullifier_trapdoor.push(pow_7(nullifier_trapdoor[i - 1] + key[i] + c[i]));
        }

        nullifier_trapdoor.insert(0, identity_trapdoor);
        Self::blind(&mut nullifier_trapdoor, rng);
        /* End assign nullifier_trapdoor */

        /* Begin assign nullifier_external */
        let mut nullifier_external = Vec::<F>::with_capacity(SUBGROUP_SIZE);
        nullifier_external.push(pow_7(external_nullifier + key[0] + c[0]));
        for i in 1..NUMBER_OF_MIMC_ROUNDS {
            nullifier_external.push(pow_7(nullifier_external[i - 1] + key[i] + c[i]));
        }

        nullifier_external.insert(0, external_nullifier);
        Self::blind(&mut nullifier_external, rng);
        /* End assign nullifier_external */

        Assignment {
            nullifier,
            key,
            nullifier_trapdoor,
            nullifier_external,
        }
    }

    fn blind<R: RngCore>(x: &mut Vec<F>, rng: &mut R) {
        /*
            We use N_ROUNDS + 1 rows
        */
        assert_eq!(x.len(), NUMBER_OF_MIMC_ROUNDS + 1);
        let mut blinders = (0..SUBGROUP_SIZE - x.len())
            .map(|_| F::rand(rng))
            .collect::<Vec<_>>();

        x.append(&mut blinders);
    }
}

#[cfg(test)]
mod layouter_tests {
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use ark_std::test_rng;

    use super::Layouter;
    use crate::mimc7::Mimc7;

    #[test]
    fn test_mimc_correctness() {
        let n_rounds = 91;
        let mut rng = test_rng();

        let mimc7 = Mimc7::<Fr>::new("mimc".into(), n_rounds);

        let identity_nullifier = Fr::from(100u64);
        let identity_trapdoor = Fr::from(200u64);

        let external_nullifier = Fr::from(300u64);

        let nullifier = mimc7.hash(identity_nullifier, Fr::zero());
        let nullifier_trapdoor =
            mimc7.multi_hash(&[identity_nullifier, identity_trapdoor], Fr::zero());
        let nullifier_external =
            mimc7.multi_hash(&[identity_nullifier, external_nullifier], Fr::zero());

        let assignment = Layouter::assign(
            identity_nullifier,
            identity_trapdoor,
            external_nullifier,
            &mimc7.cts,
            &mut rng,
        );

        assert_eq!(nullifier, assignment.nullifier[n_rounds]); // first round of multi_hash is correct
                                                               // key is copied correctly
        assert_eq!(
            assignment.nullifier[n_rounds] + identity_nullifier,
            assignment.key[0]
        );

        // identity commitment is calculated correctly
        assert_eq!(
            nullifier_trapdoor,
            assignment.nullifier_trapdoor[n_rounds]
                + identity_trapdoor
                + Fr::from(2u64) * assignment.key[0]
        );

        // public nullifier is calculated correctly
        assert_eq!(
            nullifier_external,
            assignment.nullifier_external[n_rounds]
                + external_nullifier
                + Fr::from(2u64) * assignment.key[0]
        );
    }
}
