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
    pub(crate) identity_commitment: Vec<F>,
    pub(crate) external_nullifier: Vec<F>,
}

pub struct Layouter<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Layouter<F> {
    /*
     * Construct the circuit assignment table.
     * @param identity_nullifier: The identity nullifier.
     * @param identity_trapdoor: The identity trapdoor.
     * @param external_nullifier: The external nullifier.
     * @param c: MiMC7 round constants.
     * @param rng: The random number generator used for blinding.
     */
    pub fn assign<R: RngCore>(
        identity_nullifier: F,
        identity_trapdoor: F,
        external_nullifier: F,
        c: &Vec<F>,
        rng: &mut R,
    ) -> Assignment<F> {
        // Raises a given field element to the power of 7
        let pow_7 = |x: F| x.pow(&[7, 0, 0, 0]);

        //---------------------------------------------------------------------
        // Assign the nullifier column
        let mut nullifier_col = Vec::<F>::with_capacity(SUBGROUP_SIZE);
        nullifier_col.push(identity_nullifier);

        // The first round constant should be 0, so we don't have to add it to 
        // identity_nullifier for the first row.
        assert_eq!(c[0], F::zero());
        nullifier_col.push(pow_7(identity_nullifier));

        for i in 1..NUMBER_OF_MIMC_ROUNDS {
            nullifier_col.push(pow_7(nullifier_col[i] + c[i]));
        }

        // Fill the remaining rows with random values
        Self::blind(&mut nullifier_col, rng);

        //---------------------------------------------------------------------
        // Assign the key column
        let mut key_col = iter::repeat(nullifier_col[NUMBER_OF_MIMC_ROUNDS] + identity_nullifier)
            .take(NUMBER_OF_MIMC_ROUNDS + 1)
            .collect();
        Self::blind(&mut key_col, rng);

        //---------------------------------------------------------------------
        // Assign the identity_commitment column
        let mut identity_commitment_col = Vec::<F>::with_capacity(SUBGROUP_SIZE);
        identity_commitment_col.push(identity_trapdoor);

        // The first round constant should be 0, so we don't have to add it to 
        // identity_nullifier for the first row.
        identity_commitment_col.push(pow_7(identity_trapdoor + key_col[0]));
        for i in 1..NUMBER_OF_MIMC_ROUNDS {
            identity_commitment_col.push(pow_7(identity_commitment_col[i] + key_col[i] + c[i]));
        }
        Self::blind(&mut identity_commitment_col, rng);

        //---------------------------------------------------------------------
        // Assign the nullifier_external column
        let mut external_nullifier_col = Vec::<F>::with_capacity(SUBGROUP_SIZE);
        external_nullifier_col.push(external_nullifier);

        // The first round constant should be 0, so we don't have to add it to 
        // identity_nullifier for the first row.
        external_nullifier_col.push(pow_7(external_nullifier + key_col[0]));
        for i in 1..NUMBER_OF_MIMC_ROUNDS {
            external_nullifier_col.push(pow_7(external_nullifier_col[i] + key_col[i] + c[i]));
        }
        Self::blind(&mut external_nullifier_col, rng);

        Assignment {
            nullifier: nullifier_col,
            key: key_col,
            identity_commitment: identity_commitment_col,
            external_nullifier: external_nullifier_col,
        }
    }

    /*
     * Given a Vec of field elements (which must be NUMBER_OF_MIMC_ROUNDS + 1 in length), extend it
     * to SUBGROUP_SIZE elements where the remaining values are random field elements.
     * @param x: The Vec to extend.
     * @param rng: The random number generator to use.
     */
    fn blind<R: RngCore>(
        x: &mut Vec<F>,
        rng: &mut R
    ) {
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
        let identity_commitment =
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

        // Check that the identity commitment is calculated correctly
        assert_eq!(
            identity_commitment,
            assignment.identity_commitment[n_rounds]
                + identity_trapdoor
                + Fr::from(2u64) * assignment.key[0]
        );

        // Check that the public nullifier is calculated correctly
        assert_eq!(
            nullifier_external,
            assignment.external_nullifier[n_rounds]
                + external_nullifier
                + Fr::from(2u64) * assignment.key[0]
        );
    }
}
