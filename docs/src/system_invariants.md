# System invariants

An [invariant](https://mathworld.wolfram.com/Invariant.html) is a property of a
system which remains unmodified even after operations or transformations are
applied to it. The authors of Semacaulk intend the following to be the
invariants of Semacaulk:

1. **Privacy**: No-one but the user who knows the value of the identity
   nullifier and identity trapdoor behind an identity commitment may generate a
   valid proof of set membership of the identity commitment in the accumulator.

2. **Safe NUMS value**: No-one should be able to produce a valid proof of set
   membership for the default nothing-up-my-sleeve value.

3. **Proof non-malleability**: Proofs are visible once submitted to the mempool,
   but no-one should be able to modify an existing proof, change it such that
   it is associated with a different signal, and remain valid.

4. **Zero-knowledge**: given a valid proof, no-one should be able to determine
   the index of the identity commitment the identity nullifier, or the identity
   trapdor associated with the proof.

Other invariants which have to do with the internal consistency and correctness
of the system are:

5. All identity commitments must be less than the BN254 scalar field size.

6. Every identity commitment in the accumulator must have been added at some
   point in the past, except for the NUMS values.

7. Any identity commitment besides the NUMS value may be added to the
   accumulator, unless it is full.

8. The NUMS value cannot be added to the accumulator.

9. There can be no valid proof associated with a NUMS value as the identity
   commitment.

10. All nullifier hashes must be less than the BN254 scalar field size.

11. It should only be possible to generate a proof for a valid user, and
    impossible to generate a proof for an invalid user.
