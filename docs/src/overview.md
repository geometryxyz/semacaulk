# Overview

Semacaulk is a zero-knowledge set membership protocol that works on Ethereum.

Semacaulk allows a user to *commit* to an identity, represented by two secret
values: an identity nullifier and an identity trapdoor. Next, any user who
knows their secret values can generate a proof that they had previously
committed to said identity, without revealing which member of the set they
were. Moreover, when they submit such a proof, they can broadcast an arbitrary
*signal* against an *external nullifier*, but only do so once per external
nullifier. This enables applications like mixers, whistleblowing, and simple
private voting systems. This is the same basic functionality as the [Semaphore
Protocol](https://github.com/semaphore-protocol/semaphore).

The source code for Semacaulk can be found
[here](https://github.com/geometryresearch/semacaulk).

## Differences from Semaphore

Semacaulk differs from Semaphore in two key ways. First, instead of
accumulating identity commitments in a Merkle tree, it updates a KZG
commitment. This operations involves BN254 point multiplication and addition,
rather than expensive zk-friendly hash operations. Secondly, the underlying
proof system is a polynomial interactive oracle proof that combines [Caulk+
lookups](https://eprint.iacr.org/2022/957) and [multipoint opening
argument](https://zcash.github.io/halo2/design/proving-system/multipoint-opening.html).

Thanks to these techniques, on-chain insertions are far cheaper in Semacaulk
(around 68k gas) while the gas cost of verification (356k gas) is comparable to
that of Semaphore. Moreover, proof generation comes in two phases - a
[precomputation stage](precomputation_and_updates.html) and a proof generation
stage. The total time taken is comparable to Groth16 proof generation for a
Semaphore circuit that supports the same number of insertions, but more
imporantly, precomputation can be performed long in advance and efficiently
updated, which imparts more flexibility which may lead to higher
user-friendliness.

## Motivation

We intend Semacaulk to demonstrate the use of Caulk+ techniques for membership
proofs in a gas-efficient manner to enable privacy-related applications. We
believe these techniques, as are other new proving systems and lookup
arguments, can be highly useful, and we hope that Semacaulk shows how to
practically use them.

We highly welcome and strongly encourage collaboration with projects who wish
to build upon Semacaulk.

Note that the techniques used in Semacaulk do not have to involve an end-to-end
custom prover such as used here. We have done this only because we wanted to
experiment with improving prover efficiency further. With only small changes,
the same gas-efficient membership proof construction can be used with more
generic and expressive SNARK-based programs.

## Security

The code base has not been audited. We do not recommend its use in production
until a thorough audit has been performed.
