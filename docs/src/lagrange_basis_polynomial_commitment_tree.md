# The Lagrange Basis Polynomial Commitment Tree

The Semaphore contract's `insertIdentity` function requires access to a valid
commitment to the Lagrange basis polynomial at the index at which an insertion
is made. This commitment is prohibitively expensive to compute on-chain, so 
we instead have a Merkle root to the hashes of all of these commitments be set
as an immutable storage variable at deployment time. The user only has to
provide a Merkle path to said commitment, which the contract can cheaply
verify. These commitments are deterministic and anyone can verify that the
Merkle root to these values is valid.

## Code

The Rust function to compute the Lagrange basis polynomial commitments is 
`commit_to_lagrange_bases` located in `src/accumulator.rs`. The code to compute
the Merkle tree of the hashes of these commitments is also located in the same
file.
