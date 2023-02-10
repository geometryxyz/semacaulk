# Ethereum contracts

## `Semacaulk.sol`

The main Semacaulk contract which client applications should interact with or
inherit. The key functions it exposes are:

### `insertIdentity`

Functions signature: `insertIdentity(uint256 _identityCommitment, uint256 _lagrangeLeafX, uint256 _lagrangeLeafY, bytes32[] memory _lagrangeMerkleProof`)

`_identityCommitment` is the user-generated value defined in
[6.1](./mechanism_of_operation.html#61-user-identities).

`_lagrangeLeafX` and `_lagrangeLeafY` are the respective X and Y coordinates of
the commitment to the Lagrange basis polynomial of the index at which the user
wishes to insert their identity commitment.

`_lagrangeMerkleProof` is the Merkle proof from the Keccak256 hash of
`_lagrangeLeafX` and `_lagrangeLeafY` to the root of the [Lagrange Basis
Polynomial Commitment Tree](./lagrange_basis_polynomial_commitment_tree.html).

This function first verifies the Merkle proof to ensure that `_lagrangeLeafX`
and `_lagrangeLeafY` are valid. Next, it performs field and elliptic curve
operations to perform an [insertion](./insertion.html) to update the
accumulator.

### `broadcastSignal`

Function signature: `broadcastSignal(bytes memory _signal, Types.Proof memory proof, uint256 _nullifierHash, uint256 _externalNullifier)`

This function performs the following steps:

1. Revert if `_nullifierHash` has already been seen. This prevents double-signalling.
2. Compute the $\mathsf{sig\_hash}$ public input by hashing `_signal` with
   Keccak256 and right-shifting the result by 8 bits.
3. Verify the proof and revert if it is invalid.
4. Store the nullifier hash.

## `Verifier.sol`

This contract exposes a `verify()` function for the Semacaulk contract's
`broadcastSignal` function to use. It performs the steps described in
[4.7](./verification.html).

## `Transcript.sol`

This contract abstracts over the Fiat-Shamir Heuristic by providing helper
functions to the verifier to add data to the transcript and extract the
challenge values it needs.

## `Types.sol`

A helper library that defines complex Solidity types that comprise the proof.

## `BN254.sol`

Provides functions that encapsulate elliptic curve operations over the BN254
curve.

## `KeccakMT.sol`

Provides a helper function for the Semacaulk contract's `insertIdentity`
function to verify a Merkle proof.

## `Lagrange.sol`

Provides a helper function for the verifier contract to compute the evaluation
of $L_0$ at a given point $\alpha$, and the evaluation of the vanishing
polynomial at $\alpha$.

## `Constants.sol`

Contains crucial constant values:

- `PRIME_Q`: the order of the BN254 base field.
- `PRIME_R`: the order of the BN254 scalar field.
- `DOMAIN_SIZE_INV`: the inverse of the domain size (128) over the BN254 scalar field.
- `LOG2_DOMAIN_SIZE`: the binary logarithm of the domain size such that `2 ^ LOG2_DOMAIN_SIZE = 128`.
- `OMEGA`: the 1st root of unity (counting from 0) of the subgroup domain.
- `OMEGA_N`: the $n$th root of unity (counting from 0) of the subgroup domain.

The following constants depend on the maximum size of the accumulator, and
should be changed depending on how many elements the client application wishes
to support.

- `SRS_G1_T_X`: The X coordinate of $\mathsf{srs\_g1}[t]$
- `SRS_G1_T_Y`: The Y coordinate of $\mathsf{srs\_g1}[t]$
- `SRS_G2_1_X_0`: The X0 coordinate of $\mathsf{srs\_g2}[1]$
- `SRS_G2_1_X_1`: The X1 coordinate of $\mathsf{srs\_g2}[1]$
- `SRS_G2_1_Y_0`: The Y0 coordinate of $\mathsf{srs\_g2}[1]$
- `SRS_G2_1_Y_1`: The Y1 coordinate of $\mathsf{srs\_g2}[1]$
