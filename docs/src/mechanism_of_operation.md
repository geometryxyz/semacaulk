# Mechanism of Operation

The goal of Semaphore is to enable users to:

1. Register their identity;
2. Prove in zero-knowledge that they are a member of the set of registered users;
3. Broadcast an arbitrary signal towards an external nullifier, without the
   possibility of double-signalling.

## 6.1. User identities

A user's identity consists of an *identity nullifier* \\(\mathsf{id\\_nul}\\)
and an *identity trapdoor* \\(\mathsf{id\\_trap}\\). These are secret values
and are elements of \\(\mathbb{F}_r\\) (see [1.1](./cryptographic_specification.html#11-the-bn254-scalar-field)).

An *identity commitment* \\(\mathsf{id\\_comm}\\) is the MiMC7 `multi_hash` (see [4.3](./cryptographic_specification.html#43-the-mimc7-multi_hash-algorithm))
of \\(\mathsf{id\\_nul}\\) and \\(\mathsf{id\\_trap}\\):

\\(\mathsf{id\\_comm} = \mathsf{multi\\_hash}([\mathsf{id\\_nul}, \mathsf{id\\_trap}])\\)

## 6.2. External nullifiers

An *external nullifier* \\(\mathsf{ext\\_nul}\\) is a \\(\mathbb{F}_r\\) field
element which represents a topic. A signal can only be broadcast towards each
external nullifier once and only once.

## 6.3. Nullifier hashes

A nullifier hash is the MiMC7 `multi_hash` of
\\(\mathsf{id\\_nul}\\) and \\(\mathsf{ext\\_nul}\\):

\\(\mathsf{nul\\_hash} = \mathsf{multi\\_hash}([\mathsf{id\\_nul}, \mathsf{ext\\_nul}])\\)

## 6.4. Insertions

An *insertion* is the act of updating the on-chain accumulator with a user's
identity commitment. This is done by invoking the `insertIdentity()` function
of the Semacaulk smart contract.

## 6.5. Broadcasting a signal

When a user *broadcasts a signal*, they generate a proof that they know the
secret identity nullifier and identity trapdoor behind their identity
commitment, and then submit said proof to the Semacaulk smart contract's
`broadcastSignal()` function.

Tied to this proof is the hash of a *signal* and the user's desired external
nullifier. The contract (not the user) hashes the user-provided signal using
Keccak256 and right-shifts the result by 8 bits to derive
\\(\\mathsf{sig\\_hash}\\), which is used as one of the public inputs to the
verifier.

### 6.6. Preventing double-signalling

The Semacaulk smart contract maintains a mapping of nullifier hashes. Each
nullifier hash is unique to the user and an external nullifier. If the
`broadcastSignal()` function finds that a nullifier hash has already been seen,
it rejects the transaction, thus preventing double-signalling.
