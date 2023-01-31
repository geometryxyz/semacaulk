# Cryptographic Specification

Some of the terminology, symbols, and language has been borrowed from and
inspired by the [Halo2 Book](https://zcash.github.io/halo2) and the [MACI 1.0
Audit Specification](https://hackmd.io/AP6zPSgtThWxx6pjXY7R8A).

## Cryptographic primitives

### The BN254 curve

The current implementation of Semacaulk uses the BN254 curve which Ethereum
supports in its elliptic curve addition, scalar multiplication, and
pairing-check precompiles as defined in
[EIP-196](https://eips.ethereum.org/EIPS/eip-196) and
[EIP-197](https://eips.ethereum.org/EIPS/eip-197). 

The BN254 scalar field \\(\mathbb{F}_r\\) is:

```
21888242871839275222246405745257275088548364400416034343698204186575808495617
```

The BN254 prime field \\(\mathbb{F}_q\\) is:

```
21888242871839275222246405745257275088696311157297823662689037894645226208583
```

### The nothing-up-my-sleeve value

The nothing-up-my-sleeve (NUMS) value is:

```bash
14233191614411629788649003849761857673160358990904722769695641636673172216357
```

It is the Keccak256 hash of the bytestring `Semacaulk`, modulo
\\(\mathbb{F}_r\\). To compute it, run the following in a NodeJS console where
`e` is an instance of Ethers.js 5.0:

```js
(
    BigInt(e.utils.solidityKeccak256(['string'], ['Semacaulk'])) % 
    BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')
).toString(10)
```

### The structured reference string (SRS)

### The MiMC7 hash function

Semacaulk currently uses the MiMC7 hash function to compute identity
commitments and nullifier hashes. While other possibly more secure hash
functions like Poseidon are possible, we chose MiMC7 only because of its
simplicity of implementation for our purposes of delivering a proof-of-concept.

The MiMC7 has function is defined
[here](https://iden3-docs.readthedocs.io/en/latest/_downloads/a04267077fb3fdbf2b608e014706e004/Ed-DSA.pdf).

Given the BN254 scalar field \\(\mathbb{F}_r\\), we first define 91 *round
constants* \\(\mathbb{cts}\\) using the algorithm implemented in
[`circomlibjs/src/mimc7.js`](https://github.com/iden3/circomlibjs/blob/ee8ec2fca2ca7f16dec9d0f39d57dbe80dd18870/src/mimc7.js#L29)
and
[`semacaulk/src/mimc7.rs`](https://github.com/geometryresearch/semacaulk/blob/main/src/mimc7.rs#L65).

The algorithm is as such:

- The first round constant is \\(0\\).
- The next round constant is the Keccak256 hash of the bytestring `mimc`,
  modulo the field order of \\(\mathbb{F}_r\\).
- Each subsequent round constant is the Keccak256 hash of the previous one,
  modulo the field order of \\(\mathbb{F}_r\\).

### Lagrange basis polynomials

TODO

#### Efficient generation of commitments to Lagrange basis polynomials

### KZG commitments

TODO
