# Cryptographic Specification

Some of the terminology, symbols, and language has been borrowed from and
inspired by the [Halo2 Book](https://zcash.github.io/halo2) and the [MACI 1.0
Audit Specification](https://hackmd.io/AP6zPSgtThWxx6pjXY7R8A).

## Notation

- Accumulator: an elliptic curve point which is a commitment to \\(t\\) field
  elements.
- \\(t\\): the maximum capacity of the accumulator.
- Zero value: the nothing-up-my-sleeve value (see 2).
- Elliptic curve multiplication: in this specification, we use the dot operator
  \\(\cdot\\) to denote scalar multiplication of an elliptic curve point.

## Cryptographic primitives

### 1. The BN254 curve

The current implementation of Semacaulk uses the BN254 curve which Ethereum
supports in its elliptic curve addition, scalar multiplication, and
pairing-check precompiles as defined in
[EIP-196](https://eips.ethereum.org/EIPS/eip-196) and
[EIP-197](https://eips.ethereum.org/EIPS/eip-197). 

#### 1.1. The BN254 scalar field

The BN254 scalar field \\(\mathbb{F}_r\\) is:

```
21888242871839275222246405745257275088548364400416034343698204186575808495617
```

#### 1.2. The BN254 scalar field

The BN254 prime field \\(\mathbb{F}_q\\) is:

```
21888242871839275222246405745257275088696311157297823662689037894645226208583
```

#### 1.3. The \\(\mathbb{G}_1\\) group

The group \\(\mathbb{G}_1\\) defined on BN254 has the generator point \\(g_1 =
(1, 2)\\).

#### 1.4. The \\(\mathbb{G}_2\\) point

The group \\(\mathbb{G}_2\\) defined on BN254 has the generator point \\(g_2 =
(x_0 * i + x_1, y_0 * i + y_1)\\) where:

- \\(x_0\\) equals `11559732032986387107991004021392285783925812861821192530917403151452391805634`
- \\(x_1\\) equals `10857046999023057135944570762232829481370756359578518086990519993285655852781`
- \\(y_0\\) equals `4082367875863433681332203403145435568316851327593401208105741076214120093531`
- \\(y_1\\) equals `8495653923123431417604973247489272438418190587263600148770280649306958101930`

### 2. The nothing-up-my-sleeve value

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

Due to the second-image resistance property of the Keccak256 hash function,
anyone can be assured that no-one knows any other preimage to the NUMS value.
It follows that no-one knows the MiMC7 preimage to the NUMS value.

### 3. The structured reference string (SRS)

Semacaulk's structured reference string (SRS) consists of an ordered list of
\\(2^n + 1\\) \\(\mathbb{G}_1\\) points and \\(2^n\\) \\(\mathbb{G}_2\\)
points, where the maximum capacity of the accumulator is \\(2^n\\).

We assume the existence of a secret and unknown value \\(\tau\\) which can be
generated using a [securely run trusted
setup](https://eprint.iacr.org/2017/1050.pdf).

These points are defined as such:

- \\(\mathsf{srs\\_g1}\\): \\([g_1, g_1^{\tau}, ..., g_1^{\tau^{n + 1}}]\\)
- \\(\mathsf{srs\\_g2}\\): \\([g_2, g_2^{\tau}, ..., g_2^{\tau^{n + 1}}]\\)

Where \\(g_1\\) is defined in 1.3 and \\(g_2\\) is defined in 1.4.

### 4. The MiMC7 hash function

Semacaulk currently uses the MiMC7 hash function to compute identity
commitments and nullifier hashes. While other possibly more secure hash
functions like Poseidon are possible, we chose MiMC7 only because of its
simplicity of implementation for our purposes of delivering a proof-of-concept.

The MiMC7 has function is defined
[here](https://iden3-docs.readthedocs.io/en/latest/_downloads/a04267077fb3fdbf2b608e014706e004/Ed-DSA.pdf).

Our instantiation of the MiMC7 hash function for the BN254 curve uses the
following constants:

- \\(n = 91\\)
- \\(\mathsf{MIMC\\_SEED} =\\) `mimc` (the hexidecimal array `[0x6d, 0x69, 0x6d, 0x63]`)

#### 4.1. The MiMC7 round constants

Given the BN254 scalar field \\(\mathbb{F}_r\\), we first define 91 round
constants (denoted as \\(\mathsf{cts}\\)) using the algorithm implemented in
[`circomlibjs/src/mimc7.js`](https://github.com/iden3/circomlibjs/blob/ee8ec2fca2ca7f16dec9d0f39d57dbe80dd18870/src/mimc7.js#L29)
and
[`semacaulk/src/mimc7.rs`](https://github.com/geometryresearch/semacaulk/blob/main/src/mimc7.rs#L65).

The algorithm is as such:

- The first round constant is \\(0\\).
- The next round constant is the Keccak256 hash of \\(\mathsf{MIMC\\_SEED} =\\),
  modulo the field order of \\(\mathbb{F}_r\\).
- Each subsequent round constant is the Keccak256 hash of the previous one,
  modulo the field order of \\(\mathbb{F}_r\\).

#### 4.2. The MiMC7 `hash` algorithm

To hash a single field element \\(x\\), we use the `hash()` algorithm. The inputs to
`hash()` are \\(x\\) and a key \\(k\\).

1. Compute the first round digest \\(\mathsf{rd[0]} = (x + k) ^ 7\\).
2. Compute the next \\(n - 1\\) round digests such that
\\(\mathsf{rd}[i] = (\mathsf{rd}[i - 1] + \mathsf{cts}[i] + k) ^ 7\\)
3. Return \\(\mathsf{rd}[n - 1] + k\\).

#### 4.3. The MiMC7 `multi_hash` algorithm
To hash multiple field elements \\(x_0, ..., x_n\\), we use the `multi_hash()`
algorithm. The inputs to `multi_hash()` are the array of said field elements
and a key \\(k\\).

1. Initialise \\(r\\) to equal \\(k\\).
2. For each \\(x_i\\):

    a. Set \\(h_i = \mathsf{hash}(x_i, r)\\).

    b. Set \\(r = x_i + h_i\\).

3. Return \\(r\\).

##### 4.3.1 `multi_hash` with two field elements

It is useful to describe the `multi_hash` algorithm for two input elements in
individual steps because the Semacaulk circuit construction (see [The Circuit
and Gates](./circuit_and_gates.html)) makes use of its intermediate states.

Given inputs \\(a\\) and \\(b\\):

1. Set \\(r\\) as 0.
2. Set \\(h_0 = \mathsf{hash}(a, r)\\).
3. Set \\(r = r + a + h_0\\).
4. Set \\(h_1 = \mathsf{hash}(b, r)\\).
5. Return \\(r + b + h_1\\).

Note that in step 4, the key is \\(a + h_0 = \mathsf{hash}(a, 0)\\). This fact
is crucial to understanding how the circuit construction works.

### 5. KZG commitments

Semcaulk uses the KZG commitment scheme described in
[KZG10](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf).

Given a polynomial \\(\phi\\) with \\(l\\) coefficients 
\\([\phi_0, ..., \phi_{l - 1}]\\), one
can use \\(\mathsf{srs\\_g1}\\) to
produce a commitment in the form of a \\(\mathbb{G}_1\\) point, or
\\(\mathsf{srs\\_g2}\\) to produce a commitment in the form of a
\\(\mathbb{G}_2\\) point.

\\(\mathsf{commit}(\phi, \mathsf{srs}) = \sum_{i=1}^{l} \mathsf{srs}[i] \cdot \phi_i \\)


### 6. Lagrange basis polynomials

Lagrange basis polynomials are an important concept and are used in several
parts of the protocol. To understand them, we must first define roots of unity
of a finite field.

#### 6.1. Roots of unity of a finite field

The \\(n\\)th roots of unity of a finite field \\(\mathbb{F}_p\\) with prime
order \\(p\\) are field elements where for each element \\(x\\), \\(x^n = 1\\).

For example, the 4th roots of unity of the BN254 scalar field (see 1.1) are:

```
0x0000000000000000000000000000000000000000000000000000000000000001
0x30644E72E131A029048B6E193FD841045CEA24F6FD736BEC231204708F703636
0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000000
0x0000000000000000B3C4D79D41A91758CB49C3517C4604A520CFF123608FC9CB
```

Another name for the \\(n\\) roots of unity is the evaluation domain of size \\(n\\)
for a given finite field. They are commonly denoted as \\(\\{1, \omega, ...,
\omega^{n-1}\\}\\).

#### 6.2. Lagrange basis polynomials

Given an evaluation domain of size \\(n\\), the Lagrange basis polynomials of
this domain are the \\(n\\) polynomials \\([L_0, ..., L_n]\\) such that
\\(L_i(\omega^{i - 1} = 1)\\) and \\(L_i(\omega^{j} = 0)\\) for all
\\(j \neq i - 1\\). For example:

- the Lagrange basis polynomial \\(L_0\\) evaluates to 1 given the input
  \\(\omega^0\\).
- the Lagrange basis polynomial \\(L_0\\) evaluates to 0 given the input
  \\(\omega^1\\).
- the Lagrange basis polynomial \\(L_1\\) evaluates to 0 given the input
  \\(\omega^0\\).
- the Lagrange basis polynomial \\(L_1\\) evaluates to 1 given the input
  \\(\omega^1\\).

#### 6.3. Efficient generation of commitments to Lagrange basis polynomials

To support \\(t\\) insertions, Semacaulk requires the KZG commitments to the
Lagrange basis polynomials over the evaluation domain of size \\(t\\). These
KZG commitments are efficiently generated using an implementation of the
[Feist-Khovratovich
technique](https://alinush.github.io/2021/06/17/Feist-Khovratovich-technique-for-computing-KZG-proofs-fast.html).

### 7. The accumulator

The *accumulator* is a single \\(\mathbb{G}_1\\) point that is a commitment to
a vector of \\(t\\) \\(\mathbb{F}_r\\) elements where \\(t\\) is the maximum
capacity of the instance of Semacaulk in question. These elements are ordered
with the users' identity commitments followed by nothing-up-my-sleeve values.

An *empty accumulator* is simply a commitment to \\(t\\) nothing-up-my-sleeve
values.

Given the vector of values \\([v_0, ..., v_t]\\), the accumulator \\(C\\) is computed
as such:

\\(\sum_{i=1}^{t} \mathsf{commit}(L_i, \mathsf{srs\\_g1}) \cdot v_i\\)

#### 7.1 Updating the accumulator

To replace a value at \\(w_i\\) with \\(v_i\\) at index \\(i\\):

\\(C_{\mathsf{new}} = C - L \cdot w_i + L \cdot v_i\\)

\\(= C + L \cdot (v_i - w_i)\\)

where \\(L = \mathsf{commit}(L_i, \mathsf{srs\\_g1})\\)

This can be done on-chain at a low cost because the only expensive operations
required are an elliptic curve scalar multiplication and a elliptic curve
addition.

### 8. The Keccak256 hash

The Keccak256 hash function is defined in [*The Keccak SHA-3
submission*](https://keccak.team/files/Keccak-submission-3.pdf) by Bertoni et
al with the output length of 256 bits. We rely on implementations from the
following sources:

- The EVM's [`KECCAK256`
  opcode](https://ethereum.org/en/developers/docs/evm/opcodes/) denoted as
  `0x20`.
- The Javascript [Ethers.js library's
  `ethers.utils.solidityKeccak256`](https://docs.ethers.org/v5/api/utils/hashing/#utils-keccak256)
  function.
- The Rust [`tiny-keccak` library's
  `v256`](https://docs.rs/tiny-keccak/latest/tiny_keccak/struct.Keccak.html)
  function.

### 9. Evaluation domains

#### 9.1. The subgroup domain

#### 9.2. The extended coset domain

#### 9.3. The table domain
