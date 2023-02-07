# The Circuit and Gates

Semacaulk uses a custom Plonk-style proof system where a prover must convince a
verifier that it knows of some private *witness* values which are the result of
the correct execution of predefined logical operations upon public inputs and
fixed data. In other terms, there is a *circuit* which represents some program.
In proof systems like Groth16, circuits are represented in the form of a Rank-1
Constraint System (R1CS), and compilers like [circom](https://iden3.io/circom)
can be used to easily compile circuits to this format. Semacaulk, by contrast,
uses a set of custom gates on a set of data columns to represent its
logic.

## Private inputs (witness)

- \\(\mathsf{id\\_nul}\\): the identity nullifier.
- \\(\mathsf{id\\_trap}\\): the identity trapdoor.
- \\(i\\): the index of the prover's identity commitment in the accumulator.

## Public inputs

- \\(\mathsf{ext\\_nul}\\): the extenal nullifier.
- \\(\mathsf{id\\_comm}\\): the identity commitment, which is the MiMC7
  `multi_hash` of \\([\mathsf{id\\_nul}, \mathsf{id\\_trap}]\\).
- \\(\mathsf{nul\\_hash}\\): the nullifier hash, which is the MiMC7
  `multi_hash` of \\([\mathsf{id\\_nul}, \mathsf{ext\\_nul}]\\).

## Columns

| Row | \\(\mathsf{w}_0\\) | \\(\mathsf{w}_1\\) | \\(\mathsf{w}_2\\) | \\(\mathsf{key}\\) | \\(\mathsf{c}\\) | \\(\mathsf{q\\_mimc}\\) |
|-|-|-|-|-|-|-|
|0| \\(\mathsf{id\\_nul}\\) | \\(\mathsf{id\\_trap}\\) | \\(\mathsf{ext\\_nul}\\) | \\(\mathsf{w}_0[n] + \mathsf{w}_0[0] \\) | \\(\mathsf{cts}[0]\\) | 1 |
|1| \\((\mathsf{w}_0[0] + \mathsf{c}[0]) ^ 7\\) | \\((\mathsf{w}_1[0] + \mathsf{key}[0] + \mathsf{c}[0]) ^ 7\\) | \\((\mathsf{w}_2[0] + \mathsf{key}[0] + \mathsf{c}[0]) ^ 7\\)| \\(\mathsf{w}_0[n] + \mathsf{w}_0[0] \\) | \\(\mathsf{cts}[1]\\) | 1 |
|...|...|...|...|...|...|...|
| \\(n\\) | \\((\mathsf{w}_0[n - 1] + \mathsf{c}[n - 1]) ^ 7\\) | \\((\mathsf{w}_1[n - 1] + \mathsf{key}[n - 1] + \mathsf{c}[n - 1]) ^ 7\\) | \\((\mathsf{w}_2[n - 1] + \mathsf{key}[n - 1] + \mathsf{c}[n - 1]) ^ 7\\)| \\(\mathsf{w}_0[n] + \mathsf{w}_0[0] \\) | \\(\mathsf{dummy}\\) | 0 |
| 128 | \\(b\\) | \\(b\\) | \\(b\\) | \\(b\\) | \\(b\\) | \\(b\\)

Notes:

- The 0th row contains the \\(\mathsf{id\\_nul}\\), \\(\mathsf{id\\_trap}\\), etc
  values. They are not table headers.
- \\(n\\) is the constant (91) defined in
  [4](./cryptographic_specification.html#4-the-mimc7-hash-function).
- \\(\mathsf{dummy}\\) can be any value as it will not be used by any of the gates.
- \\(\mathsf{q\\_mimc}\\) is a selector column. It is a vector starting with
  \\(n\\) 1 values followed by zeros.
- \\(\mathsf{c}\\) is a fixed column starting with \\(n\\) MiMC7 round constants.
- \\(b\\) are random values used to blind the columns, in order to
  make it computationally infeasible to brute-force their polynomial commitments.

## Gates

To understand how the logic of the circuit is encoded, consider each row of the
table as inputs to the linear combination of the following gates, which must
evaluate to 0 for a valid proof to be generated. In effect:

\\(\mathsf{gate}_0(r) + ... + \mathsf{gate}_n(r) = 0\\) must be true.

Each and every gate must evaluate to 0. It is not possible for the prover to
cheat by having some gates evaluate to some value such that the total evaluates
to 0, since the prover will be forced to separate each gate with a challenge
that they cannot control. Internally, the equation is actually:

\\(\mathsf{gate}_0(r) \cdot v_0 + ... + \mathsf{gate}_n(r) \cdot v_n = 0\\) must be true.

where the \\(v\\) values are successive powers of the hash of the public
inputs. The prover would have to break a strong hash function to choose the
public inputs and \\(v\\) values in order to cheat.

### 0. `Mimc7RoundGate`

The equation is:

\\(\mathsf{q\\_mimc}[i] \cdot (\mathsf{w}_0[i] + 0 + \mathsf{c}[i]) ^ 7\\)

This makes each row from 1 to \\(n\\) contain the successive outputs of the
MiMC7 round function over \\(\mathsf{id\\_nul}\\). 

The key is set to 0 for all rows.

### 1. `Mimc7RoundGate` for the identity commitment

The equation is:

\\(\mathsf{q\\_mimc}[i] \cdot (\mathsf{w}_1[i] + \mathsf{key}[i] + \mathsf{c}[i]) ^ 7\\)

To understand this, first note that gate 4 (`KeyCopyGate`) and gate 3
(`KeyEqualityGate`) ensure that the \\(\mathsf{key}\\) values are all the MiMC7
`hash` of \\(\mathsf{id\\_nul}\\) plus \\(\mathsf{id\\_nul}\\).

As described in
[4.3.1](./cryptographic_specification.html#431-multi_hash-with-two-field-elements),
this means that the key for step 4 of the `multi_hash` function on two inputs
is the value in any row of \\(key\\) from 0 to \\(n\\). As such, this gate
represents the circuit logic for step 4 of `multi_hash`, which brings it us
closer to computing the identity commitment.

Recall from [5.1](./mechanism_of_operation.html#51-user-identities):

\\(\mathsf{id\\_comm} = \mathsf{multi\\_hash}([\mathsf{id\\_nul}, \mathsf{id\\_trap}])\\)

### 2. `Mimc7RoundGate` for the nullifier hash

The equation is:

\\(\mathsf{q\\_mimc}[i] \cdot (\mathsf{w}_2[i] + \mathsf{key}[i] + \mathsf{c}[i]) ^ 7\\)

Recall that:

\\(\mathsf{nul\\_hash} = \mathsf{multi\\_hash}([\mathsf{id\\_nul}, \mathsf{ext\\_nul}])\\)

By the same logic behind the `Mimc7RoundGate` for the identity commitment, this
gate brings us closer to compuing the nullifier hash.

### 3. `KeyEqualityGate`

The equation is:

\\(\mathsf{q\\_mimc}[i] \cdot (\mathsf{key}[i] + \mathsf{key}[n])\\) 

This gate ensures that every row of \\(\mathsf{key}\\) from 0 to \\(n\\) contains the
same value.

### 4. `KeyCopyGate`

The equation is:

\\(L_0(\omega_i) \cdot (\mathsf{key}[i] - \mathsf{w}_0[i] - \mathsf{w}_0[n])\\)

This gate ensures that the first row in the \\(\mathsf{key}\\) column is equal
to \\(\mathsf{id\\_nul}\\) plus the \\(n\\)th iteration of the MiMC7 round
function on \\(\mathsf{id\\_nul}\\).

\\(L_0\\) is a precomputed polynomial in the multiplicative subgroup which
evaluates to 1 at \\(\omega_i\\), and 0 at all other roots of unity.
Effectively, it acts as a selector without the overhead of a selector column.

### 5. `NullifierHashGate`

The equation is:

\\(L_0(\omega_i) \cdot (\mathsf{nul\\_hash} - \mathsf{w}_2[n] - (2 \cdot \mathsf{key}[i]) - \mathsf{w}_2[i])\\)

This gate ensures that the \\(\mathsf{nul\\_hash}\\) public input is equal to:

\\(\mathsf{w}_2[n] + (2 \cdot \mathsf{key}[0]) + \mathsf{w}_2[0])\\)

To understand why, let us trace the computation of \\(\mathsf{nul\\_hash}\\):

Given inputs \\(\mathsf{id\\_nul}\\) and \\(\mathsf{ext\\_nul}\\):

1. Set \\(r\\) as 0.
2. Set \\(h_0 = \mathsf{hash}(\mathsf{id\\_nul}, r)\\).
3. Set \\(r = r + \mathsf{id\\_nul} + h_0\\).
4. Set \\(h_1 = \mathsf{hash}(\mathsf{ext\\_nul}, r)\\).
5. Return \\(r + \mathsf{ext\\_nul} + h_1\\).

Hence, \\(\mathsf{nul\\_hash}\\) equals:

\\(r + \mathsf{ext\\_nul} + h_1 =\\)

\\(\mathsf{id\\_nul} + h_0 + \mathsf{ext\\_nul} + h_1 =\\)

\\(\mathsf{id\\_nul} + \mathsf{hash}(\mathsf{id\\_nul}, 0) + \mathsf{ext\\_nul} + \mathsf{hash}(\mathsf{ext\\_nul}, \mathsf{id\\_nul} + \mathsf{hash}(\mathsf{id\\_nul}, 0))\\)

Since the value \\(r\\) from step 3 is used as the key in step 4, the above is
equal to:

\\(\mathsf{key}[0] + \mathsf{ext\\_nul} + \mathsf{hash}(\mathsf{ext\\_nul}, \mathsf{key}[0])\\)

Since \\(\mathsf{hash}(x, k)\\) equals \\(n\\) round digests of \\(x\\) plus
\\(k\\), the above equals:

\\(\mathsf{key}[0] + \mathsf{w}_2[0] + \mathsf{w}_2[n] + \mathsf{key}[0] =\\)

\\(\mathsf{w}_2[n] + (2 \cdot \mathsf{key}[0]) + \mathsf{w}_2[0])\\)

### 6. `ExternalNullifierGate`

The equation is:

\\(L_0(\omega_i) \cdot (\mathsf{w}_2[i] - \mathsf{ext\\_nul})\\)

This gate ensures that the \\(\mathsf{ext\\_nul}\\) public input is equal to
\\(\mathsf{w}_2[0]\\).
