# Proof generation

## 4.6.1. Assignment Round

Given the public and private inputs, the prover generates the assignment table
(see [4.3](./circuit_and_gates.html)). Each column is represented as a
polynomial over the multiplicative subgroup generated via Lagrange
interpolation of each row value as a coefficient (TODO: check this language).

- \\(\mathsf{w}_0\\)
- \\(\mathsf{w}_1\\)
- \\(\mathsf{w}_2\\)
- \\(\mathsf{key}\\)

The prover then computes KZG commitments to each of the above polynomials:

- \\([\mathsf{w}_0]_1\\)
- \\([\mathsf{w}_1]_1\\)
- \\([\mathsf{w}_2]_1\\)
- \\([\mathsf{key}]_1\\)

The prover also computes:

\\(A = \mathsf{w}_1 + \mathsf{w}_1(\gamma^{91}X) + 2 \cdot \mathsf{key}\\)

<!--let omega_pow_rotation = state.domain_h.element(NUMBER_OF_MIMC_ROUNDS);-->
<!--let w1_shifted_n = shift_dense_poly(&w1, &omega_pow_rotation);-->
<!--let a: DensePolynomial<_> = &w1_shifted_n + &w1 + &key * E::Fr::from(2u64);-->

where \\(\mathsf{w}_1(\gamma^{91}X)\\) is \\(\mathsf{w}_1\\) shifted by the
\\(n\\)th root of unity in the subgroup domain
([9.1](cryptographic_specification.html#91-the-subgroup-domain)).

Next, the prover adds the public inputs to the transcript in this order:

1. \\(\mathsf{ext\\_nul}\\)
2. \\(\mathsf{nul\\_hash}\\)
3. \\(\mathsf{sig\\_hash}\\)

The prover then extracts the challenge \\(v\\).

## 4.6.2. Quotient round

The prover generates a quotient polynomial \\(q\\) by dividing
a numerator — a challenge-separated linear combination of gate polynomials —
with the vanishing polynomial \\(Z_H\\).

\\(q(X) = \mathsf{numerator} / Z_H\\) where

\\(\mathsf{numerator} =\\)

\\(\mathsf{q\\_mimc}((\mathsf{w}_0 + \mathsf{cts})^7 - \mathsf{w}_0(\gamma X)) + \\)

\\(v \cdot \mathsf{q\\_mimc}((w_1 + \mathsf{key} + \mathsf{cts})^7 - w_1(\gamma X)) +\\)

\\(v^2 \cdot \mathsf{q\\_mimc}((\mathsf{w}_2 + \mathsf{key} + \mathsf{cts})^7 - \mathsf{w}_2(\gamma X)) +\\)

\\(v^3 \cdot \mathsf{q\\_mimc}(\mathsf{key} - \mathsf{key}(\gamma X)) +\\)

\\(v^4 \cdot L_0(\mathsf{key} - \mathsf{w}_0 - \mathsf{w}_0(\gamma ^{91}X)) +\\)

\\(v^5 \cdot L_0(\mathsf{nul\\_hash} - \mathsf{w}_2 - \mathsf{w}_2(\gamma ^{91}X) - 2 \cdot \mathsf{key}) +\\)

\\(v^6 \cdot L_0 \cdot (\mathsf{w}_2 - \mathsf{ext\\_nul})\\)

These equations correspond to the gates defined in
[4.3](circuit_and_gates.html#gates).

\\(\mathsf{w}_0(\gamma X)\\) refers to \\(\mathsf{w}_0\\) shifted (or
"rotated") forward by one.

\\(\mathsf{w}_0(\gamma ^{91}X)\\) refers to \\(\mathsf{w}_0\\) shifted forward
by 91, which is the number of MiMC7 rounds defined in
[4.1](./cryptographic_specification.html#41-the-mimc7-round-constants).

The prover then commits to \\(q\\) to obtain \\([q]_1\\).

## 4.6.3. First Caulk+ round

The prover computes:

- \\([z_I]_1\\)
- \\([c_I]_1\\)
- \\([u]_1\\)

according to [page 6 of the Caulk+
paper](https://eprint.iacr.org/2022/957.pdf).

The prover then updates the transcript with \\([q]_1\\) and the above values,
and extracts the challenge values \\(\chi_1\\) and \\(\chi_2\\).

## 4.6.4. Second Caulk+ round

The prover computes:

\\(H(X) = (Z_I'(U'(X)) + \chi_1 (C_I'(U'(X)) - A(X)) / Z_V(X)\\)

which is a modification of the Round 2 steps from [page 6 of the Caulk+
paper](https://eprint.iacr.org/2022/957.pdf).

## 4.6.5. Opening round

This section is a work in progress; in the meantime, see [this
document](https://hackmd.io/D-bL6-oNSbSej7Ao_-9PLA) for the multiopen argument.
