# Proof generation

## 1. Assignment Round

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

where \\(\mathsf{w}_1(\gamma^{91}X)\\) is .... TODO
