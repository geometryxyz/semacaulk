# Proof generation

## 4.6.1. Assignment Round

Given the public and private inputs, the prover generates the assignment table
(see [4.3](./circuit_and_gates.html)). Each column is represented as a
polynomial over the multiplicative subgroup.

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

where \\(\mathsf{w}_1(\gamma^{91}X)\\) is \\(\mathsf{w}_1\\) shifted by the
\\(n\\)th root of unity in the subgroup domain
([9.1](cryptographic_specification.html#91-the-subgroup-domain)).

Next, the prover adds the public inputs to the transcript in this order:

1. \\(\mathsf{ext\\_nul}\\)
2. \\(\mathsf{nul\\_hash}\\)
3. \\(\mathsf{sig\\_hash}\\)

The prover then extracts the challenge \\(v\\), which is used in the next
round.

## 4.6.2. Quotient round

The prover generates a quotient polynomial \\(q\\) by dividing
a numerator — a powers-of-\\(v\\)-separated linear combination of gate
polynomials — with the vanishing polynomial \\(Z_H\\).

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

- \\(\mathsf{z}_i\\)
- \\(\mathsf{c}_i\\)
- \\(u'\\)

and their commitments:

- \\([\mathsf{z}_i]_1\\)
- \\([\mathsf{c}_i]_1\\)
- \\([u']_1\\)

according to [page 6 of the Caulk+
paper](https://eprint.iacr.org/2022/957.pdf).

The prover then updates the transcript with \\([q]_1\\) and the above values,
and extracts the challenge values \\(\chi_1\\) and \\(\chi_2\\), which are
used in the next round. \\(\chi_1\\) is also used in the opening round.

## 4.6.4. Second Caulk+ round

The prover computes:

- \\(\mathsf{h}\\)
- \\(\mathsf{w}\\)

according to the Round 2 steps from [page 6 of the Caulk+
paper](https://eprint.iacr.org/2022/957.pdf), and commits to them:

- \\([\mathsf{h}]_1\\)
- \\([\mathsf{w}]_2\\)

The prover then extracts the challenge \\(\alpha\\), which is used in the next
round.

## 4.6.5. Opening round

This section is a work in progress; in the meantime, see [this
document](https://hackmd.io/D-bL6-oNSbSej7Ao_-9PLA) for the multiopen argument.
Also see [this document](https://hackmd.io/D-bL6-oNSbSej7Ao_-9PLA) which
describes the argument adapted for Semacaulk.

The prover computes:

- \\(\omega\\): the root of unity with index 1 (starting from zero) of the
  subgroup domain
  ((9.1)[./cryptographic_specification.html#91-the-subgroup-domain]).
- \\(\omega^n\\): the root of unity with index \\(n\\) (starting from 0) of the
  subgroup domain.

The prover computes the polynomials:

<!--\\(\mathsf{p}_1 = \mathsf{zi} + \mathsf{ci} \cdot \chi_1\\)-->

<!--\\(\mathsf{p}_2 = \mathsf{zi} \cdot \mathsf{u'}(\alpha) + \chi_1 \cdot \mathsf{ci}(\mathsf{u'}(\alpha))\\)-->

- \\(\mathsf{p}_1\\)
- \\(\mathsf{p}_2\\)

The commitments:

- \\([\mathsf{p}_1]_1\\)
- \\([\mathsf{p}_2]_1\\)

The openings:

- \\(\mathsf{w}_0(\alpha)\\)
- \\(\mathsf{w}_0(\omega\alpha)\\)
- \\(\mathsf{w}_0(\omega^n \alpha)\\)
- \\(\mathsf{w}_1(\alpha)\\)
- \\(\mathsf{w}_1(\omega\alpha)\\)
- \\(\mathsf{w}_1(\omega^n \alpha)\\)
- \\(\mathsf{w}_2(\alpha)\\)
- \\(\mathsf{w}_2(\omega\alpha)\\)
- \\(\mathsf{w}_2(\omega^n \alpha)\\)
- \\(\mathsf{key}(\alpha)\\)
- \\(\mathsf{key}(\omega\alpha)\\)
- \\(\mathsf{q\\_mimc}(\alpha)\\)
- \\(\mathsf{mimc\\_cts}(\alpha)\\)
- \\(\mathsf{q}(\alpha)\\)
- \\(\mathsf{u'}_1(\alpha)\\)
- \\(\mathsf{p}_1(\mathsf{u'}_1(\alpha))\\)
- \\(\mathsf{p}_2(\alpha)\\)

The prover adds the above openings to the transcript in the stated order.

## 4.6.6. Multiopen argument round

The steps in this are based on the Halo2 [multipoint opening
argument](https://zcash.github.io/halo2/design/proving-system/multipoint-opening.html).

The prover computes the vanishing polynomials:

- \\(\mathsf{z}_1 = x - \mathsf{u'}_1(\alpha)\\)
- \\(\mathsf{z}_2 = x - \alpha\\)
- \\(\mathsf{z}_3 = \\mathsf{z}_2 \cdot (x - \omega\alpha)\\)
- \\(\mathsf{z}_4 = \\mathsf{z}_3 \cdot (x - \omega^n \alpha)\\)

The prover extracts the challenge values \\(x_1\\), \\(x_2\\), \\(x_3\\), and
\\(x_4\\).

The prover computes the polynomials:

- \\(\mathsf{q}_1 = \mathsf{p}_1\\)
- \\(\mathsf{q}_2 = \mathsf{q\\_mimc} + 
    \\mathsf{mimc\\_cts} \cdot x_1 + 
    \\mathsf{q} \cdot {x_1}^{2} + 
    \mathsf{u'} * {x_1}^{3} + 
    \mathsf{p}_2 \cdot {x_1}^{4}\\)
- \\(\mathsf{q}_3 = \mathsf{key}\\)
- \\(\mathsf{q}_4 = \mathsf{w}_0 + \mathsf{w}_1 \cdot x_1 + \mathsf{w}_2 \cdot {x_1} ^ 2\\)
- \\(\mathsf{f}_1 = \mathsf{q}_1 / \mathsf{z}_1\\)
- \\(\mathsf{f}_2 = \mathsf{q}_2 / \mathsf{z}_2\\)
- \\(\mathsf{f}_3 = \mathsf{q}_3 / \mathsf{z}_3\\)
- \\(\mathsf{f}_4 = \mathsf{q}_4 / \mathsf{z}_4\\)
- \\(\mathsf{f} = \mathsf{f}_1 +
    \mathsf{f}_2 \cdot x_2 +
    \mathsf{f}_3 \cdot {x_2}^2 +
    \mathsf{f}_4 \cdot {x_2}^3\\)
- \\(\mathsf{final} = \mathsf{f} +
    \mathsf{q}_1 \cdot x_4 +
    \mathsf{q}_2 \cdot {x_4}^2 +
    \mathsf{q}_3 \cdot {x_4}^3 +
    \mathsf{q}_4 \cdot {x_4}^4\\)

The prover computes the openings:

- \\(\mathsf{q}_1(x_3)\\)
- \\(\mathsf{q}_2(x_3)\\)
- \\(\mathsf{q}_3(x_3)\\)
- \\(\mathsf{q}_4(x_3)\\)

The prover computes the commitments:

- \\([\mathsf{f}]_1\\)

Finally, the prover computes a KZG opening proof:

- \\(\pi_\mathsf{final} = \mathsf{open}(\mathsf{srs\\_g1}, \mathsf{final},
  x_3)\\)

## 4.6.7. The proof

The final proof consists of:

- The multiopen proof
    - \\(\mathsf{q1\\_opening}\\)
    - \\(\mathsf{q2\\_opening}\\)
    - \\(\mathsf{q3\\_opening}\\)
    - \\(\mathsf{q4\\_opening}\\)
    - \\(\mathsf{f\\_cm}\\)
    - \\(\mathsf{final\\_\pi}\\)
- The openings
    - \\(\mathsf{q\\_mimc}\\)
    - \\(\mathsf{mimc\\_cts}\\)
    - \\(\mathsf{quotient}\\)
    - \\(\mathsf{u\\_prime}\\)
    - \\(\mathsf{p1}\\)
    - \\(\mathsf{p2}\\)
    - \\(\mathsf{w0}_0\\)
    - \\(\mathsf{w0}_1\\)
    - \\(\mathsf{w0}_2\\)
    - \\(\mathsf{w1}_0\\)
    - \\(\mathsf{w1}_1\\)
    - \\(\mathsf{w1}_2\\)
    - \\(\mathsf{w2}_0\\)
    - \\(\mathsf{w2}_1\\)
    - \\(\mathsf{w2}_2\\)
    - \\(\mathsf{key}_0\\)
    - \\(\mathsf{key}_1\\)
- The commitments
    - \\([\mathsf{w}_0]_1\\)
    - \\([\mathsf{w}_1]_1\\)
    - \\([\mathsf{w}_2]_1\\)
    - \\([\mathsf{key}]_1\\)
    - \\([\mathsf{mimc\\_cts}]_1\\)
    - \\([\mathsf{quotient}]_1\\)
    - \\([\mathsf{u\\_prime}]_1\\)
    - \\([\mathsf{zi}]_1\\)
    - \\([\mathsf{ci}]_1\\)
    - \\([\mathsf{p1}]_1\\)
    - \\([\mathsf{p2}]_1\\)
    - \\([\mathsf{q\\_mimc}]_1\\)
    - \\([\mathsf{h}]_1\\)
    - \\([\mathsf{w}]_2\\)
