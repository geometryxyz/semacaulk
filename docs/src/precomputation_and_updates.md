# Precomputation and updates

Caulk employs a precomputation step in order to make the use of it sublinear in
the group size. This allows neatly separating the membership proof part of
Semacaulk from the nullifier computation, while allowing to blind the
precomputed membership proof differently at each use.

When a group is updated, precomputation is needed again, so there are a few
options as to how to avoid many precomputations in frequently updated groups.
These include storing a history of valid group commitments or batching
insertions and updating the precomputation after some predefined time slot.
This also opens the possibility to use a centralised, but verifiable, service
to compute these for them, since a unique feature of the precomputation in
Caulk is that a batch can be computed even more cheaply. There are, of course,
privacy implications when using a service, but these can also be mitigated
using several techniques and trade-offs.

Additionally, the precomputation done in Caulk is amenable to efficient updates
when the group changes, justifying a higher cost for the initial
precomputation.

## Precomputed data

Precomputed data consists of the following:

1. \\(\mathsf{mimc\\_cts}\\)
2. \\(\mathsf{mimc\\_cts\\_coset\\_evals}\\)
3. \\(\mathsf{zh\\_inverse\\_coset\\_evals}\\)
4. \\(\mathsf{q\\_mimc}\\) 
5. \\(\mathsf{q\\_mimc\\_coset\\_evals}\\) 
6. \\(\mathsf{l0\\_coset\\_evals}\\) 
7. \\(\mathsf{w_1\\_mapping}\\) 
7. \\([{\mathsf{W}_1}^{(i)}]_2\\) for all indices \\(i \in I\\)
8. \\([{\mathsf{W}_2}^{(i)}]_2\\) for all indices \\(i \in I\\)

The only parts of the precomputed data which rely on the secret index \\(i\\),
which denotes the secret position of the prover's identity commitment in the
accumulator, are \\([{\mathsf{W}_1}^{(i)}]_2\\) and \\([{\mathsf{W}_2}^{(i)}]_2\\).

The Caulk+ paper defines:

- \\({\mathsf{W}_1}^{(i)} = (C(X) - v_i) / (X - \omega^i)\\)
- \\({\mathsf{W}_2}^{(i)} = Z_H(X) / (X - \omega^i)\\)

## Updating commitments to \\(\mathsf{W}_1^{(i)}\\)

For many of Semacaulk's use cases, users insert new items into the accumulator,
and do not update existing items. As such, this section will only discuss
how to update commitments to \\(\mathsf{W}_1^{(i)}\\) when the accumulator
changes at an index \\(j\\) which is different from that of the user's entry
\\(i\\).

We can efficiently update \\([{\mathsf{W}_1}^{(i)}]_2\\) using the technique
described in [TADBFK20, section 3.4.2](https://eprint.iacr.org/2020/527.pdf),
where \\(i \neq j\\).

When an element at \\(j\\) is updated and \\(i \neq j\\), and the new element
is \\(v_j = v_\mathsf{zero} + \delta\\), the new accumulator is:

\\(C(X) - L_j(X) \cdot v_\mathsf{zero} + L_j(X) \cdot v_j\\)

\\(= C(X) + L_j(X) \cdot (v_j - v_\mathsf{zero})\\)

\\(= C(X) + L_j(X) \cdot \delta\\)

\\({\mathsf{W{new}}_1}^{(i)}\\) is therefore:

\\(\frac{C(X) - v_i + L_j(X) \cdot \delta}{X - \omega^i}\\)
\\( = {\mathsf{W}_1}^{(i)} + \frac{L_j(X)}{X - \omega^i} \cdot \delta\\)

To use the homomorphic properties of KZG commitments, we need to
compute \\([\frac{L_j(X)}{X - \omega^i}]_2\\), multiply it by \\(\delta\\), and
add it to \\([{\mathsf{W}_1}^{(i)}]_2\\). Yet we must do this with lower than
the \\(O(n)\\) cost of a full KZG \\(\mathsf{commit}\\) operation.

TADBFK20 section 3.4.2 describes how to do so without performing
\\(\mathsf{commit}\\) at all. This document will be updated to elaborate on the
method.

<!--
1. Compute \\(a_j = g \cdot (A(\tau) / (\tau / \omega^j))\\) for each \\(j \in [0
   \ldots t]\\) during the setup.
   Since \\(\tau\\) is unknown but we have access to \\(g \cdot \tau\\), we can
   rewrite this formula as:

   \\(a_j = g \cdot ((\tau^t - 1) / (\tau / \omega^j))\\)

   \\(= g \cdot (\frac{\tau^t}{\tau - \omega^j} - \frac{1}{\tau - \omega^j})\\)

   \\(= (g \cdot \frac{\tau^t}{\tau - \omega^j}) / (g \cdot \frac{1}{\tau - \omega^j})\\)

   \\(= (g \cdot \frac{\tau^t}{\tau - \omega^j}) \cdot (g \cdot (\tau - \omega^j))\\)

2. Compute \\(w_{i,j} = {a_i} \cdot {v_i} {a_j} \cdot {v_j}\\)
3. Compute \\(u = {w_{i,j}} \cdot {\frac{1}{t\omega^{-j}}}\\).
4. Compute \\([{\mathsf{W{new}}_1}^{(i)}]_2 =\\)
    \\([{\mathsf{W}_1}^{(i)}]_2 \cdot u \cdot \delta\\)

TODO: test this in code!
-->

## Updating commitments to \\(\mathsf{W}_2^{(i)}\\)

For use cases where users do not update their own entries (i.e. \\(i \neq j\\)),
there is no need to update the precomputed commitments to
\\(\mathsf{W}_2^{(i)}\\).

<!--
### \\(\mathsf{mimc\\_cts}\\)

A polynomial over the multiplicative subgroup which evaluates to the MiMC7
round constants at each root of unity. The subgroup size is the number of MiMC7
rounds defined in
[4](./cryptographic_specification.html#4-the-mimc7-hash-function).

### \\(\mathsf{mimc\\_cts\\_coset\\_evals}\\)

We first compute a polynomial which evaluates, at each root of unity in the
subgroup domain, to a vector (of the size of the subgroup) consisting of the
evaluations of the MiMC7 round constants, padded by dummy values. Next, we
perform an FFT over the coset of the extended domain on the coefficients of
this polynomial to obtain \\(\mathsf{mimc\\_cts\\_coset\\_evals}\\).

### \\(\mathsf{zh\\_inverse\\_coset\\_evals}\\)

A vector of \\(\mathbb{F}_r\\) elements that are the field inversions of the
(coefficients of the vanishing polynomial over the coset??? TODO)

### \\(\mathsf{q\\_mimc}\\) 

A polynomial whose evaluations at the roots of unity over the subgroup domain
of size 128 are \\(n = 91\\) `1` values, followed by zeroes. It represents the
\\(\mathsf{q\\_mimc}\\) [selector column](./circuit_and_gates.html).

### \\(\mathsf{q\\_mimc\\_coset\\_evals}\\) 

A vector of \\(\mathbb{F}_r\\) elements that are the evaluations of the
\\(\\mathsf{q\\_mimc}\\) polynomial coefficients over the coset?? (TODO) 

### \\(\mathsf{l0\\_coset\\_evals}\\) 

Where \\(L_0\\) is the 0th Lagrange basis polynomial over the subgroup
evaluation domain, this is a vector of its evaluations over the coset (?? TODO)

### \\({\mathsf{W}_1}^{i}\\) 

As defined in the [Caulk+ paper, section 3](https://eprint.iacr.org/2022/957.pdf).

### \\({\mathsf{W}_2}^{i}\\) 

As defined in the [Caulk+ paper, section 3](https://eprint.iacr.org/2022/957.pdf).
-->
