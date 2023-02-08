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
7. \\({\mathsf{W}_1}^{i}\\) 
8. \\({\mathsf{W}_2}^{i}\\) 

\\({\mathsf{W}_1}^{i}\\) and \\({\mathsf{W}_2}^{i}\\) are precomputed for the 
index \\(i\\), which denotes the secret position of the prover's identity
commitment in the accumulator.

### \\(\mathsf{mimc\\_cts}\\)

A polynomial over the multiplicative subgroup which evaluates to the MiMC7
round constants at each root of unity. The subgroup size is the number of MiMC7
rounds defined in
[4](./cryptographic_specification.html#4-the-mimc7-hash-function).

### \\(\mathsf{mimc\\_cts\\_coset\\_evals}\\)

A vector of \\(\mathbb{F}_r\\) elements that are the evaluations of the MiMC7
round constants over the extended coset (TODO: define what a coset is)

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
