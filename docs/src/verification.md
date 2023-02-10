# Proof verification

At a high level, the verifier does three main steps to verify a proof
([4.6.6](proof_generation.html#466-the-proof)):

## 4.7.1. Check the gate openings

Given the opening values which the prover claims to be evaluations of the
column polynomials which correspond to the circuit, the verifier computes the
linear combination of the evaluation of the openings based on each gate
equations separated by the \\(v\\) challenge values. This linear combination
must equal the product of the quotient opening and the evaluation of the
vanishing polynomial, or the verifier will return false.

## 4.7.2. Compute the multiopen argument's `final_poly` and `final_poly_eval` values

Leveraging the homomorphic properties of KZG commitments, the verifier
reconstructs a commitment to the \\(\mathsf{final}_\pi\\) polynomial generated
in the
[prover's multiopen argument round](./proof_generation.html#466-multiopen-argument-round).

The verifier also
reconstructs \\(\mathsf{final\\_poly\\_eval}\\) which is the evaluation of
\\(\mathsf{final}\\) at the \\(x_3\\) challenge.

## 4.7.3. Perform pairing checks

A three-part pairing product is performed and the verifier returns true only if
the result is 1.

\\(A * B * C == 1\\)

where:

\\(A = e(\mathsf{a}_1 + \mathsf{a}_2 + \mathsf{a}_3, [1]_2)\\)

\\(\mathsf{a}_1 = C - [\mathsf{ci}]_1\\)

\\(\mathsf{a}_2 = \chi_2(\mathsf{srs\\_g1}[t] - [1]_1)\\)

$\mathsf{a}_3 = (\pi_\mathsf{final} \cdot x_3 - \mathsf{final\_poly\_eval} + [\mathsf{final}]_1) \cdot s$

\\(B = e(-[\mathsf{zi}]_1, [\mathsf{w}]_2)\\)

\\(C = e(-[\mathsf{final}_\pi]_1 \cdot s, [1]_2 \cdot \tau)\\)

and \\(s\\) is a separator challenge extracted from the transcript.
