# Insertion

As described in the [Cryptographic
Specification](./cryptographic_specification.html#7-the-accumulator),
insertions to the accumulator are easily achieved via an elliptic curve point
multiplication and addition.

To replace a value (originally $w_i$) at index \\(i\\) with $v_i$:

$C_{\mathsf{new}}= C + L \cdot (v_i - w_i)$

where $L = \mathsf{commit}(L_i, \mathsf{srs\\_g1})$

If only insertions are allowed, $w_i$ is by definition the [nothing-up-my-sleeve
value](./cryptographic_specification.html#2-the-nothing-up-my-sleeve-value).
