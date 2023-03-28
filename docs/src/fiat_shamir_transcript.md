# The Fiat-Shamir Transcript

A transcript is an abstraction over the [Fiat-Shamir
heuristic](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic). Both
the prover and verifier use the transcript to deterministically generate
*challenge variables* based on the public inputs and proof data.

Another way to think about the transcript is as a state machine where the state
is a single data buffer. Every time a challenge is requested, it hashes the
buffer replaces the contents of the buffer with the hash, and returns a value
derived from the hash. The transcript can also be updated with abitrary data by
appending the update to the buffer.

Our transcript implements this concept with the following functions:

- `new_transcript`: returns a new transcript whose buffer is 32 bytes of `0`
  values.
- `update_with_f`: accepts a single \\(\mathbb{F}_r\\) value, converts it to a
  big-endian byte array, and appends it to the buffer.
- `update_with_g1`: accepts a single \\(\mathbb{G}_1\\) point, converts its
  \\(x\\) and \\(y\\) points to big-endian byte arrays, and appends them to the
  buffer in the aforementioned order.
- `update_with_g2`: accepts a single \\(\mathbb{G}_2\\) point, converts its
  \\(x_0\\), \\(x_1\\), \\(y_0\\), and \\(y_1\\) points into big-endian byte
  arrays, and appends them to the buffer in the aforementioned order.
- `get_challenge`: hashes the buffer with Keccak256, replaces the buffer with
  the hash, converts the hash into a \\(\mathbb{F}_r\\) element (treating it
  as a big-endian buffer), and returns the \\(\mathbb{F}_r\\) element.
