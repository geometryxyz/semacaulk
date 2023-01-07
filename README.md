# Semacaulk

Semacaulk is a custom prover and verifier of set membership proofs which uses
an on-chain polynomial commitment to enable cheap insertions, and techniques
which make verification no more expensive than verifying a Groth16 proof.

For a detailed specification, please refer to
[this document](https://hackmd.io/HqwnGqKXRJGT2f4V-EZFmw).

## Quick start

1. Install Rust using [these
   instructions](https://www.rust-lang.org/learn/get-started).

2. Install Foundry using [these
   instructions](https://github.com/foundry-rs/foundry#installation).

3. Clone this repository.

```bash
git clone https://github.com/geometryresearch/semacaulk.git && \
cd semacaulk
```

4. Build the contracts

```bash
./build_contracts.sh
```

5. Run tests

```bash
cargo test
```
