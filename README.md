# Semacaulk

Semacaulk is a custom prover and verifier of set membership proofs which uses
an on-chain polynomial commitment to enable cheap insertions, and techniques
which make verification no more expensive than verifying a Groth16 proof.

For more information, please refer to [this
document](https://hackmd.io/@kwj-geometry/B1I5Ik-hi). More documentation will
be written and released soon.

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

<<<<<<< HEAD
## Demo

The setup files `11.hex` and `lagrangeComms_11` are already in the repository.
To run a demo of Semacaulk with a maximum capacity of `2 ^ 11 = 2048`, first
build the demo executable:

```bash
cargo build --release
```

Run the demo:

```bash
./target/release/demo 11 11.hex lagrangeComms_11
```

To run a demo with a different maximum capacity, first generate the `.hex` file
with
[export-ptau-points](https://github.com/geometryresearch/export-ptau-points),
then use the `setup` executable to generate the `lagrangeComms_n` file. For
example for a maximum capacity of `2 ^ 12`:

```bash
./target/release/demo 12 12.hex lagrangeComms_12
```

Now, run:

```bash
./target/release/demo 12 12.hex lagrangeComms_12
```

A future release will integrate implement the functionality of
`export-ptau-points` into the `setup` executable, so a separate step will not
be needed.

## Documentation

We use `mdbook` v0.4.25 for documentation To build the documentation, navigate
to the `docs` directory and run:

```bash
mdbook serve
```
