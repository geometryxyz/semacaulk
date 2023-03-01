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

## Documentation

We use `mdbook` v0.4.25 for documentation.

Install `mdbook` using [these
instructions](https://rust-lang.github.io/mdBook/guide/installation.html).

To build the Semacaulk documentation, run this in the Semacaulk project root:

```bash
mdbook serve ./docs
```

## Demo

The Powers of Tau output from Hermez Network (`11.ptau`) is already in the
repository.  To run a demo of Semacaulk with a maximum capacity of `2 ^ 11 =
2048`, first build the demo executable:

```bash
cargo build --release
```

Run the demo:

```bash
./target/release/demo 11 11.ptau
```

To run a demo with a different maximum capacity, download a larger `.ptau` file and specify the log 2 of the desired maximum capacity:

```bash
./target/release/demo 16 12.ptau
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
