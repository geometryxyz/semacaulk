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
./target/release/setup 12 12.hex lagrangeComms_12
```

Now, run:

```bash
./target/release/demo 12 12.hex lagrangeComms_12
```

A future release will integrate implement the functionality of
`export-ptau-points` into the `setup` executable, so a separate step will not
be needed.

### CLI client

For testing and demonstration purposes, we also include a CLI client binary.

To deploy a Semacaulk contract (supporting a capacity of 2 ^ 11), first run
`anvil` or any Ethereum node at `127.0.0.1:8545` or use the `--rpc` flag to
specify a node.

Make sure you have built the `client` binary:

```bash
./build_contracts.sh && \
cargo build --release --bin client
```

Run the `client deploy` subcommand. Make sure that the `-l` flag is set to the
correct value!

```bash
./target/release/client deploy --ptau ./11.ptau --rpc http://127.0.0.1:8545 -l 11
```

The contract address will be printed to the console. With the default private
key on a fresh RPC node, the address should be `0x5fbdb2315678afecb367f032d93f642f64180aa3`.

To insert an identity commitment (where the identity nullifier is `1` and the
identity trapdoor is `2`, run `client insert`:

```bash
./target/release/client insert --ptau 11.ptau -c 0x5fbdb2315678afecb367f032d93f642f64180aa3 --rpc http://127.0.0.1:8545 -n 0x1 -t 0x2 -l 11
```

The client will print the transaction hash and the index of the insertion.

```
Transaction hash:
0x634bfbfd1984fd27205c2995860572703d8f2b92face4cf7b827e70f33009617
Identity index:
0x0000000000000000000000000000000000000000000000000000000000000000
```

## Documentation

We use `mdbook` v0.4.25 for documentation To build the documentation, navigate
to the `docs` directory and run:

```bash
mdbook serve
```
