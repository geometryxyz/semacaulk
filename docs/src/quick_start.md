# Quick start

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

6. Build and run the demo:

```bash
cargo build --release && \
./target/release/demo 11 11.hex lagrangeComms_11
```

Note that the files `11.hex` and `lagrangeComms_11` support up to 2048 leaf
insertions. To support a larger capacity, see the [Trusted Setup - Processing
the points](./trusted_setup.html#processing-the-points) section for
instructions on how to do so.
