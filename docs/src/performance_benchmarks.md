# Performance and Benchmarks

These benchmarks were performed on an Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
machine with 24 GB RAM. They represent the time taken for a native Rust binary
(built for `release`) to perform the precomputation and proof generation steps.

To reproduce these benchamarks, run the `demo` binary following [these instructions](./quick_start.html).

## Benchmarks

| Maximum capacity | Precomputation (ms)  | Proof generation (ms) | Precomputation + proving | SRS size (uncompressed hex) (MB) |
|-|-|-|-|-|
| `2 ** 11 = 2048` | `103` | `63` | `166` | `0.78` |
| `2 ** 12 = 4096` | `183` | `51` | `234` | `1.6` |
| `2 ** 14 = 16384` | `668` | `53` | `721` | `6.1` |
| `2 ** 16 = 65536` | `2126` | `50` | `2176` | `25` |
| `2 ** 20 = 1048576` | `24333` | `42` | `24375` | `387` |
