#!/usr/bin/env bash

rm -rf src/contracts/out
cargo clean -p semacaulk
forge clean --root src/contracts/
forge build --root src/contracts/
