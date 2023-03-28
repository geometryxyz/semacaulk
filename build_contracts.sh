#!/usr/bin/env bash

rm -rf src/contracts/out
cargo clean -p semacaulk
forge clean --root src/contracts/
forge build --root src/contracts/
cp src/contracts/out/Verifier.sol/Verifier.json src/contracts/
cp src/contracts/out/Semacaulk.sol/Semacaulk.json src/contracts/
