#!/usr/bin/env bash

cargo check
cargo test

cargo check --no-default-features
cargo test --no-default-features --lib

cargo check --no-default-features --features="alloc"
cargo test --no-default-features --features="alloc" --lib
