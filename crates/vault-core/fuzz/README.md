# Vault item fuzz target

`item` feeds arbitrary bytes to the CBOR decoder for `VaultItem`. It can find
panics in that decoding path; it does not prove that all malformed vault files
are safe. Keep discovered crash inputs for investigation and regression tests.

This is a separate Cargo workspace so libFuzzer and its build requirements do
not become dependencies of the desktop app or its normal test suite.

Check that the target compiles:

```sh
cargo check --locked --manifest-path crates/vault-core/fuzz/Cargo.toml
```

To fuzz, install `cargo-fuzz` and a nightly Rust toolchain, then run from
`crates/vault-core`:

```sh
cargo +nightly fuzz run item -- -max_total_time=60
```

Generated corpora, crash artifacts, coverage and build output are ignored.
