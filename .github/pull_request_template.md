## Summary

<!-- Concise explanation of what problem this solves and why this approach was chosen. -->

## Architectural & Security Impact

- [ ] **Cryptography / Container (`vault-core`):** Does this touch key derivation, AEAD framing, nonces, or CBOR schemas?
- [ ] **Memory Hygiene (`vault-secmem`):** Are all secret buffers allocated in locked memory (`LockedBox`) or zeroized in place (`Zeroizing`) without intermediate by-value copies?
- [ ] **FFI Boundary (`vault-ffi`):** Is `crates/vault-ffi/include/vault_ffi.h` in sync with all `#[unsafe(no_mangle)]` exports and `VAULT_FFI_ABI_VERSION`?
- [ ] **Persistence (`vault-store`):** Are writes crash-safe (write-temp, `fsync`, atomic rename) with rollback on failure?

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `python3 scripts/check-versions.py`
