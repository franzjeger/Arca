# Production readiness review — 2026-09-19

Reviewed from `main` at `9cea397`. Fixes are on `codex/production-readiness`.
This review improves the release candidate; it does not establish production
approval or replace the independent audit required by SECURITY.md.

## Changes made

- Integrated the login-summary fix from PR #23. Desktop summaries have no URL;
  the native host now accepts their actual shape and attaches the requesting URL.
- Completed the native-host response schema: successful saves, bookmark imports,
  unlock requests and CLI response variants no longer fail schema validation.
  Malformed requests/replies return failure instead of panicking the host.
- Preserved passkey credential IDs through the native host so the browser can
  request the account actually selected. Unlock errors are reported as errors.
- Bounded bridge response allocation and connect/write waits. A synthetic
  authenticated loopback test verifies that no secret request is sent before
  the app's proof is checked. Tests never discover the user's running vault.
- Added a contract test that serializes the desktop's actual response types and
  decodes them using the native host's production schema, covering all current
  response variants and passkey IDs.
- Updated locked Rust dependencies: `rustls` 0.23.45 (and `rustls-webpki`
  0.103.15), `anyhow` 1.0.103, `event-listener` 5.4.2. Advisory references:
  [TLS handshake](https://rustsec.org/advisories/RUSTSEC-2026-0285.html),
  [anyhow](https://rustsec.org/advisories/RUSTSEC-2026-0190.html),
  [event-listener](https://rustsec.org/advisories/RUSTSEC-2026-0221.html).
- Updated Browserslist and baseline-browser-mapping within the existing npm
  dependency ranges, clearing the two reported npm audit findings.
- CI now audits npm as well as Cargo, uses the locked Playwright installation,
  declares read-only repository permissions and limits job duration. Cargo
  checks and Linux package builds enforce the lockfile. Node 22+ is documented
  and declared in the frontend package.
- Release validation requires a successful manual full CI run for the exact
  commit, including packaging and OS smoke jobs. Missing/skipped jobs and stale
  commits are rejected. Regression tests also pass with Python optimization,
  which could disable the old release script's `assert` checks.
- Corrected formatting failures and outdated CSP/release documentation.

## Local verification

Environment: Linux, Rust 1.97.1, Node 26.9.0, npm 12.0.2. The initial local
verification below was followed by GitHub's Node 22 cross-platform run.

| Check | Result |
| --- | --- |
| `scripts/smoke-test.sh`, with Chromium required | Passed, including installer/release checks, Rust tests, desktop build, frontend build/tests and both browser harnesses |
| Rust workspace | 352 passed, 0 failed; 3 OS-dependent tests intentionally ignored |
| Frontend components | 74 passed |
| Browser extension | All suites passed, including real Chromium autofill, password generation, password change, gesture checks, identifier-first forms and passkey flows |
| Desktop browser harness | Passed keyboard focus, nested dialogs, reauthentication, conflict comparison, password history and sync status checks |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| Linux `.deb` and `.rpm` release-mode builds | Both built; extracted packages contain executable native hosts and all three browser manifests pointing at `/usr/bin/vault-native-host`; each packaged host passed a framed handshake with isolated synthetic app data |
| `npm audit` | 0 reported vulnerabilities |
| `cargo audit` | 0 vulnerability-class advisories; 9 informational warnings remain, detailed below |
| Workflow/shell validation | YAML parsed, shell syntax and `git diff --check` passed |

Tests use synthetic data and mocked native APIs/browser bridge where applicable.
They do not certify actual biometric prompts, a physical browser/native-host
installation, live Google Drive synchronization, or installation on another OS.
Linux packages were built from the working candidate before its final commits;
they are local verification artifacts, not signed/published release installers.

## Remaining release blockers and follow-up

1. **Require full CI for each final candidate.** With the owner's authorization,
   the repository was temporarily public to use standard hosted runners.
   Run 35444449547 in the private predecessor repository (historical evidence only)
   passed all six jobs for `6237924`, including Windows/macOS/Linux tests,
   Linux packaging, iOS cross-compilation and 13 macOS Swift tests. The repository
   was then restored to private. The private-repository billing restriction
   remains; no paid allowance was enabled. The iOS build reported seven existing
   warnings (AVCaptureSession concurrency and discarded upsert results).
   Logs also exposed a tolerated Wayland failure: the clipboard dependency lacked
   its Wayland feature. This follow-up enables that backend and makes an isolated
   headless Wayland test mandatory. The new candidate needs its own full CI run;
   success on `6237924` is not evidence for later commits.
2. **Review remaining Cargo advisories.** `glib` 0.18.5 comes through Tauri's
   Linux GTK3 stack; 0.17.10 is also present in the all-target lockfile through
   robius-authentication (gio and polkit). Both report
   [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)
   (Dependabot alert 1): the `Iterator` impls of `glib::VariantStrIter` are
   unsound. Updating to the fixed 0.20+ API is not a compatible lockfile-only
   change to these dependency chains. Reachability was checked on 2026-09-30
   against the source of every crate in the lockfile that depends on glib (atk,
   cairo-rs, gdk, gdk-pixbuf, gdkx11, gio 0.17 and 0.18, gtk, javascriptcore-rs,
   libappindicator, pango, polkit, soup3, webkit2gtk) and Arca's own code:
   nothing outside glib itself makes a `VariantStrIter` or calls
   `Variant::array_iter_str`, and Arca does not use glib directly. The alert is
   dismissed as not used. Check again whenever a dependency on that side
   changes, and drop this note once Tauri's stack moves to glib 0.20.
   Seven unmaintained-package warnings remain for
   bincode, proc-macro-error and five unic crates. They have not been suppressed
   or declared harmless. Assess reachability and the upstream migration path;
   changing bincode requires explicit vault-format compatibility review.
   *Update 2026-10-02:* bincode is gone. The container is encoded by
   `vault-core/src/wire.rs`, which writes the same bytes: the released 0.6.2
   and 0.7.0 vaults encode back byte for byte, and a differential run against
   bincode 1.3.3 (20 000 random bodies, 160 000 corrupted ones) found no
   difference. The unic crates are no longer in the lockfile;
   proc-macro-error comes with glib's GTK3 stack, as above.
3. **Run physical-device acceptance.** Use the exact candidate and synthetic
   vaults for signed install/update/rollback, clipboard expiry and locking,
   protected quick unlock, browser autofill, backup/restore and concurrent
   desktop/iPhone Drive sync. Record evidence using [RELEASE.md](RELEASE.md).
4. **Complete independent security review.** Freeze the candidate, provide the
   threat model and compatibility tests, and track findings and retests. This
   review has not commissioned or completed that external work.

## Git housekeeping

- Fetched and pruned stale remote-tracking references; retained branches with
  unmerged work. The source change from PR #23 is integrated locally, but its
  remote PR remains open pending publication and CI.
- Preserved all five untracked scratch files under
  `.git/local-archive/production-readiness-2026-09-19/`. This is a local archive,
  not part of a clone or push; retain it until the scratch work is no longer
  needed. Future disposable experiments can live under ignored `target/`.
- Added a narrow ignore rule for root-level Rust `*.long-type-*.txt` diagnostics.
- Local test and audit logs are preserved in the archive's `verification/`
  subdirectory alongside this written summary in the repository.
- Changes are grouped into commits and pushed to the review branch. No release is
  published and no application or vault is replaced by this work.

## Core & FFI hardening — 2026-11-10

Reviewed and hardened on `main` after release `0.8.5` (`4e56c7d`):

- **Eliminated by-value stack copies of raw 32-byte keys:** Added
  `SymmetricKey::from_slice(&mut [u8; KEY_LEN])` in `vault-core`, which copies
  raw key bytes directly into `vault-secmem`'s `mlock`/`VirtualLock`-backed
  `LockedBox` and immediately zeroizes the source buffer in place. Updated all
  key derivation, unwrapping, keychain decoding and FFI device-key entry points.
- **Incremental AEAD item sealing (`O(changed)` vs `O(N)`):** Added
  revision-bound ciphertext caching (`SealedCache` / `CacheSlot`) in
  `vault-core`. `Vault::seal` reuses existing `AeadBlob`s for items whose
  `(id, revision)` and container format version have not changed, eliminating
  redundant CBOR serialization, XChaCha20-Poly1305 encryption and CSPRNG nonce
  churn for unchanged items. Key rotation (`rotate`, `adopt_rotation`) clears
  the cache, and `absorb` retains only entries whose post-merge `Item` is
  identical to its pre-merge state.
- **Surgical single-item rollback in `vault-ffi`:** Added `Vault::rollback_item`
  and updated FFI write paths (`vault_ffi_passkey_register`, `upsert`,
  `vault_ffi_delete_item`, `vault_ffi_restore_password_history`) to snapshot
  and restore only the single affected item instead of cloning all decrypted
  items in the vault (`vault.clone()`). Also fixed `vault_ffi_delete_item`'s
  error rollback path, which previously called `upsert_item` and advanced the
  item's revision a second time instead of restoring the original revision.
- **Modularized `vault-ffi`:** Split the 4,847-line `crates/vault-ffi/src/lib.rs`
  into cohesive modules (`lib.rs`, `passkey.rs`, `write.rs`, `sync.rs`,
  `tests.rs`) while preserving the C ABI v22 surface and extending
  `every_export_is_declared_in_the_header` to verify all modules against
  `include/vault_ffi.h`.
