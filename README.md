# Arca

A cross-platform password manager with an identical UI on **macOS, Windows, and
Linux**. All security-critical logic lives in a small Rust core built only from
well-reviewed crates; the desktop app is a [Tauri 2](https://v2.tauri.app/) shell
over it, and the browser extension talks to that app over a local bridge.

Current source version: **0.6.2** — see [`CHANGELOG.md`](./CHANGELOG.md)

> ⚠️ **Not independently audited.** The cryptography composes well-reviewed
> RustCrypto crates and there is a written threat model, but no third party has
> reviewed this code. Read [`SECURITY.md`](./SECURITY.md) and
> [`THREAT_MODEL.md`](./THREAT_MODEL.md) before trusting it with real secrets.

## What it does

**Vault**
- Logins, passkeys, SSH keys, Wi-Fi networks (with a join QR code) and secure notes
- Live TOTP codes with a countdown, from a Base32 secret or an `otpauth://` URI
- Strong password generator; weak/reused audit; breach check against
  HaveIBeenPwned using k-anonymity (only a 5-character hash prefix ever leaves
  the device)
- Find and merge duplicates; soft delete with a Trash you can restore from
- Change the master password without re-encrypting every item

**Unlock**
- Master password (Argon2id), or quick unlock via the OS keychain gated by
  Touch ID / Windows Hello
- Auto-lock on idle and on window blur; clipboard auto-clear
- Locking discards unsaved editor changes. Save generated passwords before
  switching apps when lock-on-blur is enabled.

**In the browser** (Chrome, Brave, Edge, Firefox)
- Autofill matching logins, with the password released only for a matching
  origin while the vault is unlocked
- Offer to save new or changed logins on submit
- Passkeys: Arca acts as the authenticator for ceremonies the user actually
  started. See [`docs/PASSKEYS.md`](./docs/PASSKEYS.md).

**Sync and safety**
- End-to-end encrypted sync through your own Google Drive app folder: Google
  only ever holds ciphertext. See [`docs/SYNC.md`](./docs/SYNC.md).
- Automatic local snapshots before every save, an off-device encrypted backup,
  and restore. See [`docs/BACKUP.md`](./docs/BACKUP.md).
- CSV import (Safari/Apple Passwords, Chrome, Brave, Edge, Firefox, generic) and
  a biometric-gated CSV export

**Elsewhere**
- Built-in ssh-agent: vault SSH keys serve `ssh` and `git` over a Unix socket
  (macOS/Linux) or the OpenSSH named pipe (Windows), signing in-process so the
  private key never reaches disk

## Platform status

| Platform | State |
| --- | --- |
| **macOS** | Daily driver. Signed + notarizable releases, see [`docs/RELEASING.md`](./docs/RELEASING.md). |
| **Windows** | Working, including the ssh-agent named pipe. Built in CI. |
| **Linux** | First run by a human on 2026-08-01, on CachyOS (KDE Plasma on Wayland, NVIDIA): builds from source, unlocks, saves, snapshots. The `.deb`/`.rpm` ship the native-messaging host and register it for Chromium-family browsers and Firefox, asserted by the `linux-package` job; the host-to-app handshake is verified, in-page autofill is not yet. Unlock without the master password with a USB key ([docs/KEYFILE-UNLOCK.md](docs/KEYFILE-UNLOCK.md)) — Linux's stand-in for Touch ID; the same stick also works on macOS and Windows. Still no Linux release artifact: build from source. |
| **iOS** | Running on a phone since 2026-07-28: unlock, Face ID, search, add/edit/delete logins, passkey registration, an AutoFill provider, and Google Drive sync both ways (C ABI v16). Sideloaded — no TestFlight. See [`docs/IOS.md`](./docs/IOS.md). |
| **Android** | Not built. |
| **System-wide macOS AutoFill** | Native passwords and passkeys, including registration, are embedded in locally development-signed builds. Requires local provisioning and enabling Arca in system settings. See [macOS setup](apps/macos/README.md) and [manual acceptance checks](docs/MACOS-PASSKEYS.md). |

**Release downloads (when published):** [GitHub releases](https://github.com/franzjeger/Arca/releases/latest). Source version and published installers may differ; check the release version before installing.
This repository starts with a reviewed source snapshot and fresh history; the private predecessor remains an archive. No release is implied by the import.
The macOS release process signs, notarizes and staples Apple Silicon installers.
Windows source builds and tests run in CI; this does not imply a published
Windows installer. Check the release's assets for your OS and architecture;
build from source if no matching installer is listed.

Auto-update works from 0.3.0 onward. Copies older than that were only ever
built on one machine and have to be replaced by hand
([`docs/RELEASING.md`](./docs/RELEASING.md)).

## Architecture

```
crates/
├── vault-core/       Pure Rust, no I/O. Crypto, data model, TOTP, passkeys,
│                     password generation, merge, dedupe, breach hashing.
├── vault-store/      Atomic single-file persistence, rotating snapshots,
│                     OS-keychain quick unlock.
├── vault-ffi/        C ABI over the core, for native platform integrations
│                     (Swift). ABI v16, including sync and locked read-modify-write.
├── vault-secmem/     mlock'd buffers for key material.
├── vault-appgroup/   macOS App Group container resolution (one isolated
│                     Objective-C call, so the app crate stays unsafe-free).
└── vault-sync/       End-to-end encrypted sync: the Google Drive client, the
                      OAuth token calls, and the pull→merge→push engine, over
                      traits so each platform supplies its own storage and UI.
apps/
├── desktop/          Tauri 2 app
│   ├── src-tauri/      Rust shell: commands, state, sync glue, bridge,
│   │                   ssh-agent.
│   └── src/            React + TypeScript + Tailwind three-pane UI.
├── apple-shared/     VaultBridge.swift — the Swift side of vault-ffi, shared
│                     verbatim by the macOS and iOS targets.
├── macos/            Native password/passkey AutoFill provider and test harness.
└── ios/              SwiftUI app + AutoFill extension, built in macOS CI.
extension/
├── chromium/         Manifest V3 (Chrome/Brave/Edge) + a Firefox manifest.
└── native-host/      Rust native-messaging bridge to the desktop app.
```

**Key hierarchy:** master password ──Argon2id──▶ master key
──XChaCha20-Poly1305(unwrap)──▶ random 256-bit *vault key* ──per-item AEAD──▶
each item. The master password is never stored; only *wrapped* keys are
persisted, which is why changing it does not re-encrypt your data and why a
forgotten master password is unrecoverable.

## Prerequisites

- **Rust** via `rustup`. The exact version is pinned by
  [`rust-toolchain.toml`](./rust-toolchain.toml) and installed for you on the
  first `cargo` command, so CI and every machine build with the same compiler
  and the same `rustfmt`. The core, store and native host build with `cargo`
  alone.
- **Node.js** ≥ 22 + npm, for the desktop frontend and browser tests.
- **Platform toolchains for Tauri 2:**
  - **macOS:** Xcode Command Line Tools (`xcode-select --install`) for Tauri.
    The native AutoFill provider and Swift tests also need full Xcode and
    XcodeGen. After installing or upgrading Xcode, run
    `xcodebuild -runFirstLaunch` to install its required components.
  - **Windows:** WebView2 runtime (preinstalled on Win 11) + MSVC Build Tools.
  - **Linux (Debian/Ubuntu):**
    ```bash
    sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
      libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
      libdbus-1-dev xdg-utils
    ```
  - **Linux (Arch/CachyOS):**
    ```bash
    sudo pacman -S --needed webkit2gtk-4.1 base-devel curl wget file \
      xdotool openssl libayatana-appindicator librsvg dbus xdg-utils
    ```
    (D-Bus / Secret Service — `libdbus-1-dev` or `dbus` — is needed for keychain
    quick unlock.)

## Build and test

Ensure `~/.cargo/bin` precedes Homebrew in `PATH`: Homebrew's standalone Rust
does not select the compiler pinned in `rust-toolchain.toml`. Check with
`command -v cargo` and `rustc --version` before running the checks.

On macOS, keep the checkout and build output outside iCloud-synced Documents
or Desktop folders. Offloaded build files and coordinated Xcode project reads
can stall a build. `CARGO_TARGET_DIR` can move Rust output to a local directory
(for example, `export CARGO_TARGET_DIR="$HOME/Library/Caches/arca-target"`);
the Xcode project itself should also be in a local checkout.

```bash
cargo test --workspace --locked         # all Rust crates, including desktop
cargo clippy --workspace --all-targets --locked -- -D warnings
cd apps/desktop && npm ci && npm test   # frontend component tests
```

The suites cover Rust, frontend components, browser-extension behavior and
real Chromium flows.
`vault-core` has no I/O and is the
security-critical surface: its tests cover encrypt/decrypt round-trips,
wrong-password failure, AEAD tamper detection, KDF determinism, TOTP RFC 6238
vectors, the on-disk item codec, sync merge and quick-unlock key drift.

Tests needing a real OS secret store are `#[ignore]`d (they may prompt):

```bash
cargo test -p vault-store -- --ignored
```

### The smoke test gate

```bash
scripts/smoke-test.sh          # Rust tests, frontend build, component tests
scripts/smoke-test.sh --full   # + OS keychain tests + a live bridge round-trip
```

`scripts/install-app-macos.sh` **refuses to install without it**. That gate
exists because builds went out that passed partial checks while the actual user
flow was broken.

## Run the desktop app

```bash
cd apps/desktop
npm install
npm run tauri dev        # hot-reload, any OS
```

On macOS, install a locally signed build with `scripts/install-app-macos.sh`.
The installer requires Node.js 22+, Rust, Xcode, XcodeGen and local development
signing profiles. See [macOS setup](apps/macos/README.md). It installs locked
frontend dependencies and Playwright Chromium automatically, runs the full smoke
suite, and checks the running app and native-host versions after installation.
The previous app is restored if that final check fails.
For a build other machines can run, see [`docs/RELEASING.md`](./docs/RELEASING.md).

The vault lives in the per-user app-data directory as `default.vault`, e.g.
`~/Library/Application Support/no.sybr.vault/` on macOS, with snapshots
alongside it in `snapshots/`.

## Browser extension

Load `extension/chromium/` unpacked, then install the native-messaging host so
the extension can reach the app. Per-browser instructions are in
[`extension/README.md`](./extension/README.md). The app must be **unlocked** for
autofill to return anything.

## Continuous integration

[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs on push and PR:

- **`test`** on Linux, Windows and macOS: frontend type-check + bundle, frontend
  component tests, `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo test --workspace`.
- **`linux-smoke`**: the `#[ignore]`d real-OS tests, so the `arboard` clipboard
  path actually executes on **X11** (Xvfb) and **Wayland**
  (headless `sway`), plus a best-effort keychain test against gnome-keyring.
- **`linux-package`**: builds the `.deb` and `.rpm` and asserts they carry the
  native-messaging host and its manifests, that each manifest points at the
  installed path rather than a build directory, and that the packaged host
  answers the handshake. Nothing else here runs `tauri build`, so without it a
  bundle can ship the app alone and still be green.

CI cannot do an interactive cross-application paste. That stays a manual
acceptance check on real X11 *and* Wayland before shipping to Linux users.

Releases require a successful manual full CI run for the exact commit, including
Linux packaging, OS smoke tests and Rust/npm dependency audits. See
[`docs/RELEASE.md`](docs/RELEASE.md) for the gate and
[`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md) for the latest local
verification and outstanding blockers.

## Security

Zero-knowledge, local-first, no telemetry. Nothing is sent anywhere except the
ciphertext you choose to sync and a 5-character password-hash prefix if you run
a breach check.

[`SECURITY.md`](./SECURITY.md) and [`THREAT_MODEL.md`](./THREAT_MODEL.md) state
plainly that an **independent third-party audit is required before real-world
use**, and list the accepted residual risks.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at
your option.

## Reliability and recovery (0.5.0)

- Password history: the last 20 login/Wi-Fi password changes, encrypted inside
  each item and synced with it. Desktop and iOS can copy or restore a selected
  password; this does not change the password at the website/network.
- Desktop: one app instance, live sync status, and settings that reflect only
  successful durable writes. Settings → About shows version and build.
- Settings → Automatic encrypted backups: select an external/backed-up folder.
  Copies run every 15 minutes while Arca is running; the last 30 plus daily copies for 30 days are retained.
  A missing drive is reported without recreating its mount point.
- Settings → Encrypted backup → Restore → Verify only: check a backup with its
  master password without replacing the current vault.
- Update every device to 0.5.0 before exchanging V5 vault files. See the
  [release and validation plan](docs/RELEASE.md), including the outstanding
  independent audit and real-device checks.

## Verification, updates and sync conflicts (0.6.0)

- On Linux, CSV export, changing the master password and replacing/restoring
  the vault require the **current** master password. macOS and Windows use
  system verification. Confirmation expires if the vault locks, is replaced,
  or its password wrapping changes while verification is pending.
- The sync-conflict button opens a comparison with choices per field, explicit
  secret reveal, and revision checks before saving. Choose the original, the
  conflict copy, selected fields, or keep both. Replaced inputs remain in Trash;
  snapshots provide an additional recovery path. Older conflict copies require
  selecting their original manually. Cryptographic credentials stay intact.
- Linux installation uses `scripts/install-linux.sh` (Python 3.11+). It requires
  a clean committed checkout, runs the tests, installs the matching app and
  native host, and verifies the running process through its authenticated bridge.
  The native host is stored in `~/.local/lib/arca`, independent of Cargo's cache.
  `install.json` records the exact commit, checksums and verification result.
- Close Arca and save unfinished edits before updating, or pass `--restart`
  to permit restarting it. `scripts/install-linux.sh --rollback --restart`
  restores the preceding app/native-host installation without reverting vault
  data. A pre-update encrypted vault copy is retained with the previous build.

The 0.6.0 changes retain the V5 file format and ABI v16. The conflict comparison
is available on desktop; iOS retains the conflict entries and their metadata.
