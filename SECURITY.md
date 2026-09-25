# Security

## Status: independent audit outstanding

**An independent cryptographic audit and a formal threat model are REQUIRED
before this software is used to protect real-world secrets.** The design below
follows established practice and composes only well-reviewed cryptographic
crates, but "uses good building blocks" is not the same as "is secure." Until a
qualified third party has reviewed the implementation, treat this as a
demonstration/foundation, not a product.

A first-draft **threat model** now exists at [`THREAT_MODEL.md`](./THREAT_MODEL.md)
(assets, trust boundaries, adversaries, per-threat mitigations, and accepted
residual risks). It is the *input* to an audit, not a replacement for one: the
independent third-party audit remains **outstanding** and cannot be self-closed
by this project.

## Design goals

- **Zero-knowledge, local-first.** No plaintext, master password, or master key
  ever leaves the device or is written to a log. There is no server.
- **No analytics telemetry.** Network features include optional Google Drive sync,
  signed-update checks, breach-prefix queries and WebAuthn related-origin
  validation. These requests reveal connection metadata to their providers.
- **No secrets in errors.** Error types describe *what kind* of operation failed,
  never the data involved (see `vault-core::Error`, `CmdError`). Decryption
  failures are deliberately indistinct ("wrong password or tampered data").
- **Single product tier.** Every feature is available to every user; there is no
  licensing or feature gating anywhere in the code.

## Cryptography

New unlocked saves use `SYBRVLT5`: a domain-separated HMAC-SHA256 under the
vault key authenticates the complete container body, including purge records,
password wrapping and the encrypted item list. Unlock and sync verify it before
accepting that state. Legacy files remain readable but lack this protection;
see [migration and concurrent sync](docs/SYNC.md#authenticated-files-and-concurrent-writes).

Composed entirely from [RustCrypto](https://github.com/RustCrypto) crates — no
custom primitives are implemented.

| Concern            | Choice                                                    |
| ------------------ | --------------------------------------------------------- |
| KDF                | **Argon2id** (`argon2`), default m=64 MiB, t=3, p=4       |
| Master key         | 256-bit, derived from master password + 32-byte random salt |
| Vault key          | random 256-bit, **wrapped** with the master key           |
| Wrapping / items   | **XChaCha20-Poly1305** AEAD (`chacha20poly1305`)          |
| Per-item encryption| each item sealed individually; its UUID bound as **AAD**  |
| Randomness         | OS CSPRNG (`getrandom`)                                   |
| Secret comparison  | constant-time (`subtle`)                                  |
| Memory hygiene     | keys & plaintext zeroized on drop (`zeroize`)             |

- **KDF parameters are versioned** in a cleartext header so they can be raised
  over time; the wrap binds those parameters as AAD, so an attacker cannot
  substitute weaker parameters and still authenticate.
- **Wrong password / tampering** are caught by AEAD authentication (Poly1305 tag
  verification is constant-time). The vault never "partially" unlocks.
- **At-rest format** = `"SYBRVLT5"` magic + cleartext header (public KDF params +
  wrapped keys) + a list of individually-sealed items. The header carries a
  `format_version` so the layout can evolve. Each encrypted **item payload** is
  serialized with **CBOR** (self-describing, variant-tagged by name), so the
  `VaultItem` schema can gain or reorder variants without misreading existing
  data — a positional codec such as bincode could not guarantee this. (The thin
  outer container framing remains bincode.)

## Persistence & keychain

- **Atomic writes**: vault bytes are written to a sibling temp file, fsynced,
  then `rename`d over the target (directory fsynced on Unix). A crash mid-write
  can never produce a torn vault. Temp files are created `0600` on Unix.
- **Quick/biometric unlock**: a random 256-bit *device key* is stored in the OS
  keychain (macOS Keychain / Windows Credential Manager / Linux Secret Service)
  using platform APIs. Protected macOS enrollments use `SecAccessControl` in the
  data-protection keychain; existing Mac installs upgrade through Settings.
  See [migration and verification](docs/KEYCHAIN-HARDENING.md).
  A device-key-wrapped copy of the vault key lives in
  the header. **The master password is never stored**; deleting the keychain
  entry disables quick-unlock.

## Application behavior

- **Sensitive-action confirmation:** Linux requires the current master password
  before plaintext export, password rotation or vault replacement. macOS/Windows
  use system verification. Checks run off the UI thread and outside the vault
  mutex; authorization is rejected after locking/reunlocking, replacement or a
  change to the authenticated header. This does not change Linux quick unlock.
- **Conflict resolution:** previews mask secrets until explicitly revealed;
  private-key identities are selected as complete units. Saving checks both
  reviewed revisions, retains replaced inputs in Trash and rolls back in-memory
  mutations if persistence fails. Conflict links and resolution markers are
  encrypted as part of each item.
- **Secret access is scoped to the active view.** Desktop lists contain metadata;
  reveal/editor commands fetch secrets on demand, while normal secret copying
  happens in Rust. iOS detail views obtain their payload through the FFI.
  Desktop locking discards unsaved editor drafts and closes editors; queued
  draft effects cannot restore the cleared store. Drafts are never written to
  disk. Dropping references does not guarantee erasure of UI heaps.
- **Auto-lock** on idle (configurable timeout) and on window blur; locking drops
  and zeroizes the in-memory vault key and plaintext items.
- **Clipboard auto-clear** after a configurable timeout (default 30 s), and a
  clear request on lock, only if the clipboard still holds the value we wrote.

## Known limitations and residual risks

These are explicitly **not** mitigated yet and must be part of the threat model:

- **Not audited.** No third-party cryptographic or implementation review.
- **Host trust.** A compromised OS, malware running as the same user, or a
  kernel-level attacker can read process memory and defeat any local password
  manager. Symmetric keys use best-effort locked memory (`vault-secmem`);
  item plaintext and UI copies are not all page-locked. `zeroize` reduces but
  does not eliminate residual-secret exposure.
- **Webview exposure.** Revealed secrets and TOTP codes live transiently in the
  webview's JS heap; copied secrets live in the OS clipboard for the clear
  window. The production CSP in `tauri.conf.json` restricts styles to `'self'`
  and does not allow `'unsafe-inline'`.
- **Clipboard.** Copies go through a long-lived owner thread holding a single
  `arboard` instance for the app's lifetime, so the X11/Wayland selection stays
  served until paste or auto-clear (which wipes only if the value is unchanged).
  X11 and Wayland have required CI smoke tests using isolated display servers.
  The build enables `arboard`'s Wayland data-control backend, with X11 fallback
  on compositors that do not support that protocol. Interactive paste between
  real applications on supported desktops remains a release acceptance check.
- **Metadata & length.** Items are encrypted individually, so anyone with read
  access to the vault file can count entries and see each ciphertext's
  approximate size. The per-item payload is **self-describing** (CBOR), so field
  and variant names (`type`, `username`, ...) are present inside each blob and
  ciphertext length correlates slightly with which variant and fields are
  populated. This is all inside the AEAD and leaks nothing without the key — but
  field names are **not** secret, and the format does not pad to hide sizes.
- **KDF tuning.** Defaults (64 MiB/t=3/p=4) are reasonable but should be tuned
  to target hardware and periodically re-benchmarked.
- **Browser autofill.** Origin checks, authenticated native-host communication,
  optional consent and passkey operations are implemented. Browser/OS compromise
  remains outside their protection.
- **No recovery.** By design, a forgotten master password means unrecoverable
  data without another valid unlock mechanism. Encrypted backups and password
  history provide data recovery, not master-password recovery. There is no key
  escrow. Older backups may require an older master password.

## History and backup retention

Previous login/Wi-Fi passwords are encrypted with their item and zeroized on
Rust drop. Up to 20 entries are retained; sync preserves history from both
sides. Old passwords remain secrets, including after restoration. Hard-purging
an item removes its history from the current vault but not from already-made
snapshots or external backups. Copies need deliberate retention/deletion.

Desktop automatic backups are opt-in and contain only encrypted vault bytes.
Writes are atomic and checked by reading them back. Full cryptographic
verification additionally needs the backup password (Settings → Verify only).
A configured folder on the same disk does not protect against disk loss.

The [release plan](docs/RELEASE.md) records required cross-platform checks and
the scope of the independent audit. That audit has not been performed here.

## Reporting

Report suspected vulnerabilities privately to **security@sybr.no**. Please do not
open public issues for security reports.
