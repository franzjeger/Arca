# Sync — architecture & status

**Goal:** multi-device sync with zero server. The *encrypted* vault file lives in
the user's own cloud folder (iCloud Drive / Dropbox / OneDrive); only ciphertext
ever leaves the device, so it's end-to-end encrypted by construction. Concurrent
edits are reconciled at the item level so a device never clobbers another's
changes.

## Authenticated files and concurrent writes

New unlocked saves use `SYBRVLT5`. A domain-separated HMAC-SHA256 under the
vault key covers the complete serialized body: header, encrypted item list and
purge records. Unlock and sync verify it before accepting changes, including
empty remote vaults. Per-item AEAD remains unchanged. Invalid authentication is
an error and never permission to replace a remote file.

V1–V4 files still open; saving after unlock upgrades them. A locked legacy copy
stays in the legacy format until the key is available. During migration, legacy
sync can import authenticated item ciphertext with the same master wrapping,
but cannot introduce unverified purge records or password rotations. Start by
opening and syncing the latest existing copy with the updated app. Update all
devices before continuing: older Arca builds intentionally refuse V5 files.
Legacy formats have no whole-file integrity protection; this upgrade cannot
retroactively authenticate an old file or provide protection against replay of
an entire previously valid file.

Each successful cloud upload now creates a new file, then retires only the
input files already incorporated in it. A checksum preflight alone leaves a
race between checking and replacing: two devices can both pass it and the last
upload wins. Separate immutable uploads preserve both edits even if either
process stops before another cycle. The next cycle merges any concurrent
copies. Listings consume every page; a peer retiring an input during a cycle
causes a retry.

## Built (foundation)

Desktop 0.6.0 exposes unresolved conflicts through the main status bar. New
conflict copies carry an encrypted link to their original. The comparison lets
the user choose an entire entry or individual fields; passwords, authenticator
secrets and notes stay masked until explicitly revealed. Private-key credentials
cannot be split into mismatched identity/key fields. Both reviewed revisions
must still be current at save time. Replaced inputs are retained in Trash.
Older copies without a link require manual pairing. If the original is gone,
the remaining conflict copy can be kept as an independent entry.

- **`vault-core::sync::merge(local, remote)`** — unions two decrypted item sets;
  per id, the version with the newer change-time (`max(modified_at, deleted_at)`)
  wins, ties keep local, soft-delete tombstones propagate. Pure, tested.
- **`Vault::merge_remote(&mut self, bytes)`** — decrypts a peer file's items with
  *this* vault's key (valid because a synced vault shares one stable vault key)
  and merges. A different vault's key can't decrypt → refused (`Decryption`), so
  a foreign file is never merged as garbage. Tested.
- **`VaultStore::save_synced(&mut Vault)`** — if the on-disk file changed since we
  last read/wrote it (fingerprint), merge it in before the atomic write, so a
  peer's edits survive. A **corrupt/partial** file (e.g. a cloud daemon
  mid-write) is treated as garbage and replaced (doesn't wedge saving); a
  **valid foreign** vault is refused (not clobbered). Tested.
- Wired into `persist` and the bridge writes: every save is now sync-aware.
- **`sync::Purge`** — a hard `purge_item` used to leave nothing behind, so the
  next merge with a peer that still held the item put it straight back: a
  credential deleted on purpose, resurrected. A purge now leaves an id and a
  timestamp that travel with the vault, and `apply_purges` drops the item
  wherever it reappears. An edit *after* the purge still wins, exactly as it
  does against a soft-delete tombstone. The records are never expired, because
  expiry would resurrect items on any device offline longer than the window.
  This is why the container is `SYBRVLT3`; V2 and V1 still open, and simply have
  no purges, which is the truth about them.
- **A vault from a newer Arca is refused, not replaced.** `merge_remotes` treats
  an unparseable remote as a torn upload and overwrites it, which is right for
  half a file and catastrophic for a vault written by a version that knows more
  than we do. `from_bytes` now answers `UnsupportedVersion` for any unknown
  `SYBRVLT*` container instead of `Format`. Tested.

## Google credentials, and why they are not in this repository

Drive sync needs an OAuth client. There are two, both in the same Google Cloud
project so every Arca reaches the same `appDataFolder`: a **desktop** client for
macOS/Windows/Linux, and an **iOS** client, because Google ties the redirect to
the client *type* and iOS cannot bind the loopback address a desktop client
redirects to.

The client **ids** are in `crates/vault-sync/src/drive.rs`, which is correct —
an id is public by design, it appears on the consent screen and, on iOS, inside
the app's own URL scheme.

The desktop client **secret** is not. Google's documentation is clear that an
installed-app secret is not confidential (it ships inside every binary, and PKCE
is what binds an authorization code to the process that asked for it), but a
credential in git history cannot be withdrawn — only rotated, which costs a
release. One was published that way, and has since been rotated. So
`crates/vault-sync/build.rs` supplies it at build time from, in order:

1. `ARCA_GOOGLE_CLIENT_SECRET` in the environment.
2. `~/.arca/google-client-secret` — one line, `chmod 600`, next to the updater
   key, and backed up with it.

An iOS client is a **public** client: Google issues no secret for it at all and
rejects a request that sends an empty one, so the token calls omit the field
entirely when there is none. That is pinned by a test.

**A build without the secret is a supported build.** `drive::sync_configured()`
returns false, and the desktop sign-in refuses before opening a browser rather
than walking the user to a consent page that dies at the token exchange. That is
what CI builds and what a clone of this repository builds; everything except
Drive sync works. `release-macos.sh` refuses to build without it, because a
release that silently cannot sync is a bad thing to discover after shipping.

**Adding the secret to a checkout that has already been built** needs one extra
step. `build.rs` only asks cargo to watch the file when it already exists —
`rerun-if-changed` on a missing path means "rerun always", which would rebuild
this crate and everything above it on every cargo invocation. So the first build
after creating `~/.arca/google-client-secret` reuses the sync-less artifacts
unless you force it:

```bash
touch crates/vault-sync/build.rs
```

`cargo clean -p vault-sync` does **not** do it — it reports `Removed 0 files` and
leaves the build-script output in place. The build now warns when no secret is
found, so a sync-less build says so at the time rather than at sign-in.

## Rotating the desktop client secret

Needed if the live secret is exposed — published to a public repository, leaked
from a machine, or pasted somewhere it will be retained. The value already in
this repository's history was rotated away and is dead; these are the steps for
doing it again.

**Rotation invalidates every installed copy, not just the leak.** The secret is
compiled into the binary, so an Arca built before the rotation still presents the
old one and Google refuses its token exchange and its refresh. Sync stops for
those users — silently, at the moment their access token next expires, which is
not when they were told to expect it. Rotation therefore costs a release, and
the release has to reach people before the old secret is withdrawn.

That ordering matters more here than it looks: in-app updates do not currently
work (see [RELEASING.md](RELEASING.md) — the manifest endpoint is not
anonymously readable, and there is no published Linux or Windows artifact), so
"reach people" means they download and install by hand. Withdrawing the old
secret the same day breaks everyone who has not.

1. **Create the new secret** in Google Cloud Console ▸ APIs & Services ▸
   Credentials, on the existing **desktop** OAuth client. Keep the client id:
   changing it changes the consent screen and the `appDataFolder` the tokens
   address, which is a migration, not a rotation.
2. **Put it in `~/.arca/google-client-secret`** (one line, `chmod 600`), and
   update the backup that lives beside the updater key.
3. **Force the rebuild.** `build.rs` only watches the file once it exists, so an
   existing checkout reuses the old build-script output:
   ```bash
   touch crates/vault-sync/build.rs
   ```
4. **Confirm the new secret is the one baked in** before shipping — a release
   built from a stale build-script output looks identical and fails at sign-in:
   ```bash
   cargo build -p vault-sync 2>&1 | grep -i 'client secret'   # no "compiled out" warning
   ```
5. **Cut and publish the release**, and give people time to install it. Until
   updates work on their own, say so in the release notes rather than assuming.
6. **Only then delete the old secret** in the Cloud Console. Google keeps both
   valid while they coexist, which is what makes the overlap possible.

If the exposure is urgent enough that waiting is not acceptable, delete the old
secret first and accept that every installed copy loses sync until it is
updated. That is a deliberate trade, and the release notes should say which one
was made.

Nothing here touches the vault. The client secret authorises Arca to *talk to
Drive*; the vault's contents are encrypted with the master password before they
ever reach it, so a leaked or rotated secret does not expose a single stored
credential. What it exposes is the ability to impersonate Arca's OAuth client on
a consent screen, which is a phishing and quota problem, not a decryption one.

## Not yet built (required before enabling user-facing sync)

These are prospective — they only bite once the vault actually lives in a shared
folder, which needs the path-config UI below. Flagged by an adversarial review.

1. **Vault-path configuration + onboarding UX.** Let the user point Arca at a
   vault in a cloud folder, and — critically — choose *"use the existing vault
   here"* vs *"create new"*. Two independent `create`s in the same folder mint
   different vault keys and can never reconcile (each refuses the other). The
   onboarding flow must prevent that.
2. **Same-item conflict handling.** Merge is last-writer-wins per item on the
   wall clock, so two devices editing the same item concurrently silently drop
   the older edit — and clock skew can pick the wrong winner. Add a conflict
   copy (keep both) rather than discarding, at least for same-item collisions.
3. **Cross-process lost update.** `save_synced`'s read→merge→write isn't atomic
   across writers; a peer/cloud write landing mid-save is lost (never a *torn*
   file — the atomic rename guarantees a complete old-or-new vault, just a lost
   update). Consider a file lock or a re-check-after-write.
4. **Header changes over sync.** `merge_remote` keeps the local header. If master
   password rotation (`change_master_password`, currently unwired) ships, a
   stale-header device would revert the rotation on its next save. Add a header
   version/epoch and take the newer header before wiring password change.
5. **Status/refresh UX.** Show sync state; refresh the item list when a
   background merge brings in a peer's changes.
