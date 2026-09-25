# USB key unlock

**Status (unreleased):** implemented in `apps/desktop/src-tauri/src/keyfile_unlock.rs`
for Linux, macOS and Windows. Linux had no biometric the app could call, so
every unlock there was the master password — after each idle lock, before each
browser fill, for each passkey. This turns a USB stick into a possession
factor. On macOS and Windows it sits *alongside* Touch ID / Hello, and one
stick serves every computer you enroll it on.

## What the user sees

- **Settings → Unlock with a USB key → Set up…** lists removable volumes,
  asks for the master password once, and writes `Arca/<id>.arcakey` to the
  stick — or adopts the one already there, so the second, third and fourth
  computer just pick the same stick. That is the whole enrollment.
- While the stick is plugged in the vault opens without a prompt: when Arca
  starts, when the window regains focus after an idle lock, and — the part that
  matters day to day — when the browser asks. A focused password field, a
  fill, a passkey sign-in or registration: the bridge sees a locked vault and
  the stick, opens the vault, and answers. No window comes forward.
- Pulling the stick out locks the vault at once (a toggle, on by default).
  Plugging it back in opens it again.
- The master password always works, and is still required for the things that
  were already re-confirmed on Linux: exports, restores, changing the password,
  and enrolling or removing the key itself. Passkey *creation* still shows
  Arca's approval dialog.

## How it works

Two random 32-byte values per computer:

| Half | Where it lives | Travels? |
|------|----------------|----------|
| **secret** | `Arca/<id>.arcakey` on the stick (JSON: version, id, hex secret) | with the stick; shared by every computer enrolled on it |
| **pepper** + **wrap** | `keyfile-unlock.json` next to the vault, `0600` | never: not synced, not in backups; one per computer |

The device key is `HMAC-SHA256(key = pepper, msg = "arca keyfile unlock v1" ‖ secret)`.
It wraps the vault key (`Vault::wrap_vault_key`, AAD `arca/keyfile-unlock/v1`)
and the wrap is stored **in the sidecar, not in the vault header**. Unlock
reads the file, re-derives the key and unwraps (`unlock_with_wrapped_key`).

Why the sidecar and not the header's device slot: the header has exactly one
such slot, it is bincode-serialised (a new field is a format bump for every
client, iOS included), and it travels with the vault. Keeping the wrap local
means the key file coexists with Touch ID / Hello / the Linux keyring instead
of taking their slot, every computer binds the same stick with its own pepper
and wrap, and nothing about the on-disk vault format changes.

Why two halves: the vault file travels — sync, Drive, backups — but the pepper
and the wrap do not. A lost stick plus any copy of the vault must not be an
open vault; the local pepper guarantees that. A disk image without the stick
has a pepper, a wrap and no secret. They are only ever together on this
machine with the stick inserted.

The key file is the identity. Its random id is recorded in the sidecar and
checked on every read, so a stranger's file or a stale one is reported as
such. It is looked for on the platform's removable roots — a `stat` per root,
cheap enough for the once-a-second watcher:

| | Roots scanned | Enrollment list | Mounting |
|---|---|---|---|
| Linux | `/run/media/*/*`, `/media/*`, `/media/*/*` | `lsblk -J` (removable, with a filesystem) | `udisksctl mount --no-user-interaction` by filesystem UUID when the desktop has not mounted it; presence also via `/dev/disk/by-uuid` |
| macOS | `/Volumes/*` | `mount` + `diskutil info -plist` (Ejectable / RemovableMedia / not Internal) | Finder's |
| Windows | `D:\`–`Z:\` | `Get-Volume` with `DriveType = Removable`, run with `CREATE_NO_WINDOW` | the drive letter |

**Interaction with the keychain quick unlock:** none. The header slot is
untouched, so `hasQuickUnlock`, the keychain/Touch ID toggle and their
self-heal behave exactly as before. If a restored backup or a vault adopted
from a peer makes the sidecar's wrap stale, a password unlock with the stick
mounted re-wraps it (`keyfile_unlock::heal`).

**Removing** the key on one computer deletes that computer's sidecar only. The
file on the stick stays for the others; delete `Arca/` from the stick to
retire it everywhere. Removing never touches the vault.

## Failure modes, by error code

| Code | Meaning | What the UI does |
|------|---------|------------------|
| `keyfile_missing` | enrolled stick not plugged in / file gone | lock screen hint; password field |
| `keyfile_stale` | the sidecar's wrap no longer opens this vault (restore, peer's copy) | "unlock with your master password once to repair it" |
| `keyfile` | wrong or damaged file, mount failure, config unreadable | message names the cause |
| `keyfile_not_enrolled` | configure/unlock with nothing set up | n/a (UI hides the controls) |

## Security notes (feeds THREAT_MODEL.md T15)

- A possession factor with **no user-presence test**. Laptop + stick together
  = open vault. The mitigation is behavioural (do not keep them in the same
  bag) and the removal lock.
- Same-user code running while the stick is inserted can read both halves —
  the T9 residual, unchanged.
- The key file is deliberately not hidden: a FAT stick has no permissions
  anyway, and the file is useless without the pepper.
- Neither half is a key on its own, so a stick that is lost, copied or imaged
  reveals nothing about the vault; `revoke` deletes the sidecar, so a copy of
  the file made before revocation is dead for this computer too.
- Any cheap FIDO2 key would give the same flow with a touch requirement and a
  non-extractable secret (`hmac-secret`). This design exists because a plain
  stick is what people have; a FIDO2 backend would produce the same sidecar
  wrap from an `hmac-secret` output instead of a file.

## Manual acceptance

1. Settings → Set up… → pick the stick → master password → toast names it.
   `keyfile-unlock.json` exists next to the vault, mode `0600`;
   `Arca/<id>.arcakey` is on the stick. Touch ID / keychain toggle unchanged.
2. Lock (sidebar). Focus the window → opens with no prompt (and no Touch ID
   sheet on a Mac).
3. Lock. In the browser, focus a password field on a site with a stored login
   → picker shows credentials; Arca's window did not come forward.
4. Pull the stick → lock screen within a second. Plug it in → opens.
5. Settings → uncheck "Lock when the USB key is removed" → pull → stays open.
6. Second computer: Set up… → the same stick shows "has an Arca key" → toast
   says it is using the existing key. Both computers open with it.
7. Restore an older backup → key is reported stale → enter the master
   password → next lock/unlock is silent again.
8. Remove… → the sidecar is gone, the file is still on the stick, and this
   computer no longer opens with it.
