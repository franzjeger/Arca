# Backup and recovery

Arca is zero-knowledge: the master password never leaves your machine and is
never stored. That is the point, and it is also the risk. **Nobody can recover
your vault for you.** This document is the plan for the day something goes
wrong.

## What protects you, and against what

| Failure | What saves you |
| --- | --- |
| Deleted an entry, a bulk merge ate too much, a sync merge went wrong | **Local snapshots** (automatic) |
| Disk died, laptop lost or stolen, macOS reinstall | **Off-device backup** + Google Drive sync |
| Vault file corrupted mid-write | Atomic writes, plus snapshots |
| Forgot the master password | **Nothing.** See "The one unrecoverable case". |

## Local snapshots (automatic)

Before every save, Arca copies the vault as it was *just before* the change.
Retention is tiered: the **last 5 saves**, plus the **newest of each of the last
7 days**. That covers both "undo what I just did" and "something broke a few
days ago and I only noticed now".

Snapshots live next to the vault:

```
~/Library/Application Support/no.sybr.vault/snapshots/     # macOS
%APPDATA%\no.sybr.vault\snapshots\                         # Windows
~/.local/share/no.sybr.vault/snapshots/                    # Linux (default)
```

They are byte-for-byte copies of the **encrypted** container. A snapshot is
exactly as safe as the vault itself: same ciphertext, same master password,
nothing in plaintext.

**Restoring:** Settings → *Earlier versions* → *Restore*. Restoring snapshots
the current state first, so a restore is itself undoable. Arca locks afterwards,
because a snapshot may predate a master-password change and must be unlocked
with the password that was in effect when it was written.

> Snapshots are on the same disk as the vault. They do not protect you from
> losing the machine. That is what the off-device backup is for.

## Off-device backup (do this today)

Settings → *Back up the vault* writes a copy of the encrypted vault wherever you
choose. Because it is ciphertext, it is safe on a USB stick, a NAS, or another
computer: without your master password it is noise.

**Restoring from it:** disconnect Google Drive sync, then choose Settings →
*Encrypted backup* → *Restore*. Select the `.vault` file and enter the master
password that was active when the backup was made. Arca fully decrypts and
validates the backup before touching the current vault, takes a snapshot of the
current state, replaces it atomically, and locks afterwards.

Replacing the current vault also requires fresh authorization: its **current**
master password on Linux, or system verification on macOS/Windows. This is
separate from the backup's password, which may be older. "Verify only" checks
the backup without replacing the current vault and needs only the backup password.

The restore refuses oversized, corrupt, wrongly encrypted, or foreign vault
files. It also refuses to run while Google Drive sync is connected, so a backup
cannot accidentally be attached to the wrong remote vault.

For manual disaster recovery while Arca is not running, the live vault paths
are:

```
~/Library/Application Support/no.sybr.vault/default.vault  # macOS
%APPDATA%\no.sybr.vault\default.vault                      # Windows
~/.local/share/no.sybr.vault/default.vault                 # Linux (default)
```

Take a fresh backup after any bulk change (a large import, a master-password
change) and otherwise every few months.

## Google Drive sync is redundancy, not backup

Sync keeps devices in step; it is not a time machine. A deletion or a bad merge
propagates to every device within a minute. Sync protects you from a dead disk.
Snapshots protect you from a bad edit. You want both.

## The one unrecoverable case

If you forget the master password, the vault is gone. There is no reset link, no
support override, no back door: the master password is the only thing that
derives the key, and Arca stores nothing that could reconstruct it. This is the
deliberate trade for a vault that nobody else can open.

Mitigate it **before** you need to:

- Store the master password in a password manager you already trust, or write it
  down and keep it somewhere physically safe (a home safe, a sealed envelope).
- Keep an off-device backup so a lost machine is not also a lost vault.
- Export a CSV before a master-password change if you want a readable escape
  hatch. Treat that file as radioactive: it is every password in plaintext.
  Delete it when done.

## Emergency kit (fill in and keep offline)

```
Arca emergency kit
------------------
Vault file:      ~/Library/Application Support/no.sybr.vault/default.vault
Backup copy at:  ____________________________  (USB / NAS / other machine)
Backup taken:    ______________
Master password: stored in ____________________  (NOT written here)
Sync account:    ____________________________
Restore: Settings → Encrypted backup → Restore; choose the file and unlock it.
```

Print it, fill it in by hand, keep it with your other important papers. Do not
write the master password on it.
