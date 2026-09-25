# `arca` — passwords for automation

Provisioning needs credentials. Creating an M365 user, a service account, a
database login: each one means minting a password and using it once. The
choices used to be typing it by hand or letting it sit in plain text in
whatever log the script was writing, and the second is worse than it looks —
a transcript outlives the password.

    arca new --title "Kunde AS - ny bruker" --user ny.bruker@kunde.no
    # prints only the new item's id

    arca exec <id> -- pwsh -File new-user.ps1
    # runs it with $env:ARCA_PASSWORD set

The password is created inside the desktop app, filed in the vault, and handed
to the child process. It does not pass through the caller's output, so it stays
out of shell history, CI logs and agent transcripts.

## Commands

| | |
|---|---|
| `arca status` | Is the app running and unlocked. |
| `arca new --title T [--user U] [--url X] [--notes N] [--length 8-64] [--no-symbols] [--show]` | Mint and store. Prints the id on stdout; everything human goes to stderr, so `ID=$(arca new …)` works. |
| `arca show <id>` | Print the password. A separate verb so it never happens by accident. |
| `arca rm <id>` | Retract an item. Moves it to Deleted in the app, restorable there. Prints what it removed. |
| `arca exec <id> -- <cmd…>` | Run `cmd` with `ARCA_PASSWORD` set. The child's exit code is passed through. |

Exit codes: `0` ok, `1` failed, `2` bad usage, `3` app locked or not running.
`3` is separate on purpose — a script can tell "unlock it" from "start it" and
say so, instead of reporting a generic failure.

## `rm` is soft, and only soft

`arca rm` sets the deleted flag. The item moves to Deleted in the app and can
be restored there; the vault also snapshots on every save. Purging for good is
not offered and should not be: automation that can create a credential ought to
be able to take it back — an offboarding script, a failed run cleaning up after
itself — but nothing running unattended needs the power to make a vault entry
unrecoverable.

It prints the TITLE of what it removed, so a caller that was handed an id from
somewhere else can see whether it retracted the right thing while that is still
one click away.

## What it is not

It holds no key material and does no crypto. Every operation goes to the
running desktop app over the loopback bridge, using the token the app already
writes for the browser extension, and nothing works while the vault is locked.

That token is readable by any process running as you, and `fill` has always
returned passwords to anything that can read it. **The security boundary is the
user account, and always has been.** This tool does not widen it; it makes the
existing boundary usable from a script instead of only from a browser.

If that boundary is not the one you want, the fix is not to withhold this
command — it is to change what the bridge will do without confirmation, which
is a decision about the bridge, for every client at once.

## Why `exec` rather than a variable

    PW=$(arca show "$ID")        # now it is in the shell, in `ps`, maybe in history
    arca exec "$ID" -- ...       # now it is in one process that needs it

`show` exists because sometimes a person has to read a password out loud, and
pretending otherwise just sends them somewhere worse. But it should be the
thing you reach for deliberately, not the shape every script happens to take.
