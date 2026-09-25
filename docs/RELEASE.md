# Coordinated release and validation

Arca 0.6.2 uses authenticated `SYBRVLT5` containers and C ABI v16. Desktop,
Apple targets and the browser extension advertise the same application version;
`scripts/check-versions.py` prevents accidental divergence. The desktop About
row includes the Git build identifier to distinguish locally built binaries.

## Release procedure

1. Commit and push the final source. Start the full workflow for the candidate
   branch (`gh workflow run ci.yml --ref <candidate-branch>`), wait for completion,
   then run `scripts/check-release.sh` from that unchanged checkout. The gate
   requires the latest manual run for the exact commit to succeed, with Linux,
   Windows, macOS, Linux packaging, OS smoke and dependency-audit jobs all passing.
   Ordinary push CI skips the heavier jobs and is insufficient for release.
   macOS builds the Swift targets and runs the shared bridge tests. Both Apple
   release scripts enforce this check. A skipped job or unavailable GitHub
   runner blocks release; local tests do not override the gate. The keychain
   step within the OS smoke job remains best-effort; physical-device
   acceptance below is still required.
2. Build/sign the matching desktop and iOS artifacts. Check V1–V4 unlock/migration
   and a V5 backup restore on copies of test vaults, including wrong-password and
   modified-container rejection. Keep a pre-upgrade encrypted backup.
3. On a physical phone, execute the [iOS release checks](IOS.md#release-verification).
   On desktop, check keyboard-only dialogs, clipboard expiry, repeated launches,
   failed settings writes, missing backup drive and backup verification/restore.
4. Test concurrent real Google Drive changes on desktop and phone, offline edits,
   retries, account disconnect/reconnect and restoring into a disconnected vault.
5. Publish matching installers with the compatibility note. Update every device
   before sharing a V5 file; older published clients may refuse to open it. A
   local desktop install does not update a phone or constitute a public release.

CI produces build/test evidence, not a physical-device certification or an
independent security audit. Record those results against the release commit;
do not relabel a previous version's device check as validation of a new build.

## Outstanding device acceptance checks

These checks remain **unverified for the current changes**. Run them against a
committed release candidate with synthetic vaults and a dedicated test Drive
account. Record commit, installer version, device/OS/browser, expected and actual
results, and pass/fail evidence. Automated tests do not close these rows.

| Check | Required acceptance evidence |
| --- | --- |
| Install/update on the desktops actually used | Clean install and upgrade from the previous published version; verify signature, launch, unlock and saved items after restart. Exercise interrupted download/failed startup and recovery without replacing the vault. |
| Lock on desktop | For login, note, Wi-Fi and bookmark editors, try manual, idle and blur locks with synthetic unsaved secrets. Editors close and do not reopen or restore drafts after either UI or external unlock. Save a generated password before switching apps. Verify copied Arca data clears on lock/expiry while a subsequent unrelated clipboard value survives. This does not prove heap erasure or removal from clipboard history. |
| Backup/restore on disposable data | Create and verify an encrypted backup; change the test vault, disconnect sync, restore and compare items. Check wrong password and modified/truncated backup rejection leaves the current vault intact. Test a missing backup drive and recovery, and verify the pre-restore snapshot. |
| Real Google Drive, desktop and physical iPhone | Make distinct edits offline on both devices, reconnect in both orders and verify convergence. Edit the same item concurrently; verify conflict visibility, resolution and retained alternatives. Interrupt a push, retry, restart and verify no lost edits. Test account disconnect/reconnect and refusal to restore while connected. |
| Autofill/platform release | On physical Linux, exercise in-page fill with the installed native host and extension in the browsers actually used, including wrong-origin and locked-vault refusal. On physical iOS, run the linked release checks for the matching sideloaded build. Test Windows install/update and autofill before claiming release readiness there. |

Prioritize the current desktop and iPhone workflows, recovery and sync first,
based on the usage recorded in README. Validate Linux in-page autofill before
promoting Linux installers. Broader Linux distribution, TestFlight and Android
implementation remain separate work, to prioritize when actual use requires
them; no platform release is established by this checklist.

## Independent review before broad distribution

**Outstanding. No independent reviewer has been engaged by this change.**

Provide a qualified reviewer with the frozen commit, SECURITY.md, THREAT_MODEL.md,
format fixtures, migration tests, and a minimal synthetic vault. Scope:

- KDF/wrapping parameters, authenticated framing, format downgrade and replay.
- Revision/conflict/purge/history behavior and failed-write recovery.
- Browser origin binding, native-host authentication, consent and passkey UV.
- OS keychain/biometric gates, async locking, UI drafts and memory retention.
- External backups, restore authentication, permissions and deletion semantics.
- Build provenance, updater signatures, Apple signing and dependency handling.

Track each finding, fix and retest. An internal review or successful test suite
cannot close this independent-review requirement. Arranging that external work
requires a reviewer; no email, engagement or payment is sent by the release tools.

For Linux development installs, the installer enforces the local smoke suite and
records the verified commit in `~/.local/lib/arca/install.json`. The signed release
gate remains separate. Test a failed startup and rollback on disposable data;
rollback replaces executables and registrations, never the current vault.
