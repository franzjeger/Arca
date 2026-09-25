# macOS keychain hardening: verification and migration requirements

The desktop supports OS-enforced device-key protection. New macOS enrollments
use the data-protection keychain; existing installations upgrade from Settings
→ Touch ID protection → Upgrade protection. An unlocked vault and successful
system authentication are required. This does not change the master password.

Each candidate uses a unique `desktop-protected-<UUID>` account in the shared
keychain group. The candidate is read back through a fresh LAContext and compared
in constant time before the active reference is saved in `quick-unlock.json`.
The old login-keychain copy is deleted only after commit. The AutoFill copy
remains independently access-controlled and is updated from the verified key
without another keychain read. Routine AutoFill publication never rereads it.

The marker remains after disabling quick unlock or restoring a vault. A missing
or invalid protected key never falls back to the legacy key. macOS password
unlock no longer creates unprotected device keys automatically: use Settings to
repair or re-enable protected Touch ID. A malformed readable marker can also be
repaired while unlocked. Signing/permission errors remain errors.

Authentication runs off the main thread and outside the vault mutex. A generation
counter rejects results after explicit lock, automatic lock, restore, cloud
bootstrap or another authentication attempt. Enrollment gives the native system
prompt a bounded 60-second blur grace; explicit and idle locks still invalidate it.

For a new enrollment or repair, the protected reference is written before the
new vault header. If the vault save fails, the old reference is restored; if
that restoration also fails, the staged protected key is retained. A crash
between those writes can require master-password unlock and Repair Touch ID,
but cannot corrupt the vault or expose an unprotected replacement key.

## Reproduce the signed interactive check

Run `bash scripts/test-keychain-access-control-macos.sh` on a Mac with the
local Apple Development profile and identity and enrolled Touch ID.
The helper runs from a temporary app bundle without registering it in Launch
Services. Its bundle identifier matches the provisioning profile, while the legacy
test item uses a fresh service name, while the protected test item uses a fresh
`desktop-protected-<UUID>` account.
It never opens a vault file or queries an existing device-key account.

The test creates a random 32-byte synthetic key, stores a legacy test copy and
a data-protection copy protected by `biometryCurrentSet` and
`WhenUnlockedThisDeviceOnly`, and checks:

- A fresh noninteractive authentication context cannot read the protected key.
- After Touch ID, the returned bytes match the synthetic key.
- The original test item is deleted only after the replacement was verified.
- A second fresh noninteractive context still cannot read the protected key.
- All synthetic keychain items and the temporary app bundle are removed.

Cancelling the prompt checks that the original test key is still present and
unchanged. The helper exits with code 2 because the successful migration path
was not exercised. Exit 0 means the successful authenticated path passed.
Set `ARCA_TEST_DENY_AUTH=1` to exercise the failed-authentication retention path
without prompting (expected exit 2).

An abrupt process termination can bypass keychain cleanup; normal completion,
including a cancelled prompt, cleans both items.

## Local evidence, 2026-09-09

The successful authenticated path passed against the production native shim
with the committed development provisioning profile. A noninteractive read was
denied, Touch ID released the exact key, the original test copy was retired,
and a fresh context was denied again. Metadata presence checks were also tested;
macOS can return `errSecInteractionNotAllowed` even for metadata of a matching
protected item, which is treated as presence only. Synthetic items were removed.

A forced noninteractive authentication refusal exercised retention of the
original synthetic key and cleanup. The manual cancellation attempt was instead
authenticated, so manual cancellation has not yet been certified. Unit tests
cover stale authentication generations, failed config writes, failed vault
writes, failed rollback, and fail-closed malformed configuration. UI tests cover
failed enrollment and retry without falsely reporting success.

Remaining acceptance checks include the actual migrated app's repeated
lock/unlock, user cancellation, restart/re-signing, AutoFill on a real website,
changed fingerprint enrollment and release signing on another Mac. An independent
security audit is still outstanding. Do not treat the synthetic mechanism test
as those checks.

Apple documents the access-control flags in
[SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
and authentication context lifetime in
[kSecUseAuthenticationContext](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext).
[SecAccessControlCreateWithFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:))
also specifies that protected operations can block and should run in the background.
