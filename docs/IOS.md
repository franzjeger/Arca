# iOS implementation and release status

The current feature/build reference is [apps/ios/README.md](../apps/ios/README.md).
The app has run on a physical iPhone since 2026-07-28. Source version 0.5.0 uses
C ABI v16 and the same authenticated V5 vault format as desktop.

## First setup

1. Install the matching signed iOS build and enable Arca as an AutoFill provider.
2. Import an encrypted `.vault` file and unlock with its master password.
3. Enable device unlock if desired, then sign into the same Google account for
   ongoing encrypted sync.

Desktop and iOS must refer to the same original vault. Creating independent
vaults with the same master password produces different keys and does not join
those vaults; foreign vaults are rejected during sync.

## Release verification

The [release plan](RELEASE.md) separates compiler/unit-test evidence from signed
physical-device checks and the independent security audit. The macOS CI job
builds the app and extension unsigned and executes the shared Swift tests.

For each candidate, verify on a device:

- Background the app while master-password/Face ID unlock is still pending;
  returning must require a new unlock. Check immediate and delayed lock settings.
- Lock or background during sync; delayed results must not reveal the list or
  revive an obsolete session.
- Edit a login and Wi-Fi password, sync to desktop, copy an older password and
  restore it. Confirm account, site, notes and TOTP remain unchanged.
- Exercise password AutoFill, passkey creation/assertion and device-key renewal.
- Disconnect/reconnect Drive and test a real two-device concurrent edit.

Initial-device findings and their fixes are retained in Git history rather than
presented as current missing features.
