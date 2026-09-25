# Arca for iOS

SwiftUI app and AutoFill Credential Provider over the shared Rust vault core.
The project has run on an iPhone since 2026-07-28. Current source is **0.5.0**,
with **C ABI v16**; that is separate from the version installed on a device.

## Implemented

| Area | Behavior |
| --- | --- |
| Unlock | Master password, or device key protected by Face ID / Touch ID. |
| Items | Search and browse logins, passkeys, Wi-Fi, SSH metadata and secure notes. Create/edit logins, Wi-Fi and notes; delete items. |
| AutoFill | Passwords and passkey registration/assertion through the system credential provider. |
| TOTP | Verification codes, QR setup and Live Activity support. |
| Sync | Google Drive through the shared Rust engine, OAuth sign-in and OS credential storage. Every successful edit marks the vault dirty. |
| Password history | Last 20 password changes, encrypted and synced; copy or restore one login/Wi-Fi password. |
| Locking | Configurable background grace period; an unfinished unlock is invalidated on backgrounding. Late async results cannot reactivate a locked session. |
| Clipboard | Local-only copies with expiry; no Universal Clipboard transfer. |

A fresh phone still imports an encrypted vault file before first unlock. Desktop
handles SSH agent operations, bulk imports, Trash recovery, the security report
and scheduled external backups. History starts when passwords are changed by a
history-capable build; it cannot reconstruct older passwords that were never
saved.

## Validation

Every main push runs the macOS/Windows/Linux matrix. The macOS leg builds the
Swift targets and runs shared bridge tests, including the ABI and session-token
regressions. Physical Face ID, system AutoFill and background/resume behavior
still need a signed device check for each release; a green compiler is not that
check. See [release requirements](../../docs/RELEASE.md).

## Build

```sh
cd apps/ios
xcodegen generate          # writes Arca.xcodeproj from project.yml
open Arca.xcodeproj
```

The pre-build phase runs [`scripts/build-ffi-ios.sh`](../../scripts/build-ffi-ios.sh),
which adds the Rust targets, cross-compiles `vault-ffi` for device and simulator
and stages `libs/device/libvault_ffi.a` and `libs/simulator/libvault_ffi.a`. Two
are not optional: device and simulator are different *platforms*, and an
SDK-conditional `LIBRARY_SEARCH_PATHS` picks the right one.

Not an `.xcframework`, though `docs/IOS.md` originally asked for one and the
first cut built one. Xcode resolves a framework dependency when it sets the
target up, before any pre-build script runs, so a library the project builds
itself can never exist in time — a clean checkout fails with *"There is no
XCFramework found at …"*. Search paths resolve at link time, which is also how
`apps/macos` links the same library. Package an xcframework if the library is
ever shipped to someone else.

The device slice is arm64 only — every iOS device is. The **simulator** slice is
a `lipo` of arm64 and x86_64, which is not optional: `ARCHS_STANDARD` for
iphonesimulator is `arm64 x86_64`, and a generic simulator destination has no
concrete device to narrow it to, so Xcode links both. An arm64-only simulator lib
fails with *"ignoring file … found architecture 'arm64', required architecture
'x86_64'"* and then every `vault_ffi_*` symbol undefined.

### Compile-check without signing

```sh
cd apps/ios && xcodegen generate
xcodebuild -scheme Arca -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO -derivedDataPath build build
```

Running it on a device needs your Apple ID: App Groups, keychain sharing and the
AutoFill capability are all team-scoped.

## Try it on a device

1. Set **Team** in Signing & Capabilities if Xcode complains — `project.yml`
   defaults to `LY6LJ395B8`, which must match `apps/macos` because App Groups
   and keychain groups are team-scoped.
2. Run on the device. AirDrop `default.vault` from your Mac (it lives in
   `~/Library/Application Support/no.sybr.vault/`), then **Import a vault file**.
3. Unlock with your master password.
4. **Settings ▸ General ▸ AutoFill & Passwords** and turn **Arca** on.
5. In Safari, focus a login field and pick the Arca suggestion.

> Step 5 needs step 4 done *and* one unlock afterwards: identities are
> published to `ASCredentialIdentityStore` at the end of `VaultStore.unlock`,
> and the store refuses them while Arca is switched off. If AutoFill is off the
> app says so at the bottom of the list. The keyboard's password button reaches
> Arca either way — it calls `prepareCredentialList` directly.

## Layout

```
apps/ios/
├── project.yml              XcodeGen source of truth
├── Arca/                    the app
│   ├── ArcaApp.swift          entry, scene phase, lock-on-background
│   ├── VaultStore.swift       @Observable state: shut / opening / open
│   ├── VaultFile.swift        the vault in the App Group container + import
│   ├── Pasteboard.swift       copy with localOnly + expiry
│   ├── CredentialIdentities.swift  publish metadata to the QuickType bar
│   └── *View.swift            unlock, import, list, detail
└── ArcaAutoFill/            the credential provider
    ├── CredentialProviderViewController.swift   OS entry points + containment
    ├── AutoFillModel.swift                      unlock → fill / pick
    └── UnlockPickerView.swift                   its UI
```

The Swift↔Rust bridge is [`../apple-shared/VaultBridge.swift`](../apple-shared/VaultBridge.swift),
shared verbatim with `apps/macos`. It is platform-agnostic by design — the only
`#if os(macOS)` in it is the data-protection keychain flag.

## Two invariants that are easy to break

Both are shared with `apps/macos`; see [that README](../macos/README.md) for the
full version.

- **`ArcaKeychainAccessGroup` in both Info.plists must match
  `keychain-access-groups` in the entitlements.** That is how the bridge learns
  the team prefix without hardcoding one.
- **`VaultShared.requiredAbiVersion` must match `ABI_VERSION` in
  `crates/vault-ffi/src/lib.rs`.** Opening checks it and fails closed.
