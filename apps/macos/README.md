# Arca — macOS AutoFill

The locally development-signed Arca app embeds `ArcaAutoFill.appex` for native
password and passkey AutoFill, including registration. The desktop app and the
browser extension remain separate entry points. See
[macOS passkeys and unlock](../../docs/MACOS-PASSKEYS.md) for persistence,
account selection and the remaining manual acceptance checks.

## Targets and shared code

[`project.yml`](project.yml) is the source of truth; XcodeGen generates the
ignored `.xcodeproj`. The Swift/Rust bridge lives in `apps/apple-shared` and is
also used by iOS.

| Target | Purpose |
| --- | --- |
| `ArcaSign` | Provisions `no.sybr.vault` with the desktop's restricted capabilities. It is not installed. |
| `ArcaHost` | Development harness that embeds the extension and carries the `ArcaBridgeTests` scheme. The installed container is the Tauri `Arca.app`. |
| `ArcaAutoFill` | Native password and passkey credential provider. |
| `ArcaBridgeTests` | Standalone Swift tests, including the ABI contract against the linked Rust library. |

The keychain group in each Info.plist must match its signed entitlements.
`VaultShared.requiredAbiVersion` must also match `ABI_VERSION` in `vault-ffi`;
Rust and Swift tests check this contract.

## Local signing setup

Use a checkout outside iCloud-synced Documents/Desktop, full Xcode, XcodeGen,
Node.js 22+ and the Rust toolchain in `rust-toolchain.toml` through rustup.
Run `xcodebuild -runFirstLaunch` after an Xcode installation or upgrade.

1. Sign in under Xcode → Settings → Apple Accounts. The project uses team
   `LY6LJ395B8`, which owns the existing app IDs and shared groups.
2. Generate and open `apps/macos/Arca.xcodeproj` with `xcodegen generate`.
3. Let Xcode manage signing for `ArcaSign`, `ArcaHost` and `ArcaAutoFill` for
   this Mac. All three request the AutoFill capability, App Group and shared
   keychain group. Provisioning can also be requested with:

   ```sh
   xcodebuild -project Arca.xcodeproj -scheme ArcaSign -destination 'platform=macOS' \
     -allowProvisioningUpdates -allowProvisioningDeviceRegistration build
   xcodebuild -project Arca.xcodeproj -scheme ArcaHost -destination 'platform=macOS' \
     -allowProvisioningUpdates -allowProvisioningDeviceRegistration build
   ```

4. From the repository root, run `scripts/install-app-macos.sh`.

Profiles and private keys stay local. The installer selects profiles from
Xcode's profile directories or the currently installed app. Both bundle IDs
must authorize the same available signing certificate, this Mac, the App Group,
shared keychain group and AutoFill capability. Expired or mismatched profiles
fail before the working app is replaced. Signing adds the application and team
identifiers to both bundles and verifies the sealed results.

If Xcode reports a certificate whose private key is missing, restore the
certificate **with its private key** from the original machine or backup.
Downloading a certificate alone does not restore that key. Revocation and
replacement are an explicit account-management operation; the installer never
performs them automatically.

`ARCA_ADHOC=1 scripts/install-app-macos.sh` explicitly installs a local build
without native AutoFill or shared entitlements. Development signing is the
default. Distribution/notarization is a separate workflow in
[RELEASING.md](../../docs/RELEASING.md).

## Installation and verification

The installer runs the full smoke suite, builds the app and native host, then
embeds and signs the AutoFill extension. The CLI is installed in `~/.local/bin`
and the browser host in `~/.local/lib/arca/vault-native-host`; browser manifests
use that stable path even if Cargo's output directory changes. App, helper
binaries and registrations are restored if installation verification fails.

`CARGO_TARGET_DIR` controls Cargo output. Apple build products default to its
`apple/ArcaHost` subdirectory, or `ARCA_APPLE_BUILD_ROOT/ArcaHost` when set.
The FFI library uses a separate `apple-ffi` cache and is built before Xcode.

Enable Arca in System Settings → General → AutoFill & Passwords. Safari and
native apps use the native provider; Chromium-family browsers use the browser
extension. Unlock Arca to publish credential identities, then try a real login.
A successful build or provider registration does not prove an account ceremony.

```sh
python3 scripts/prepare-autofill-signing.py --verify /Applications/Arca.app
python3 scripts/prepare-autofill-signing.py --verify \
  /Applications/Arca.app/Contents/PlugIns/ArcaAutoFill.appex
pluginkit -m -i no.sybr.vault.autofill-host.autofill
```

For unsigned Swift build/test coverage:

```sh
cd apps/macos
xcodegen generate
xcodebuild -project Arca.xcodeproj -scheme ArcaHost -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO -derivedDataPath build test
```

CI uses `scripts/build-apple-ci.sh` for the macOS tests and iOS build. Keep a
single installed Arca container to avoid stale extension registrations.
