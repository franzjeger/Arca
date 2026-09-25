# Releasing Arca (macOS and Linux)

The everyday build (`scripts/install-app-macos.sh`) is signed for **this Mac
only**. To put Arca on another machine it must be Developer ID signed, hardened,
notarized and stapled, or Gatekeeper refuses to open it.

```bash
scripts/release-macos.sh                 # build, sign, notarize, staple
scripts/release-macos.sh --no-notarize   # sign only, to check the build
```

## One-time setup

Notarization needs your Apple credentials. Create the keychain profile
yourself — no script or tool here ever sees the password:

1. Make an **app-specific password** at <https://appleid.apple.com> →
   *Sign-In and Security* → *App-Specific Passwords*.
2. Store it:

```bash
xcrun notarytool store-credentials "arca-notary" --apple-id "<your-apple-id>" --team-id LY6LJ395B8
```

Check `security find-identity -v -p codesigning` for a usable Developer ID
Application identity. Local Apple Development signing does not provide one.
A certificate download does not restore its private key; restore both from a
backup or manage replacement explicitly through Apple Developer.

## Why release builds carry no entitlements

The App Group and shared-keychain entitlements in
`apps/desktop/src-tauri/Entitlements.plist` are **restricted**: macOS (AMFI)
kills an app that carries them without a provisioning profile that authorizes
them — the "error 163" that stopped us for hours. They are therefore *not* in
`tauri.conf.json`. A plain `tauri build` produces a clean bundle that Developer
ID signing and notarization accept, while `install-app-macos.sh` re-applies them
locally with matching profiles for native AutoFill, shared keychain access and
App Group migration. The release script currently does not embed the native
AutoFill extension; development-install capability checks do not validate a
distribution bundle.

Verify a release build with:

```bash
codesign -dv --verbose=2 target/release/bundle/macos/Arca.app 2>&1 | grep -E 'Authority|flags='
```

You want `Authority=Developer ID Application` and `flags=0x10000(runtime)`.

## The stranded-vault guard

`release-macos.sh` refuses to build while the App Group container holds a
**newer** vault than app data. A release build has no entitlement to read that
container, so installing it would silently open the older copy and lose
everything since. Launch the locally installed dev build once (it migrates the
vault back), then release. The guard reads only file timestamps, which is
allowed even though the contents are not.

## Auto-update

The app includes the updater plugin, public key and GitHub release endpoint.
`release-macos.sh` requires the local updater private key, asks Tauri for signed
updater artifacts, and writes `latest.json`. It fails if the signed archive is
missing. Publishing those artifacts and the manifest is still a release step;
a local build does not publish an update.

The default private-key path is `~/.arca/arca-updater.key`, overridable with
`ARCA_UPDATER_KEY`. Keep the key outside Git and retain a secure backup. Apple
code signing and updater signing use different keys.

**Back up the private key now.** Losing it means every installed copy is stuck
on its current version forever, with no way to ship a fix. A Secure Note in Arca
plus the off-device backup (see [BACKUP.md](BACKUP.md)) is a reasonable home for
it.

The plugin, the key, the endpoint and the UI are all in place: Settings ▸
Updates checks on demand and installs on a second, explicit click. There is no
background check — nothing is fetched or installed unless the user asks.

### Public update endpoint

New builds fetch `https://github.com/franzjeger/Arca/releases/latest/download/latest.json`
without credentials. This public repository is the source and release destination.
The endpoint exists only after a signed release and its manifest are published;
creating the repository does not itself publish an update.

Older builds that point at the private predecessor repository need a manual
update once. Never embed a GitHub token to make that private endpoint work.

### Per-platform reality

| Platform | Updatable | Artifact |
|---|---|---|
| macOS | yes | `Arca.app.tar.gz` + `.sig` |
| Linux, AppImage | yes | `*.AppImage` + `.sig` |
| Linux, `.deb`/`.rpm` | **no** | installed by the package manager |
| Windows | not built | no release pipeline yet |

`tauri-plugin-updater` replaces a running **AppImage**, and that is the only
thing it can do on Linux: a `.deb` or `.rpm` install lives in `/usr/bin` and
belongs to apt/dnf, so there is no file for the updater to swap. Ship the
AppImage if in-app updates on Linux are wanted; keep the `.deb`/`.rpm` for
people who would rather their package manager owned it.

### The manifest is merged, not rewritten

`latest.json` describes **one version across every platform**, so each release
script merges its own entry with `scripts/update-manifest.py` rather than
writing the file:

```
scripts/release-macos.sh     # adds darwin-aarch64, darwin-x86_64
scripts/release-linux.sh     # adds linux-x86_64 (or linux-aarch64)
```

Both scripts emit the same `latest.json` path, and each keeps the entries the
other put there. Publish whichever was produced **last**, since it is the one
carrying both. When the version changes the old entries are dropped rather than
merged — their URLs point at the previous release's files, and a manifest that
mixes versions hands half its users a download that does not match the version
it claims.

Before this merging existed each script wrote the whole file, so releasing one
platform silently deleted the other's entry and stopped those installs from
updating.
