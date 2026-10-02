# Releasing Arca (macOS and Linux)

The everyday build (`scripts/install-app-macos.sh`) is signed for **this Mac
only**. To put Arca on another machine it must be Developer ID signed, hardened,
notarized and stapled, or Gatekeeper refuses to open it.

```bash
scripts/release-macos.sh                 # build, sign, notarize, staple
scripts/release-macos.sh --no-notarize   # build and sign only, to check the build
```

Both start with `scripts/check-release.sh`: a clean checkout whose exact commit
passed a full, manually dispatched CI run.

## One-time setup

```bash
scripts/setup-macos-signing.sh           # make what is missing
scripts/setup-macos-signing.sh --check   # read only: what exists
```

It works through the App Store Connect API key that `release-ios.sh` already
uses, and makes:

- a **Developer ID Application** identity, with its private key generated on
  this Mac, in a keychain of its own (`arca-developer-id.keychain`);
- **Developer ID profiles** for the app and its AutoFill extension, which grant
  the App Group, shared keychain and AutoFill capabilities on every Mac;
- **notarization credentials** named `arca-notary`, from the same API key, so no
  Apple ID password or app-specific password is involved.

Apple lets only the Account Holder create a Developer ID certificate, and not
through an API key. The first run therefore stops with the steps for the
developer portal and the signing request to upload there. In the portal, choose
**G2 Sub-CA**: the preselected "Previous Sub-CA" issues certificates that all
expire on 2027-02-01. Run the script again afterwards. It finds the new
certificate by its key, so there is nothing to download.

**Back up `~/.arca/signing/`** with the updater key and the `.p8`. A lost
Developer ID key means a new certificate, and Apple caps how many a team may
hold; what is already signed and notarized keeps working either way.

## What a release is

The same app the everyday install builds, assembled by the same script
(`scripts/assemble-app-macos.sh`), with:

- the **AutoFill extension** inside, so updating from the everyday build keeps
  native AutoFill;
- the **browser host** inside, beside the app's executable. Arca registers it
  with the browsers when it starts, so an update replaces both halves of the
  bridge together;
- a **Developer ID signature** on the browser host, the extension and the app,
  in that order, each with the hardened runtime and a secure timestamp.

The app is notarized and stapled first, so the ticket travels inside it. The
disk image is built from that app, then signed, notarized and stapled itself.

Check a build with:

```bash
codesign -dv --verbose=2 target/release/bundle/macos/Arca.app 2>&1 | grep -E 'Authority|flags='
spctl --assess --type execute --verbose=2 target/release/bundle/macos/Arca.app
```

You want `Authority=Developer ID Application`, `flags=0x10000(runtime)` and
`source=Notarized Developer ID`.

## Publishing

```bash
scripts/publish-release.sh             # show what would be published
scripts/publish-release.sh --publish   # publish it
```

It publishes what `release-macos.sh` built, and only if that is this checkout:
the app's own build info must name `HEAD`, clean, and the same CI gate must
pass. It also checks that:

- the disk image is stapled and both it and the app pass Gatekeeper;
- `latest.json` names only files on this release, carrying the archive's
  signature;
- `CHANGELOG.md` has a section for the version, which becomes the notes.

A tag that exists is never replaced: a published version is released again as a
new one.

Installed copies act on a release the moment it exists. So it is made as a
draft, filled and checked, then published, and the script reads the public
`latest.json` back to confirm what installed copies now see.

## Why a release carries restricted entitlements

The App Group, shared keychain and AutoFill entitlements in
`apps/desktop/src-tauri/Entitlements.plist` are **restricted**: macOS (AMFI)
kills an app that carries them without a provisioning profile that authorizes
them, the "error 163" that once stopped us for hours. They are therefore not in
`tauri.conf.json`. Both install paths apply them after the build, each with its
own profiles: development profiles that name this Mac, or Developer ID profiles
that name none. `prepare-autofill-signing.py` refuses to mix the two.

Release builds used to carry none of them, and could not read the App Group
container, so `release-macos.sh` refused to build while the container held a
newer vault than app data. A release now has the App Group, migrates a newer
container vault itself as the everyday build does, and that guard is gone.

## Auto-update

The app includes the updater plugin, public key and GitHub release endpoint.
`release-macos.sh` makes the update archive from the finished, stapled app
(`Arca_<version>_aarch64.app.tar.gz`). The updater unpacks everything under the
archive's first folder in place of the running app, so the archive holds
`Arca.app/` alone, without AppleDouble `._` entries. The script signs it with the
updater key, bound to the version, and writes `latest.json`.

Tauri's own updater archive is not used on macOS: it would hold the app as it
was before the extension, the host and the notarization ticket went in.

The manifest is not signed, only the archive is. So the app requires the
archive's signature to name the version the manifest announces
(`requireSignedVersion`). Otherwise whoever could serve a manifest could pair a
new version number with an older, validly signed archive, and install copies
back onto an old release. No release was published before this was on, so
every signature installed copies can meet carries its version.

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
| macOS, Apple silicon | yes | `Arca_<version>_aarch64.app.tar.gz` + `.sig` |
| macOS, Intel | not built | the release is arm64 only |
| Linux, AppImage | yes | `*.AppImage` + `.sig` |
| Linux, `.deb`/`.rpm` | **no** | installed by the package manager |
| Linux, `scripts/install-linux.sh` | **no** | `git pull`, then `scripts/install-linux.sh --restart` |
| Windows | not built | no release pipeline yet |

`tauri-plugin-updater` replaces a running **AppImage**, and that is the only
thing it can do on Linux: a `.deb` or `.rpm` install lives in `/usr/bin` and
belongs to apt/dnf, so there is no file for the updater to swap. Ship the
AppImage if in-app updates on Linux are wanted; keep the `.deb`/`.rpm` for
people who would rather their package manager owned it.

The plugin does not refuse the other cases by itself: for any binary it cannot
place it takes the AppImage path and overwrites the running file. So Arca
loads the updater on Linux only when it runs as an AppImage
(`apps/desktop/src-tauri/src/updates.rs`); a package or a copy built from
source has no updater, and Settings ▸ Updates says how that copy is updated.

### The manifest is merged, not rewritten

`latest.json` describes **one version across every platform**, so each release
script merges its own entry with `scripts/update-manifest.py` rather than
writing the file:

```
scripts/release-macos.sh     # adds darwin-aarch64
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

The merge also refuses a signature by a key the installed copies do not trust,
or one bound to another version. Either would offer an update every client then
refuses, and nobody would notice until someone wondered why no update came.
