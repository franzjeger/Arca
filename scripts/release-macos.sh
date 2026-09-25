#!/usr/bin/env bash
#
# Build a DISTRIBUTABLE macOS Arca: Developer ID signed, hardened runtime,
# notarized and stapled, as a .dmg other Macs will open without warnings.
#
#   scripts/release-macos.sh            # build, sign, notarize, staple
#   scripts/release-macos.sh --no-notarize   # sign only (local check)
#
# One-time setup (you must do this yourself — it needs your Apple ID and an
# app-specific password from https://appleid.apple.com):
#
#   xcrun notarytool store-credentials "arca-notary" \
#     --apple-id "<your-apple-id>" --team-id LY6LJ395B8
#
# That stores the credential in your login keychain, so no secret ever appears
# in this script, in the environment, or in your shell history.
#
# Distribution signing deliberately does NOT carry the App Group / shared
# keychain entitlements: the macOS AutoFill extension is shelved, the vault
# lives in app data, and restricted entitlements would drag a provisioning
# profile into every release for no benefit.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
cd "$REPO"
"$REPO/scripts/check-release.sh"
NOTARIZE=1
[ "${1:-}" = "--no-notarize" ] && NOTARIZE=0

NOTARY_PROFILE="${ARCA_NOTARY_PROFILE:-arca-notary}"
TEAM_ID="LY6LJ395B8"

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Guard: never ship a build that would strand the user's data.
#
# The vault briefly lived in the App Group container. A release build has no
# App Group entitlement, so it CANNOT see that container — if a newer vault is
# still sitting there, installing this build would silently open an older
# app-data copy and quietly lose everything since. The dev build migrates it
# back on launch; run that first. (Metadata is readable from a shell even
# though the contents are not, which is exactly what this check needs.)
# ---------------------------------------------------------------------------
step "Checking that no vault data is stranded in the App Group container"
CONTAINER_VAULT="$HOME/Library/Group Containers/group.no.sybr.vault/default.vault"
APPDATA_VAULT="$HOME/Library/Application Support/no.sybr.vault/default.vault"
if [ -f "$CONTAINER_VAULT" ]; then
  c_mtime=$(stat -f %m "$CONTAINER_VAULT")
  a_mtime=$(stat -f %m "$APPDATA_VAULT" 2>/dev/null || echo 0)
  if [ "$c_mtime" -gt "$a_mtime" ]; then
    die "the App Group container holds a NEWER vault than app data.
     container: $(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$CONTAINER_VAULT")
     app data:  $(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$APPDATA_VAULT" 2>/dev/null || echo 'missing')
     A release build cannot read that container, so installing it would open
     the older copy and lose the difference. Launch the locally installed dev
     build once (scripts/install-app-macos.sh) — it migrates the vault back —
     then re-run this."
  fi
  echo "   container copy is not newer; nothing stranded"
else
  echo "   no container vault; nothing to check"
fi

step "Smoke test"
bash "$REPO/scripts/smoke-test.sh"

# `|| true`: `head -1` can SIGPIPE the upstream `grep`, and with `pipefail` that
# aborts the script with a message about a missing certificate that is in fact
# right there. Emptiness is the real test, and it is the next line.
IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | grep -Eo '"Developer ID Application[^"]*"' | head -1 | tr -d '"' || true)"
[ -n "$IDENTITY" ] || die "no 'Developer ID Application' certificate in the keychain."
echo "   signing identity: $IDENTITY"

# The update signing key is separate from the Apple one: Apple's signature says
# "this came from Frank Lia", the update key says "this is the same Arca you
# already trust". Installed copies only accept updates signed by the key baked
# into the build they are running, so losing it strands every user forever.
UPDATER_KEY="${ARCA_UPDATER_KEY:-$HOME/.arca/arca-updater.key}"
[ -f "$UPDATER_KEY" ] || die "no update signing key at $UPDATER_KEY.
     Without it the build cannot be published as an update. Restore it from
     your backup, or (only if no release has ever shipped) generate a new one:
       cd apps/desktop && npx tauri signer generate -w \"$UPDATER_KEY\""

# The Google OAuth client secret is not in the repository — crates/vault-sync's
# build script reads it from here. A build without it works perfectly except
# that Drive sync refuses to connect, which is a silent thing to discover after
# shipping, so a release stops rather than going out half-working.
CLIENT_SECRET_FILE="${ARCA_GOOGLE_CLIENT_SECRET_FILE:-$HOME/.arca/google-client-secret}"
if [ -z "${ARCA_GOOGLE_CLIENT_SECRET:-}" ]; then
  [ -s "$CLIENT_SECRET_FILE" ] || die "no Google client secret at $CLIENT_SECRET_FILE.
     This build would ship with Drive sync switched off. Put the secret for the
     desktop OAuth client there (one line, chmod 600), or export
     ARCA_GOOGLE_CLIENT_SECRET. See docs/SYNC.md."
fi

# A DMG build that dies part-way leaves its scratch image mounted, and the next
# run then fails on a name that is already taken — reporting only "failed to run
# bundle_dmg.sh", which says nothing about the actual cause. Clear them first.
for vol in /Volumes/dmg.*; do
  [ -d "$vol" ] || continue
  echo "   ejecting a leftover build volume: $vol"
  hdiutil detach "$vol" -force >/dev/null 2>&1 || true
done
find "$CARGO_OUTPUT/release/bundle/macos" -maxdepth 1 -name "rw.*.dmg" -delete 2>/dev/null || true

step "Building the release bundle (Developer ID + hardened runtime)"
# Tauri signs the bundle itself when these are set; the hardened runtime is
# required for notarization.
export APPLE_SIGNING_IDENTITY="$IDENTITY"
export APPLE_TEAM_ID="$TEAM_ID"
# TAURI_SIGNING_PRIVATE_KEY, not ..._KEY_PATH: this CLI reads the former and
# accepts either the key itself or a path to it. With only the PATH variable set
# it found the public key, found no private one, and failed AFTER bundling
# everything — so the run looked like it had worked right up until the end.
# A path rather than the key's contents keeps the material out of the process
# environment.
export TAURI_SIGNING_PRIVATE_KEY="$UPDATER_KEY"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${ARCA_UPDATER_KEY_PASSWORD:-}"
# createUpdaterArtifacts is passed HERE, not in tauri.conf.json: in the shared
# config it made every local dev build demand the release signing key.
#
# `--bundles app`, not `app,dmg`. Tauri's DMG bundler drives Finder over
# AppleScript to arrange the icons in the window, and that step fails at random
# ("Can't get disk (-1728)"): the same command succeeded by hand and failed
# under the build minutes apart, and all Tauri reports is "failed to run
# bundle_dmg.sh" with no cause. Prettiness is not worth a release that fails
# every other attempt for reasons nobody can see. The disk image is built below
# with hdiutil instead — no Finder, no automation, same contents.
(cd "$REPO/apps/desktop" && npm run tauri build -- --bundles app \
  --config '{"bundle":{"createUpdaterArtifacts":true}}')

APP="$CARGO_OUTPUT/release/bundle/macos/Arca.app"
[ -d "$APP" ] || die "no app bundle at $APP"

step "Building the disk image"
VERSION="$(python3 -c "import json;print(json.load(open('$REPO/apps/desktop/src-tauri/tauri.conf.json'))['version'])")"
DMG="$CARGO_OUTPUT/release/bundle/dmg/Arca_${VERSION}_aarch64.dmg"
mkdir -p "$(dirname "$DMG")"
rm -f "$DMG"
DMG_STAGE="$(mktemp -d)"
# `ditto` rather than `cp -R`: it preserves the signature's extended attributes,
# and a DMG holding a subtly broken copy would fail notarization with something
# far less obvious than this comment.
ditto "$APP" "$DMG_STAGE/Arca.app"
ln -s /Applications "$DMG_STAGE/Applications"
hdiutil create -volname "Arca" -srcfolder "$DMG_STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$DMG_STAGE"
# Sign the image too, so what the user downloads is itself attributable and not
# merely a container for something that is.
codesign --force --sign "$IDENTITY" "$DMG"
echo "   $(basename "$DMG") ($(du -h "$DMG" | cut -f1))"

step "Verifying the signature"
codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -3
# Hardened runtime must be on, or notarization rejects the upload.
#
# Read into a variable rather than piping into `grep -q`. That pipeline failed
# whenever the flag was PRESENT: grep exits the moment it matches, codesign dies
# on SIGPIPE (141), and `pipefail` turns that into the whole check failing. A
# test that only fails when its subject is correct is worse than no test.
SIG_INFO="$(codesign -d --verbose=2 "$APP" 2>&1 || true)"
case "$SIG_INFO" in
  *"flags="*"runtime"*) echo "   hardened runtime: on" ;;
  *) die "the app is not signed with the hardened runtime." ;;
esac

if [ "$NOTARIZE" = "0" ]; then
  printf '\nSigned but NOT notarized (--no-notarize).\n  %s\n' "$APP"
  exit 0
fi

if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
  die "no notarytool credentials named '$NOTARY_PROFILE'.
     Create them once (they never touch this script):
       xcrun notarytool store-credentials \"$NOTARY_PROFILE\" \\
         --apple-id \"<your-apple-id>\" --team-id $TEAM_ID"
fi

# Notarize the DMG when we built one — stapling the disk image means the
# download itself is trusted, not just the app inside it.
TARGET="${DMG:-$APP}"
if [ "$TARGET" = "$APP" ]; then
  TARGET="$CARGO_OUTPUT/release/bundle/macos/Arca.zip"
  ditto -c -k --keepParent "$APP" "$TARGET"
fi

step "Notarizing $(basename "$TARGET") (Apple can take a few minutes)"
xcrun notarytool submit "$TARGET" --keychain-profile "$NOTARY_PROFILE" --wait

step "Stapling the ticket"
if [ "${TARGET##*.}" = "dmg" ]; then
  xcrun stapler staple "$TARGET"
  xcrun stapler validate "$TARGET"
else
  # A zip cannot be stapled; staple the app and re-zip.
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
  rm -f "$TARGET"
  ditto -c -k --keepParent "$APP" "$TARGET"
fi

step "Gatekeeper assessment (what another Mac will decide)"
spctl --assess --type execute --verbose=2 "$APP" 2>&1 | tail -3

step "Writing the update manifest"
# Tauri emits <bundle>.app.tar.gz plus a detached .sig when
# createUpdaterArtifacts is on. latest.json is what installed copies poll.
UPD_ARCHIVE="$(ls -t "$CARGO_OUTPUT/release/bundle/macos/"*.app.tar.gz 2>/dev/null | head -1 || true)"
if [ -n "$UPD_ARCHIVE" ] && [ -f "$UPD_ARCHIVE.sig" ]; then
  LATEST="$CARGO_OUTPUT/release/bundle/latest.json"
  # Merged, never rewritten. This block used to emit the whole manifest, which
  # meant a macOS release published after a Linux one silently dropped
  # linux-x86_64 and stopped every installed Linux copy from updating (and the
  # other way round). scripts/update-manifest.py keeps the other platforms of
  # the same version and drops them only when the version itself changes.
  python3 "$REPO/scripts/update-manifest.py" \
    --manifest "$LATEST" \
    --version "$VERSION" \
    --url "https://github.com/franzjeger/Arca/releases/download/v$VERSION/$(basename "$UPD_ARCHIVE")" \
    --signature-file "$UPD_ARCHIVE.sig" \
    --platform darwin-aarch64 \
    --platform darwin-x86_64
  echo "   Publish it AND $(basename "$UPD_ARCHIVE") on the v$VERSION GitHub release,"
  echo "   or installed copies will never see the update."
else
  # Fatal, not a note. A release with no signed updater archive cannot be
  # delivered as an update to anyone, and this used to print a shrug at the very
  # end of an otherwise successful-looking run.
  die "no signed updater archive was produced.
     Everything else built, but installed copies could never update to this.
     Check TAURI_SIGNING_PRIVATE_KEY and createUpdaterArtifacts."
fi

printf '\nRELEASE OK\n  app: %s\n' "$APP"
[ -n "$DMG" ] && printf '  dmg: %s\n' "$DMG"
