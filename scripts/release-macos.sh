#!/usr/bin/env bash
#
# Build a DISTRIBUTABLE macOS Arca: the app install-app-macos.sh puts on this
# Mac, with its AutoFill extension and browser host inside, signed with
# Developer ID and the hardened runtime, notarized and stapled. Other Macs open
# it without warnings, and installed copies can update to it.
#
#   scripts/release-macos.sh                 # build, sign, notarize, staple
#   scripts/release-macos.sh --no-notarize   # build and sign only, to check it
#
# One-time setup: scripts/setup-macos-signing.sh. It makes the Developer ID
# identity; the Developer ID profiles that keep the App Group, shared keychain
# and AutoFill capabilities on every Mac; and the "arca-notary" credentials.
# All of it comes from the App Store Connect API key, with no Apple ID password.
#
# What it leaves in <cargo output>/release/bundle:
#   dmg/Arca_<version>_aarch64.dmg                    for people to download
#   macos/Arca_<version>_aarch64.app.tar.gz + .sig    what installed copies update to
#   latest.json                                       what installed copies poll
#   macos/Arca.app                                    the notarized app itself
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
cd "$REPO"
"$REPO/scripts/check-release.sh"
NOTARIZE=1
[ "${1:-}" = "--no-notarize" ] && NOTARIZE=0

NOTARY_PROFILE="${ARCA_NOTARY_PROFILE:-arca-notary}"
# Where setup-macos-signing.sh keeps it: beside the signing key, readable while
# the screen is locked, unlike notarytool's default.
NOTARY_KEYCHAIN="${ARCA_NOTARY_KEYCHAIN:-$HOME/Library/Keychains/arca-developer-id.keychain-db}"
NOTARY=(--keychain "$NOTARY_KEYCHAIN" --keychain-profile "$NOTARY_PROFILE")

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# Assembled outside Documents: File Provider can re-attach FinderInfo to
# bundles there, and codesign rightly refuses them.
WORK="$(mktemp -d /tmp/arca-release.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

step "Checking what signing and publishing need"
python3 "$REPO/scripts/prepare-autofill-signing.py" --distribution --plan "$WORK/signing.json" \
  || die "Developer ID signing is not ready. Run scripts/setup-macos-signing.sh."
IDENTITY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"])' "$WORK/signing.json")"
echo "   Developer ID identity $IDENTITY, with profiles for the app and its extension"

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

# The signing identity and the notary credentials live in that keychain, and
# it locks again at every restart: codesign and notarytool then stop with "The
# ... keychain is locked". setup-macos-signing.sh gave it a password of its
# own, kept beside the signing key for exactly this.
KEYCHAIN_PASSWORD_FILE="${ARCA_KEYCHAIN_PASSWORD_FILE:-$HOME/.arca/signing/developer-id-keychain-password}"
if [ -r "$KEYCHAIN_PASSWORD_FILE" ]; then
  security unlock-keychain -p "$(cat "$KEYCHAIN_PASSWORD_FILE")" "$NOTARY_KEYCHAIN" \
    || die "could not unlock $NOTARY_KEYCHAIN with the password in $KEYCHAIN_PASSWORD_FILE"
fi

# Asked before building rather than after: the build takes minutes, and this
# is the step most likely to be missing on a new Mac.
if [ "$NOTARIZE" = 1 ]; then
  if ! NOTARY_ERROR="$(xcrun notarytool history "${NOTARY[@]}" 2>&1 >/dev/null)"; then
    # Apple turns notarization off for the whole team whenever it updates the
    # Program License Agreement, until the Account Holder accepts it. Setting
    # the credentials up again would not help.
    case "$NOTARY_ERROR" in
      *"required agreement"*)
        die "Apple refuses to notarize until the Account Holder accepts its updated agreement:
     ${NOTARY_ERROR%%$'\n'*}
     Accept it at https://developer.apple.com/account; it took about ten minutes
     to apply on 2026-10-02." ;;
    esac
    die "notarytool cannot use the credentials named '$NOTARY_PROFILE' in $NOTARY_KEYCHAIN:
     ${NOTARY_ERROR%%$'\n'*}
     Run scripts/setup-macos-signing.sh."
  fi
fi

step "Smoke test"
bash "$REPO/scripts/smoke-test.sh"

step "Building the app"
# Unsigned: assemble-app-macos.sh signs everything once the extension and the
# host are inside. For the same reason Tauri makes no updater archive here: its
# archive would hold the app as it was before they, and the notarization
# ticket, went in. The archive is made below, from the finished app.
(cd "$REPO/apps/desktop" && npm ci && npm run tauri build -- --bundles app)
APP_BUILD="$CARGO_OUTPUT/release/bundle/macos/Arca.app"
[ -d "$APP_BUILD" ] || die "no app bundle at $APP_BUILD"
APP="$WORK/Arca.app"
ditto --norsrc "$APP_BUILD" "$APP"

# The browser host travels inside the app, so an update replaces both halves
# of the bridge at once. Arca registers it with the browsers when it starts.
cargo build --release -p vault-native-host --manifest-path "$REPO/Cargo.toml" \
  || die "the native messaging host failed to build"
ditto --norsrc "$CARGO_OUTPUT/release/vault-native-host" "$APP/Contents/MacOS/vault-native-host"

"$REPO/scripts/assemble-app-macos.sh" "$APP" "$WORK/signing.json" "$WORK"

step "Checking the hardened runtime"
# Notarization rejects any executable without it.
#
# Read into a variable rather than piping into `grep -q`. That pipeline failed
# whenever the flag was PRESENT: grep exits the moment it matches, codesign dies
# on SIGPIPE (141), and `pipefail` turns that into the whole check failing. A
# test that only fails when its subject is correct is worse than no test.
for code in "$APP" "$APP/Contents/PlugIns/ArcaAutoFill.appex" "$APP/Contents/MacOS/vault-native-host"; do
  SIG_INFO="$(codesign -d --verbose=2 "$code" 2>&1 || true)"
  case "$SIG_INFO" in
    *"flags="*"runtime"*) echo "   $(basename "$code"): on" ;;
    *) die "$(basename "$code") is not signed with the hardened runtime." ;;
  esac
done

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
OUT="$CARGO_OUTPUT/release/bundle"
DMG="$OUT/dmg/Arca_${VERSION}_aarch64.dmg"
ARCHIVE="$OUT/macos/Arca_${VERSION}_aarch64.app.tar.gz"
mkdir -p "$OUT/dmg" "$OUT/macos"
rm -f "$DMG" "$ARCHIVE" "$ARCHIVE.sig"

keep_app() {
  rm -rf "$OUT/macos/Arca.app"
  ditto "$APP" "$OUT/macos/Arca.app"
}

if [ "$NOTARIZE" = "0" ]; then
  keep_app
  printf '\nSigned but NOT notarized (--no-notarize).\n  %s\n' "$OUT/macos/Arca.app"
  exit 0
fi

# `notarytool submit --wait` can end without a verdict of Accepted, so the
# verdict is read rather than assumed, and Apple's log explains a rejection.
notarize() {
  local file="$1" result status id
  result="$(xcrun notarytool submit "$file" "${NOTARY[@]}" \
    --wait --output-format json 2>"$WORK/notary.err" || true)"
  status="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", ""))' <<<"$result" 2>/dev/null || true)"
  id="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id", ""))' <<<"$result" 2>/dev/null || true)"
  if [ "$status" != "Accepted" ]; then
    cat "$WORK/notary.err" >&2 2>/dev/null || true
    if [ -n "$id" ]; then
      xcrun notarytool log "$id" "${NOTARY[@]}" >&2 || true
    fi
    die "Apple did not notarize $(basename "$file")${status:+ ($status)}."
  fi
  echo "   accepted: $id"
}

# The app is notarized and stapled first, so the ticket travels inside it: in
# the disk image, and in the update archive, where no disk image comes along.
step "Notarizing the app (Apple can take a few minutes)"
ditto -c -k --keepParent "$APP" "$WORK/Arca.zip"
notarize "$WORK/Arca.zip"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

step "Building the disk image"
# hdiutil, not Tauri's DMG bundler: that one drives Finder over AppleScript to
# arrange the window, and failed at random ("Can't get disk (-1728)") with
# nothing but "failed to run bundle_dmg.sh" to show for it. Same contents.
mkdir "$WORK/dmg"
# `ditto` rather than `cp -R`: it keeps what the signature depends on.
ditto "$APP" "$WORK/dmg/Arca.app"
ln -s /Applications "$WORK/dmg/Applications"
hdiutil create -volname "Arca" -srcfolder "$WORK/dmg" -ov -format UDZO "$DMG" >/dev/null
# Signed and notarized itself, so what people download is attributable too.
codesign --force --timestamp -s "$IDENTITY" "$DMG"
notarize "$DMG"
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
echo "   $(basename "$DMG") ($(du -h "$DMG" | cut -f1))"

step "Gatekeeper, as another Mac will judge them"
spctl --assess --type execute --verbose=2 "$APP" 2>&1 | tail -2
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG" 2>&1 | tail -2

step "The update installed copies download"
# The updater unpacks everything under the archive's first folder in place of
# the running app, so the archive holds Arca.app/ and nothing beside it. No
# AppleDouble "._" entries either: one at the top would be unpacked onto the
# app's own folder and fail the update.
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs -czf "$ARCHIVE" -C "$WORK" Arca.app
python3 - "$ARCHIVE" <<'PY' || die "the update archive holds more than Arca.app."
import sys, tarfile
names = tarfile.open(sys.argv[1]).getnames()
stray = [n for n in names if n != "Arca.app" and not n.startswith("Arca.app/") or "/._" in n]
sys.exit(f"   stray entries: {stray[:5]}" if stray else 0)
PY
# Bound to the version, as `tauri build` binds its own: a tampered manifest
# cannot then pair this version number with an older, signed archive.
(cd "$REPO/apps/desktop" && TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${ARCA_UPDATER_KEY_PASSWORD:-}" \
  npx --no-install tauri signer sign --private-key-path "$UPDATER_KEY" \
  --app-version "$VERSION" "$ARCHIVE" </dev/null >/dev/null) \
  || die "the update archive could not be signed."
[ -s "$ARCHIVE.sig" ] || die "no signature beside $(basename "$ARCHIVE")."
echo "   $(basename "$ARCHIVE") ($(du -h "$ARCHIVE" | cut -f1)), signed for $VERSION"

step "Writing the update manifest"
# Merged, never rewritten: scripts/update-manifest.py keeps the other
# platforms of the same version. It also refuses a signature by a key the
# installed copies do not trust, or for another version. Apple silicon only:
# this build is arm64, and an Intel Mac offered it could not open it.
python3 "$REPO/scripts/update-manifest.py" \
  --manifest "$OUT/latest.json" \
  --version "$VERSION" \
  --url "https://github.com/franzjeger/Arca/releases/download/v$VERSION/$(basename "$ARCHIVE")" \
  --signature-file "$ARCHIVE.sig" \
  --platform darwin-aarch64

keep_app
printf '\nRELEASE OK: Arca %s\n' "$VERSION"
printf '  download: %s\n' "$DMG"
printf '  update:   %s (+ .sig)\n' "$ARCHIVE"
printf '  manifest: %s\n' "$OUT/latest.json"
printf 'All three go on the v%s GitHub release; installed copies see nothing until they do.\n' "$VERSION"
