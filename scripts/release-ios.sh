#!/usr/bin/env bash
#
# Build, sign and upload Arca for iOS to TestFlight.
#
#   scripts/release-ios.sh              # archive, export, upload
#   scripts/release-ios.sh --no-upload  # stop after the .ipa (local check)
#
# One-time setup, both on Frank's Apple account and therefore not scriptable:
#
#   1. An app record at appstoreconnect.apple.com for bundle id
#      no.sybr.vault.ios. Without it the upload is rejected with a message
#      about the bundle id not being found, which reads like a signing problem
#      and is not one.
#
#   2. An App Store Connect API key with the ADMIN role, so this can sign and
#      upload without a password living anywhere. Users and Access ▸ Integrations
#      ▸ App Store Connect API ▸ generate a key, then:
#
#      The role matters and "App Manager" is not enough. App Manager can upload
#      a build but cannot ask Apple for a signing certificate, and the export
#      then fails with "Cloud signing permission error" — which sounds like a
#      network problem and is a permissions one. Admin can do both.
#
#        mkdir -p ~/.appstoreconnect/private_keys
#        mv ~/Downloads/AuthKey_XXXXXXXXXX.p8 ~/.appstoreconnect/private_keys/
#        printf 'XXXXXXXXXX\n<issuer-uuid>\n' > ~/.arca/asc-api-key
#
#      The .p8 is downloadable exactly once. Back it up with the updater key.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
"$REPO/scripts/check-release.sh"
UPLOAD=1
[ "${1:-}" = "--no-upload" ] && UPLOAD=0

TEAM_ID="LY6LJ395B8"
ARCHIVE="$REPO/target/ios/Arca.xcarchive"
EXPORT_DIR="$REPO/target/ios/export"

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# TestFlight rejects a build whose (version, build) pair it has already seen,
# and it does so AFTER the upload, by email, minutes later. Deriving the build
# number from the commit count makes a repeat impossible without also being a
# repeat of the source.
BUILD_NUMBER="$(git rev-list --count HEAD)"
step "Build $BUILD_NUMBER"

# The API key is read HERE, not just before the upload, because xcodebuild can
# use it too — and must.
#
# `-allowProvisioningUpdates` on its own authenticates as the Apple ID signed
# into Xcode. That session expires, and when it does xcodebuild cannot renew it:
# renewal means a two-factor prompt, and there is no window to show one in. The
# failure reads "No Accounts: Add a new account in Accounts settings" even when
# the account is right there in Xcode ▸ Settings ▸ Accounts, which sends you
# looking in the wrong place. Ask me how I know.
#
# Given the key, xcodebuild talks to App Store Connect directly and can create
# the distribution certificate and the profiles it needs — including for a
# target added since the last release, which is the case that breaks.
KEY_FILE="${ARCA_ASC_KEY:-$HOME/.arca/asc-api-key}"
[ -s "$KEY_FILE" ] || die "no App Store Connect API key id at $KEY_FILE.
     See the header of this script — it is a one-time setup, and without it the
     only way up is dragging the .ipa through Xcode's Organizer."
KEY_ID="$(sed -n 1p "$KEY_FILE")"
ISSUER_ID="$(sed -n 2p "$KEY_FILE")"
[ -n "$KEY_ID" ] && [ -n "$ISSUER_ID" ] || die "$KEY_FILE needs the key id on line 1 and the issuer uuid on line 2."
KEY_P8="$HOME/.appstoreconnect/private_keys/AuthKey_$KEY_ID.p8"
[ -f "$KEY_P8" ] || die "no private key at $KEY_P8.
     The .p8 downloads exactly once; if it is gone, generate a new key."
ASC_AUTH=(
  -authenticationKeyPath "$KEY_P8"
  -authenticationKeyID "$KEY_ID"
  -authenticationKeyIssuerID "$ISSUER_ID"
)

step "Archiving"
xcodebuild -project apps/ios/Arca.xcodeproj -scheme Arca -configuration Release \
  -destination 'generic/platform=iOS' -archivePath "$ARCHIVE" \
  -allowProvisioningUpdates "${ASC_AUTH[@]}" \
  CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
  archive
[ -d "$ARCHIVE" ] || die "no archive at $ARCHIVE"

# Export signs MANUALLY, against a certificate and profiles this machine owns.
#
# Automatic signing wanted a cloud-managed distribution certificate — one whose
# private key lives at Apple and is fetched at export time. That fetch is only
# authorized by the Apple ID signed into Xcode, never by an API key, whatever
# role the key has (an Admin key reads /v1/certificates fine and still gets
# "Cloud signing permission error" here). And xcodebuild launched outside Xcode
# cannot use that account, so the two halves never met.
#
# scripts/setup-ios-signing.sh mints a real Apple Distribution certificate
# through the same API, keeps the private key on this machine, and creates the
# three App Store profiles. Nothing then has to be asked of Apple at export.
step "Checking the signing identity and profiles are present"
security find-identity -v -p codesigning 2>/dev/null | grep -q "Apple Distribution" \
  || die "no Apple Distribution identity in the keychain search list.
     Run scripts/setup-ios-signing.sh — it creates one and installs the profiles."
for suffix in "" ".autofill" ".widgets"; do
  name="Arca App Store no.sybr.vault.ios$suffix"
  found=0
  for f in "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"/*.mobileprovision; do
    [ -f "$f" ] || continue
    if security cms -D -i "$f" 2>/dev/null | plutil -extract Name raw - 2>/dev/null \
       | grep -qx "$name"; then found=1; break; fi
  done
  [ "$found" = 1 ] || die "missing provisioning profile \"$name\".
     Run scripts/setup-ios-signing.sh."
done
echo "   Apple Distribution + 3 App Store profiles"

# Unlock the dedicated signing keychain non-interactively and re-authorize
# codesign, or the export pops a GUI password prompt for a 32-char random
# password nobody has memorized — and a wrong guess there (a login password,
# say) just fails. setup-ios-signing.sh sets no auto-lock, but a reboot relocks
# every keychain, so do it here every run.
KC_NAME="arca-signing.keychain"
KC_PW_FILE="$HOME/.arca/signing/keychain-password"
if [ -s "$KC_PW_FILE" ] && security list-keychains -d user | grep -q "$KC_NAME"; then
  KC_PW="$(cat "$KC_PW_FILE")"
  if security unlock-keychain -p "$KC_PW" "$KC_NAME" 2>/dev/null; then
    security set-key-partition-list -S apple-tool:,apple:,codesign: \
      -s -k "$KC_PW" "$KC_NAME" >/dev/null 2>&1 || true
    echo "   signing keychain unlocked"
  else
    die "could not unlock $KC_NAME with the stored password.
     The keychain and ~/.arca/signing/keychain-password are out of sync.
     Fix: scripts/setup-ios-signing.sh (reuses dist.key, recreates the keychain)."
  fi
fi

step "Exporting for the App Store"
rm -rf "$EXPORT_DIR"
cat > "$REPO/target/ios/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>app-store-connect</string>
    <key>teamID</key><string>$TEAM_ID</string>
    <key>signingStyle</key><string>manual</string>
    <key>signingCertificate</key><string>Apple Distribution</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>no.sybr.vault.ios</key><string>Arca App Store no.sybr.vault.ios</string>
        <key>no.sybr.vault.ios.autofill</key><string>Arca App Store no.sybr.vault.ios.autofill</string>
        <key>no.sybr.vault.ios.widgets</key><string>Arca App Store no.sybr.vault.ios.widgets</string>
    </dict>
    <key>uploadSymbols</key><true/>
    <key>destination</key><string>export</string>
</dict>
</plist>
PLIST
xcodebuild -exportArchive -archivePath "$ARCHIVE" \
  -exportOptionsPlist "$REPO/target/ios/ExportOptions.plist" \
  -exportPath "$EXPORT_DIR" -allowProvisioningUpdates "${ASC_AUTH[@]}"

IPA="$EXPORT_DIR/Arca.ipa"
[ -f "$IPA" ] || die "no .ipa at $IPA"

# A development signature exports fine and is refused at upload. Catch it here,
# where the message can say which one it is.
step "Checking the signature is a DISTRIBUTION one"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
(cd "$WORK" && unzip -q "$IPA")
AUTHORITY="$(codesign -d --verbose=2 "$WORK/Payload/Arca.app" 2>&1 \
  | grep -m1 '^Authority=' || true)"
case "$AUTHORITY" in
  *"Apple Distribution"*) echo "   ${AUTHORITY#Authority=}" ;;
  *) die "signed with ${AUTHORITY#Authority=}, not Apple Distribution.
     TestFlight will refuse this. Check the export method." ;;
esac
# The App Store profile carries no device list; a development one does. This is
# the difference that decides whether the build runs on anybody else's phone.
if security cms -D -i "$WORK/Payload/Arca.app/embedded.mobileprovision" 2>/dev/null \
   | plutil -p - 2>/dev/null | grep -q ProvisionedDevices; then
  die "the embedded profile has a device list — that is a development profile."
fi
echo "   App Store profile (no device list)"

if [ "$UPLOAD" = "0" ]; then
  printf '\nBuilt but NOT uploaded (--no-upload).\n  %s\n' "$IPA"
  exit 0
fi

# Validation is best-effort, and deliberately NOT a gate. altool's --validate-app
# wraps Apple's Transporter, which intermittently dies with an internal
# "Defaults.properties couldn't be opened" (a Transporter resource quirk, not a
# problem with the build). The upload runs its own server-side validation, so a
# failed pre-check must warn, not abort a good archive.
step "Validating with App Store Connect (best-effort)"
if ! xcrun altool --validate-app -f "$IPA" -t ios \
     --apiKey "$KEY_ID" --apiIssuer "$ISSUER_ID"; then
  echo "   validation pre-check failed (often Transporter's Defaults.properties"
  echo "   quirk); continuing to upload, which validates server-side."
fi

step "Uploading"
xcrun altool --upload-app -f "$IPA" -t ios \
  --apiKey "$KEY_ID" --apiIssuer "$ISSUER_ID"

printf '\nUPLOADED build %s.\n' "$BUILD_NUMBER"
echo "Apple processes it for a few minutes, then it appears in TestFlight."
echo "First upload only: answer the export-compliance question in App Store Connect."
