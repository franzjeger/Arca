#!/usr/bin/env bash
#
# One-time (or after expiry) macOS Developer ID signing setup.
#
#   scripts/setup-macos-signing.sh           # create what is missing
#   scripts/setup-macos-signing.sh --check   # read only: what exists
#
# What a published macOS release needs, through the App Store Connect API with
# the key release-ios.sh already uses:
#
#   * a Developer ID Application certificate, its private key generated HERE.
#     Only the Account Holder may create one, and not with an API key: the
#     first run stops with the steps for the developer portal, which takes the
#     signing request written here, and the next run finds the certificate;
#   * Developer ID profiles for the app and its AutoFill extension, which grant
#     the App Group, shared keychain and AutoFill capabilities on every Mac;
#   * notarization credentials in the login keychain, from the same API key,
#     so no Apple ID password or app-specific password is involved.
#
# WHAT IT LEAVES BEHIND
#
#   ~/.arca/signing/developer-id.key     the private key   BACK THIS UP
#   ~/.arca/signing/developer-id.cer     the certificate Apple issued
#   ~/.arca/signing/developer-id-keychain-password
#   ~/Library/Keychains/arca-developer-id.keychain-db
#   ~/Library/Developer/Xcode/UserData/Provisioning Profiles/*.provisionprofile
#   a notarytool profile named "arca-notary"
#
# Its own keychain, apart from the iPhone's: setup-ios-signing.sh recreates that
# one from scratch, which would take this key with it.
#
# Losing developer-id.key means a new certificate. Apple caps how many a team
# may hold; revoke unused ones in the developer portal when that bites. What is
# already signed and notarized keeps working either way.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
D="$HOME/.arca/signing"
KCNAME="arca-developer-id.keychain"
KC="$HOME/Library/Keychains/$KCNAME-db"
NOTARY_PROFILE="${ARCA_NOTARY_PROFILE:-arca-notary}"

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

command -v python3 >/dev/null || die "python3 is required."
python3 -c 'import jwt' 2>/dev/null || die "python3 needs PyJWT:  python3 -m pip install pyjwt"

KEY_FILE="${ARCA_ASC_KEY:-$HOME/.arca/asc-api-key}"
[ -s "$KEY_FILE" ] || die "no App Store Connect API key at $KEY_FILE. See release-ios.sh."

if [ "${1:-}" = "--check" ]; then
  step "What the account has (nothing is changed)"
  python3 "$REPO/scripts/lib/asc_developer_id.py" --check
  exit 0
fi

mkdir -p "$D"
chmod 700 "$D"

step "Private key and signing request"
if [ -f "$D/developer-id.key" ]; then
  echo "   reusing $D/developer-id.key"
else
  openssl genrsa -out "$D/developer-id.key" 2048 2>/dev/null
  chmod 600 "$D/developer-id.key"
  echo "   generated $D/developer-id.key"
fi
openssl req -new -key "$D/developer-id.key" -out "$D/developer-id.csr" \
  -subj "/CN=Arca Developer ID/C=NO" 2>/dev/null

step "Importing the key into its own keychain"
if [ ! -f "$D/developer-id-keychain-password" ]; then
  # Not `tr </dev/urandom | head`: under pipefail the tr that head cuts off
  # fails the pipeline, and set -e ended the script here without a word.
  openssl rand -hex 16 > "$D/developer-id-keychain-password"
  chmod 600 "$D/developer-id-keychain-password"
fi
PW="$(cat "$D/developer-id-keychain-password")"
security delete-keychain "$KCNAME" 2>/dev/null || true
security create-keychain -p "$PW" "$KCNAME"
# No timeout and no lock on sleep: a keychain that relocks mid-build fails the
# signature in words that blame the certificate.
security set-keychain-settings "$KCNAME"
security unlock-keychain -p "$PW" "$KCNAME"
security import "$D/developer-id.key" -k "$KCNAME" -P "" \
  -T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/security
EXISTING="$(security list-keychains -d user | sed -e 's/^ *"//' -e 's/"$//' | grep -v "$KCNAME" || true)"
# shellcheck disable=SC2086
security list-keychains -d user -s $EXISTING "$KC"

step "Asking Apple for the certificate and profiles"
ARCA_SIGNING_DIR="$D" python3 "$REPO/scripts/lib/asc_developer_id.py"
[ -s "$D/developer-id.cer" ] || die "no certificate at $D/developer-id.cer."
# The keychain is new on every run, so this never meets a copy already there.
security import "$D/developer-id.cer" -k "$KCNAME" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$PW" "$KCNAME" >/dev/null

step "Notarization credentials from the same API key"
KEY_ID="$(sed -n 1p "$KEY_FILE" | tr -d '[:space:]')"
ISSUER_ID="$(sed -n 2p "$KEY_FILE" | tr -d '[:space:]')"
P8="$HOME/.appstoreconnect/private_keys/AuthKey_${KEY_ID}.p8"
[ -f "$P8" ] || die "no private key at $P8."
xcrun notarytool store-credentials "$NOTARY_PROFILE" \
  --key "$P8" --key-id "$KEY_ID" --issuer "$ISSUER_ID" >/dev/null
xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null \
  || die "notarytool cannot use the stored credentials."
echo "   $NOTARY_PROFILE"

step "Verifying"
security find-identity -v -p codesigning | grep -q "Developer ID Application" \
  || die "the Developer ID Application identity is not usable — import failed."
python3 "$REPO/scripts/prepare-autofill-signing.py" --distribution --plan /dev/null \
  || die "the Developer ID profiles do not cover the app and its extension."
echo "   identity, both profiles and notarization ready"

cat <<'DONE'

Done. scripts/release-macos.sh can now sign, notarize and staple.

BACK UP ~/.arca/signing/ alongside the updater key and the .p8.
DONE
