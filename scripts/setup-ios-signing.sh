#!/usr/bin/env bash
#
# One-time (or after expiry) iOS distribution signing setup.
#
#   scripts/setup-ios-signing.sh
#
# Mints an Apple Distribution certificate through the App Store Connect API,
# keeps its private key on this machine, and creates the three App Store
# provisioning profiles release-ios.sh signs with.
#
# WHY THIS EXISTS
#
# Xcode's automatic signing wants a CLOUD-MANAGED distribution certificate:
# Apple holds the private key and hands it out at export time. That handout is
# authorized only by the Apple ID signed into Xcode.app. An App Store Connect
# API key cannot authorize it no matter what role it has — an Admin key reads
# /v1/certificates happily and still gets "Cloud signing permission error" at
# export. And xcodebuild invoked outside Xcode cannot reach the Xcode account
# either; it reports "No Accounts: Add a new account in Accounts settings" while
# the account sits right there in Xcode ▸ Settings ▸ Accounts.
#
# So the two mechanisms never meet, and the release is stuck between them. A
# certificate we generate the key for ourselves belongs to neither mechanism and
# works with both.
#
# WHAT IT LEAVES BEHIND
#
#   ~/.arca/signing/dist.key            the distribution private key   BACK THIS UP
#   ~/.arca/signing/dist.cer            the certificate Apple issued
#   ~/.arca/signing/keychain-password   password for the keychain below
#   ~/Library/Keychains/arca-signing.keychain-db
#
# A separate keychain, not the login one: signing then needs no interactive
# unlock and no GUI "allow access" click, and the login keychain is untouched.
# Removing it again is `security delete-keychain arca-signing.keychain` plus a
# `security list-keychains -d user -s ...` without it.
#
# Losing dist.key means generating a new certificate — Apple allows a small
# number of distribution certificates, so revoke the old one first if you hit
# the limit. Existing App Store builds are unaffected; they are already signed.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
D="$HOME/.arca/signing"
KCNAME="arca-signing.keychain"
KC="$HOME/Library/Keychains/$KCNAME-db"
SUFFIXES=("" ".autofill" ".widgets")

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

command -v python3 >/dev/null || die "python3 is required."
python3 -c 'import jwt' 2>/dev/null || die "python3 needs PyJWT:  python3 -m pip install pyjwt"

KEY_FILE="${ARCA_ASC_KEY:-$HOME/.arca/asc-api-key}"
[ -s "$KEY_FILE" ] || die "no App Store Connect API key at $KEY_FILE. See release-ios.sh."

mkdir -p "$D"
chmod 700 "$D"

step "Private key and signing request"
if [ -f "$D/dist.key" ]; then
  echo "   reusing $D/dist.key"
else
  openssl genrsa -out "$D/dist.key" 2048 2>/dev/null
  chmod 600 "$D/dist.key"
  echo "   generated $D/dist.key"
fi
openssl req -new -key "$D/dist.key" -out "$D/dist.csr" \
  -subj "/CN=Arca Distribution/C=NO" 2>/dev/null

step "Asking Apple for the certificate and profiles"
ARCA_SIGNING_DIR="$D" python3 "$REPO/scripts/lib/asc_signing.py"

step "Importing into a dedicated keychain"
if [ ! -f "$D/keychain-password" ]; then
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 > "$D/keychain-password"
  chmod 600 "$D/keychain-password"
fi
PW="$(cat "$D/keychain-password")"

security delete-keychain "$KCNAME" 2>/dev/null || true
security create-keychain -p "$PW" "$KCNAME"
# No timeout and no lock on sleep. A keychain that relocks mid-build produces a
# signing failure that reads like a certificate problem and is not one.
security set-keychain-settings "$KCNAME"
security unlock-keychain -p "$PW" "$KCNAME"
security import "$D/dist.key" -k "$KCNAME" -P "" \
  -T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/security
security import "$D/dist.cer" -k "$KCNAME" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$PW" "$KCNAME" >/dev/null

# Append without dropping what was already searched. Rebuilding this list from a
# guess is how a login keychain stops being found.
EXISTING="$(security list-keychains -d user | sed -e 's/^ *"//' -e 's/"$//' | grep -v "$KCNAME" || true)"
# shellcheck disable=SC2086
security list-keychains -d user -s $EXISTING "$KC"

step "Verifying"
security find-identity -v -p codesigning | grep -q "Apple Distribution" \
  || die "the Apple Distribution identity is not usable — import failed."
echo "   Apple Distribution identity present"

DEST="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
for suffix in "${SUFFIXES[@]}"; do
  name="Arca App Store no.sybr.vault.ios$suffix"
  found=0
  for f in "$DEST"/*.mobileprovision; do
    [ -f "$f" ] || continue
    if security cms -D -i "$f" 2>/dev/null | plutil -extract Name raw - 2>/dev/null \
       | grep -qx "$name"; then found=1; break; fi
  done
  [ "$found" = 1 ] || die "profile \"$name\" was not installed."
  echo "   $name"
done

cat <<'DONE'

Done. scripts/release-ios.sh will now sign and upload without Xcode's account.

BACK UP ~/.arca/signing/ alongside the updater key and the .p8. Losing dist.key
costs a new certificate, and Apple caps how many you may hold at once.
DONE
