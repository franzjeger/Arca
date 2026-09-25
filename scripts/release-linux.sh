#!/usr/bin/env bash
#
# Build a Linux Arca release: the AppImage the in-app updater can actually
# install, plus the .deb/.rpm most people install from.
#
#   scripts/release-linux.sh              # appimage + deb + rpm
#   scripts/release-linux.sh --appimage   # only the updatable artifact
#
# Why AppImage is not optional here: tauri-plugin-updater can replace a running
# AppImage file, and nothing else on Linux. A .deb or .rpm lives in /usr/bin and
# belongs to the package manager, so the updater has no way to apply one — an
# install from those packages can only be upgraded by apt/dnf or a rebuild.
# Shipping ONLY .deb/.rpm, which is what happened until now, is why "Check for
# updates" has never been able to do anything on Linux.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
cd "$REPO"
"$REPO/scripts/check-release.sh"

BUNDLES="appimage,deb,rpm"
[ "${1:-}" = "--appimage" ] && BUNDLES="appimage"

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# Same key, same place, same failure mode as the macOS release: without it the
# build still succeeds and produces something that can never be delivered as an
# update, which is a bad thing to discover after publishing.
UPDATER_KEY="${ARCA_UPDATER_KEY:-$HOME/.arca/arca-updater.key}"
[ -f "$UPDATER_KEY" ] || die "no update signing key at $UPDATER_KEY.
     Without it the build cannot be published as an update. Restore it from
     your backup, or (only if no release has ever shipped) generate a new one:
       cd apps/desktop && npx tauri signer generate -w \"$UPDATER_KEY\""

# A build without the Google client secret works completely except that Drive
# sync refuses to connect — silent to discover after shipping.
CLIENT_SECRET_FILE="${ARCA_GOOGLE_CLIENT_SECRET_FILE:-$HOME/.arca/google-client-secret}"
if [ -z "${ARCA_GOOGLE_CLIENT_SECRET:-}" ]; then
  [ -s "$CLIENT_SECRET_FILE" ] || die "no Google client secret at $CLIENT_SECRET_FILE.
     This build would ship with Drive sync switched off. Put the secret for the
     desktop OAuth client there (one line, chmod 600), or export
     ARCA_GOOGLE_CLIENT_SECRET. See docs/SYNC.md."
fi

# The AppImage bundler shells out to xdg-open, and reports its absence only
# after the whole release build has finished — five minutes in, with everything
# compiled and the bundle half written. Checked here so the answer arrives
# before the wait rather than after it.
command -v xdg-open >/dev/null 2>&1 || die "xdg-open is missing (package: xdg-utils).
     The AppImage bundler needs it and fails at the very end of the build
     without it. Install it first:
       Debian/Ubuntu: sudo apt install xdg-utils
       Arch/CachyOS:  sudo pacman -S --needed xdg-utils"

VERSION="$(python3 -c "import json;print(json.load(open('$REPO/apps/desktop/src-tauri/tauri.conf.json'))['version'])")"

step "Building the Linux bundles ($BUNDLES)"
# createUpdaterArtifacts is passed HERE rather than in tauri.conf.json for the
# same reason the macOS script does it: in the shared config every local dev
# build would demand the release signing key.
export TAURI_SIGNING_PRIVATE_KEY="$UPDATER_KEY"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${ARCA_UPDATER_KEY_PASSWORD:-}"
(cd "$REPO/apps/desktop" && npm run tauri build -- --bundles "$BUNDLES" \
  --config '{"bundle":{"createUpdaterArtifacts":true}}')

step "Locating the signed updater artifact"
# Tauri has changed which file carries the AppImage update between versions
# (.AppImage.tar.gz in some, the .AppImage itself in others). Rather than
# hard-code one and break on an upgrade, take whichever has a detached .sig
# beside it — that pairing is what the updater actually consumes.
APPIMAGE_DIR="$CARGO_OUTPUT/release/bundle/appimage"
UPD_ARCHIVE=""
for candidate in "$APPIMAGE_DIR"/*.AppImage.tar.gz "$APPIMAGE_DIR"/*.AppImage; do
  [ -f "$candidate" ] || continue
  [ -f "$candidate.sig" ] || continue
  UPD_ARCHIVE="$candidate"
  break
done
# Fatal, not a note. A release with no signed updater archive cannot be
# delivered as an update to anyone.
[ -n "$UPD_ARCHIVE" ] || die "no signed updater archive in $APPIMAGE_DIR.
     Everything else may have built, but installed copies could never update to
     this. Check TAURI_SIGNING_PRIVATE_KEY and createUpdaterArtifacts."

# Only ever claim the architecture this machine actually built and signed.
case "$(uname -m)" in
  x86_64)          PLATFORM="linux-x86_64" ;;
  aarch64|arm64)   PLATFORM="linux-aarch64" ;;
  *)               die "unsupported architecture $(uname -m) for the updater manifest" ;;
esac

step "Merging $PLATFORM into the update manifest"
# Merged, never rewritten: the macOS entries for this same version have to
# survive, or publishing Linux would stop every installed Mac from updating.
LATEST="$CARGO_OUTPUT/release/bundle/latest.json"
python3 "$REPO/scripts/update-manifest.py" \
  --manifest "$LATEST" \
  --version "$VERSION" \
  --url "https://github.com/franzjeger/Arca/releases/download/v$VERSION/$(basename "$UPD_ARCHIVE")" \
  --signature-file "$UPD_ARCHIVE.sig" \
  --platform "$PLATFORM"

printf '\nRELEASE OK (v%s)\n' "$VERSION"
printf '  updater artifact: %s\n' "$UPD_ARCHIVE"
printf '  manifest:         %s\n' "$LATEST"
for kind in deb rpm; do
  f="$(ls -t "$CARGO_OUTPUT/release/bundle/$kind/"*".$kind" 2>/dev/null | head -1 || true)"
  [ -n "$f" ] && printf '  %-17s %s\n' "$kind:" "$f"
done
cat <<NOTE

Publish on the v$VERSION GitHub release: the AppImage, its .sig, and latest.json
(plus the .deb/.rpm as downloads). If a macOS release for this same version was
built first, upload ITS latest.json only after this one — this file now carries
both, and the last upload wins.

The updater fetches the manifest with no credentials. While the repository is
private that request 404s for everyone, so publishing alone will not make
"Check for updates" work; the manifest and artifacts have to be reachable
anonymously.
NOTE
