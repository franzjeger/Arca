#!/usr/bin/env bash
#
# Publish a built macOS release on GitHub: the tag, the release page, and the
# files new users and installed copies download.
#
#   scripts/publish-release.sh             # show what would be published
#   scripts/publish-release.sh --publish   # publish it
#
# It publishes what scripts/release-macos.sh left in <cargo output>/release/bundle
# for the version in tauri.conf.json, and only if that is what this checkout
# built: the app's own build info must name HEAD, clean. The release notes are
# that version's section of CHANGELOG.md.
#
# Publishing is public and immediate. Installed copies poll latest.json and
# offer the update the moment the release is out, so the release is made as a
# draft, filled and checked, and only then published.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_OUTPUT="$(python3 "$REPO/scripts/cargo-target-dir.py")"
cd "$REPO"
PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

step() { printf '\n==> %s\n' "$1"; }
die() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

# The same gate the build passed: this exact commit, clean, with full CI.
"$REPO/scripts/check-release.sh"

VERSION="$(python3 -c 'import json; print(json.load(open("apps/desktop/src-tauri/tauri.conf.json"))["version"])')"
TAG="v$VERSION"
COMMIT="$(git rev-parse HEAD)"
OUT="$CARGO_OUTPUT/release/bundle"
APP="$OUT/macos/Arca.app"
DMG="$OUT/dmg/Arca_${VERSION}_aarch64.dmg"
ARCHIVE="$OUT/macos/Arca_${VERSION}_aarch64.app.tar.gz"
MANIFEST="$OUT/latest.json"
WORK="$(mktemp -d /tmp/arca-publish.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

step "Checking what release-macos.sh built"
for file in "$DMG" "$ARCHIVE" "$ARCHIVE.sig" "$MANIFEST" "$APP/Contents/MacOS/vault-desktop"; do
  [ -e "$file" ] || die "missing $file. Run scripts/release-macos.sh."
done
BUILT="$("$APP/Contents/MacOS/vault-desktop" --build-info)"
python3 - "$BUILT" "$VERSION" "$COMMIT" <<'PY' || die "the built app is not a clean build of this checkout: $BUILT"
import json, sys
built, version, commit = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
sys.exit(0 if (built["version"], built["commit"]) == (version, commit)
         and not built["build"].endswith("-dirty") else 1)
PY
echo "   Arca $VERSION, built from $COMMIT"
xcrun stapler validate "$DMG" >/dev/null || die "$(basename "$DMG") carries no notarization ticket."
spctl --assess --type open --context context:primary-signature "$DMG" 2>/dev/null \
  || die "Gatekeeper rejects $(basename "$DMG")."
spctl --assess --type execute "$APP" 2>/dev/null || die "Gatekeeper rejects the app."
echo "   notarized, stapled and accepted by Gatekeeper"

# Every download the manifest names must be a file on this release, and the
# signature beside the archive must be the one the manifest carries.
python3 - "$MANIFEST" "$VERSION" "$TAG" "$ARCHIVE" <<'PY' || die "latest.json does not describe these files."
import json, os, sys
manifest, version, tag, archive = sys.argv[1:]
data = json.load(open(manifest))
assert data["version"] == version, f"latest.json is for {data['version']}"
prefix = f"https://github.com/franzjeger/Arca/releases/download/{tag}/"
for platform, entry in data["platforms"].items():
    assert entry["url"].startswith(prefix), f"{platform} downloads {entry['url']}"
    assert entry["url"][len(prefix):] == os.path.basename(archive), f"{platform} names a file not published here"
    assert entry["signature"] == open(archive + ".sig").read().strip(), f"{platform} carries another signature"
print("   latest.json:", ", ".join(sorted(data["platforms"])))
PY

# The version's section of the changelog, heading excluded.
awk -v version="$VERSION" '
  /^## / { if (found) exit; if ($2 == version) { found = 1; next } }
  found { print }
' CHANGELOG.md > "$WORK/notes.md"
grep -q '[^[:space:]]' "$WORK/notes.md" || die "CHANGELOG.md has no section for $VERSION."

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || git ls-remote --exit-code --tags origin "$TAG" >/dev/null; then
  die "$TAG already exists. A published version is never replaced; release a new one."
fi

step "What would be published"
echo "   $TAG at $COMMIT"
for file in "$DMG" "$ARCHIVE" "$ARCHIVE.sig" "$MANIFEST"; do
  printf '   %-40s %s\n' "$(basename "$file")" "$(du -h "$file" | cut -f1)"
done
echo "   notes: CHANGELOG.md, $VERSION ($(wc -l <"$WORK/notes.md" | tr -d ' ') lines)"
if [ "$PUBLISH" = 0 ]; then
  printf '\nNothing published. Run with --publish to publish it.\n'
  exit 0
fi

step "Publishing $TAG"
git tag -a "$TAG" -m "Arca $VERSION" "$COMMIT"
git push origin "refs/tags/$TAG"
gh release create "$TAG" --draft --verify-tag --title "Arca $VERSION" \
  --notes-file "$WORK/notes.md" "$DMG" "$ARCHIVE" "$ARCHIVE.sig" "$MANIFEST"
# The draft holds every file before anyone can see it.
ASSETS="$(gh release view "$TAG" --json assets -q '.assets[].name' | sort | tr '\n' ' ')"
EXPECTED="$(printf '%s\n' "$(basename "$DMG")" "$(basename "$ARCHIVE")" "$(basename "$ARCHIVE").sig" latest.json | sort | tr '\n' ' ')"
[ "$ASSETS" = "$EXPECTED" ] || die "the draft holds [$ASSETS], not [$EXPECTED]. It is still a draft: fix or delete it."
gh release edit "$TAG" --draft=false --latest

step "Checking what installed copies now see"
LIVE="$(curl -fsSL "https://github.com/franzjeger/Arca/releases/latest/download/latest.json")" \
  || die "the published latest.json cannot be fetched."
python3 -c 'import json,sys; v=json.loads(sys.argv[1])["version"]; sys.exit(0 if v == sys.argv[2] else f"   the endpoint says {v}")' \
  "$LIVE" "$VERSION" || die "the update endpoint does not offer $VERSION yet."
printf '\nPUBLISHED: Arca %s\n  https://github.com/franzjeger/Arca/releases/tag/%s\n' "$VERSION" "$TAG"
