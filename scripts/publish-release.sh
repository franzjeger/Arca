#!/usr/bin/env bash
#
# Publish a release on GitHub: the tag, the release page, and the files new
# users and installed copies download, for macOS and Linux together.
#
#   scripts/publish-release.sh             # show what would be published
#   scripts/publish-release.sh --publish   # publish it
#
# It publishes what scripts/release-macos.sh left in <cargo output>/release/bundle
# for the version in tauri.conf.json, and only if that is what this checkout
# built: the app's own build info must name HEAD, clean. The release notes are
# that version's section of CHANGELOG.md.
#
# The Linux half is built on GitHub, by .github/workflows/release-linux.yml,
# which this script starts against the draft and waits for. It used to be a
# separate script run by hand on a Linux machine; nobody ran it, so no release
# carried Linux and no Linux install could update itself. Now a release is not
# published without it.
#
# Publishing is public and immediate. Installed copies poll latest.json and
# offer the update the moment the release is out, so the release is made as a
# draft, filled and checked, and only then published. If the Linux build fails,
# the draft stays a draft; running this again finishes it.
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
LINUX_WORKFLOW="release-linux.yml"
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

# Every download the Mac's manifest names must be one of these files, and the
# signature beside the archive must be the one the manifest carries.
MAC_FILES=("$DMG" "$ARCHIVE" "$ARCHIVE.sig" "$MANIFEST")
for file in "${MAC_FILES[@]}"; do basename "$file"; done > "$WORK/mac-assets.txt"
python3 scripts/check-manifest.py --manifest "$MANIFEST" --version "$VERSION" \
  --assets "$WORK/mac-assets.txt" --sig-dir "$(dirname "$ARCHIVE")" --expect darwin-aarch64 \
  || die "latest.json does not describe these files."

# The version's section of the changelog, heading excluded.
awk -v version="$VERSION" '
  /^## / { if (found) exit; if ($2 == version) { found = 1; next } }
  found { print }
' CHANGELOG.md > "$WORK/notes.md"
grep -q '[^[:space:]]' "$WORK/notes.md" || die "CHANGELOG.md has no section for $VERSION."

# The Linux half needs the workflow on GitHub and its secrets. Checked before
# anything is tagged, so a missing secret is found here rather than with a tag
# pushed and a draft waiting.
step "Checking GitHub can build the Linux release"
gh workflow view "$LINUX_WORKFLOW" >/dev/null 2>&1 \
  || die "GitHub has no $LINUX_WORKFLOW workflow. It runs from the default branch; merge it first."
SECRETS="$(gh secret list --env release --json name -q '.[].name' 2>/dev/null)" \
  || die "cannot read the secrets of the release environment. Set it up as docs/RELEASING.md describes."
for secret in ARCA_UPDATER_KEY ARCA_GOOGLE_CLIENT_SECRET; do
  grep -qx "$secret" <<<"$SECRETS" || die "the release environment has no $secret secret (docs/RELEASING.md)."
done
echo "   $LINUX_WORKFLOW and the release environment's secrets are in place"

# A tag that exists is never replaced, with one exception: the draft this script
# left behind when the Linux build failed. Nobody can have seen it, and its tag
# is this commit, so it is finished rather than released again.
RESUME=0
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || git ls-remote --exit-code --tags origin "$TAG" >/dev/null; then
  draft="$(gh release view "$TAG" --json isDraft -q .isDraft 2>/dev/null || true)"
  tagged="$(git rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null \
    || git ls-remote origin "refs/tags/$TAG^{}" | cut -f1)"
  [ "$draft" = true ] && [ "$tagged" = "$COMMIT" ] \
    || die "$TAG already exists. A published version is never replaced; release a new one."
  RESUME=1
fi

step "What would be published"
if [ "$RESUME" = 1 ]; then
  echo "   $TAG at $COMMIT: finishing the draft a previous run left"
else
  echo "   $TAG at $COMMIT"
fi
for file in "${MAC_FILES[@]}"; do
  printf '   %-40s %s\n' "$(basename "$file")" "$(du -h "$file" | cut -f1)"
done
echo "   + the Linux AppImage, its .sig, .deb and .rpm, built on GitHub by $LINUX_WORKFLOW,"
echo "     with linux-x86_64 merged into latest.json"
echo "   notes: CHANGELOG.md, $VERSION ($(wc -l <"$WORK/notes.md" | tr -d ' ') lines)"
if [ "$PUBLISH" = 0 ]; then
  printf '\nNothing published. Run with --publish to publish it.\n'
  exit 0
fi

if [ "$RESUME" = 1 ]; then
  step "Putting this build's Mac files back on the $TAG draft"
  # Including the Mac's own latest.json: the Linux build below merges into
  # whatever is there, so it starts again from this build's.
  gh release upload "$TAG" "${MAC_FILES[@]}" --clobber
else
  step "Drafting $TAG"
  git tag -a "$TAG" -m "Arca $VERSION" "$COMMIT"
  git push origin "refs/tags/$TAG"
  gh release create "$TAG" --draft --verify-tag --title "Arca $VERSION" \
    --notes-file "$WORK/notes.md" "${MAC_FILES[@]}"
fi

step "Building the Linux half on GitHub"
# Dispatched on the tag, so the workflow that builds the release is the one the
# release carries. The run is found by commit and start time: the dispatch
# itself returns no id.
since="$(python3 -c 'import datetime as d; print((d.datetime.now(d.timezone.utc) - d.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
gh workflow run "$LINUX_WORKFLOW" --ref "$TAG" -f tag="$TAG"
RUN=""
for _ in $(seq 36); do
  RUN="$(gh run list --workflow "$LINUX_WORKFLOW" --event workflow_dispatch --commit "$COMMIT" \
    --limit 10 --json databaseId,createdAt \
    -q "[.[] | select(.createdAt >= \"$since\")] | sort_by(.createdAt) | last | .databaseId // empty")"
  [ -n "$RUN" ] && break
  sleep 5
done
[ -n "$RUN" ] || die "the Linux release workflow did not start. $TAG is still a draft; run this again to finish it."
echo "   $(gh run view "$RUN" --json url -q .url)"
echo "   waiting for it (about 20 minutes)…"
gh run watch "$RUN" --exit-status --interval 30 >/dev/null \
  || die "the Linux release failed: $(gh run view "$RUN" --json url -q .url)
     $TAG is still a draft with the Mac files on it. Fix the cause and run this
     script again; it finishes the draft rather than starting over."

step "Checking the draft carries both platforms"
mkdir -p "$WORK/release"
gh release view "$TAG" --json assets -q '.assets[].name' | sort > "$WORK/assets.txt"
gh release download "$TAG" --pattern latest.json --pattern '*.sig' --dir "$WORK/release"
# The Mac files on the draft are this build's.
cmp -s "$WORK/release/$(basename "$ARCHIVE").sig" "$ARCHIVE.sig" \
  || die "the archive signature on the $TAG draft is not this build's. It is still a draft: fix or delete it."
python3 scripts/check-manifest.py --manifest "$WORK/release/latest.json" --version "$VERSION" \
  --assets "$WORK/assets.txt" --sig-dir "$WORK/release" \
  --expect darwin-aarch64 --expect linux-x86_64 \
  || die "the draft's latest.json does not describe its files. It is still a draft: fix or delete it."
# Exactly the files a release carries, nothing left over from an earlier attempt.
python3 - "$WORK/assets.txt" "$WORK/mac-assets.txt" <<'PY' \
  || die "the $TAG draft holds other files than a release carries. It is still a draft: fix or delete it."
import sys
assets = set(open(sys.argv[1]).read().split())
mac = set(open(sys.argv[2]).read().split())
linux = assets - mac
kinds = {kind: sorted(n for n in linux if n.endswith(kind))
         for kind in (".AppImage", ".AppImage.sig", ".deb", ".rpm")}
problems = [f"no Mac file {name}" for name in sorted(mac - assets)]
problems += [f"{len(names)} {kind} files" for kind, names in kinds.items() if len(names) != 1]
problems += [f"unexpected {name}" for name in sorted(linux - {n for v in kinds.values() for n in v})]
for problem in problems:
    print(f"   {problem}", file=sys.stderr)
print("   " + ", ".join(sorted(assets)))
sys.exit(1 if problems else 0)
PY

step "Publishing $TAG"
gh release edit "$TAG" --draft=false --latest

step "Checking what installed copies now see"
LIVE="$(curl -fsSL "https://github.com/franzjeger/Arca/releases/latest/download/latest.json")" \
  || die "the published latest.json cannot be fetched."
python3 - "$LIVE" "$VERSION" <<'PY' || die "the update endpoint does not offer $VERSION to both platforms yet."
import json, sys
live, version = json.loads(sys.argv[1]), sys.argv[2]
platforms = sorted(live.get("platforms", {}))
print(f"   the endpoint offers {live.get('version')} to {', '.join(platforms)}")
sys.exit(0 if live.get("version") == version
         and {"darwin-aarch64", "linux-x86_64"} <= set(platforms) else 1)
PY
printf '\nPUBLISHED: Arca %s\n  https://github.com/franzjeger/Arca/releases/tag/%s\n' "$VERSION" "$TAG"
