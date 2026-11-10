#!/usr/bin/env bash
#
# Start a built AppImage the way a user would, in a home of its own, and check
# that it gave the browsers a host they can use after it has exited:
#
#   scripts/test-appimage-host.sh target/release/bundle/appimage/Arca_*.AppImage
#
# An AppImage runs from a mount that is gone once it exits, so the host inside
# it is useless to a browser. Arca copies it out to ~/.local/lib/arca-appimage
# and registers the copy (apps/desktop/src-tauri/src/browser_host.rs). Unit
# tests cover that logic; this covers the parts only a real AppImage has: that
# the host is inside it at all, that the AppImage runtime sets what Arca reads
# to recognise itself, and that the result answers a browser's handshake.
#
# Nothing here touches the real session: its own HOME and XDG folders, a
# private D-Bus (Arca's single-instance check would otherwise find a running
# Arca and hand over to it), and a virtual X display. Needs xvfb-run and
# dbus-run-session.
set -euo pipefail

APPIMAGE="$(realpath "${1:?usage: $0 path/to/Arca.AppImage}")"
[ -x "$APPIMAGE" ] || { echo "not an executable file: $APPIMAGE" >&2; exit 1; }
for tool in xvfb-run dbus-run-session; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/arca-appimage-host.XXXXXX")"
# Arca runs in a session of its own, whose id it writes from inside: with job
# control on, a backgrounded `setsid` forks and $! is not that session.
SESSION="$WORK/session"
stop_arca() {
  [ -s "$SESSION" ] || return 0
  local sid; sid="$(cat "$SESSION")"
  pkill -TERM -s "$sid" 2>/dev/null || true
  for _ in $(seq 20); do pgrep -s "$sid" >/dev/null || break; sleep 0.25; done
  pkill -KILL -s "$sid" 2>/dev/null || true
  rm -f "$SESSION"
}
trap 'stop_arca; rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $1" >&2; [ -f "$WORK/app.log" ] && sed 's/^/   app: /' "$WORK/app.log" >&2; exit 1; }
ok() { echo "ok: $1"; }

# A browser's first message, sent to a host as a browser in the test home
# would start it: it must not find a real Arca through the real home.
hello() {
  printf '\x10\x00\x00\x00{"type":"hello"}' \
    | env HOME="$HOME_DIR" XDG_CONFIG_HOME="$HOME_DIR/.config" XDG_DATA_HOME="$HOME_DIR/.local/share" "$1" \
    | tail -c +5
}

HOME_DIR="$WORK/home"
mkdir -p "$HOME_DIR/.config/google-chrome" "$HOME_DIR/.mozilla" "$WORK/tmp"

# 1. The host is inside the AppImage, next to Arca.
(cd "$WORK" && "$APPIMAGE" --appimage-extract usr/bin/vault-native-host >/dev/null)
BUNDLED="$WORK/squashfs-root/usr/bin/vault-native-host"
[ -x "$BUNDLED" ] || fail "the AppImage carries no usr/bin/vault-native-host"
ok "the AppImage carries the browser host"

# 2. Run it, and wait for the registration it writes at startup.
REGISTRATION="$HOME_DIR/.config/google-chrome/NativeMessagingHosts/no.sybr.vault.json"
# Extracted rather than mounted (no FUSE on CI runners): the same AppImage
# runtime, which sets APPIMAGE the same way, and leaves no mount behind.
export SESSION
setsid sh -c 'echo $$ > "$SESSION"; exec "$@"' sh \
  env -u WAYLAND_DISPLAY -u DISPLAY \
  HOME="$HOME_DIR" XDG_CONFIG_HOME="$HOME_DIR/.config" XDG_DATA_HOME="$HOME_DIR/.local/share" \
  XDG_CACHE_HOME="$HOME_DIR/.cache" XDG_STATE_HOME="$HOME_DIR/.local/state" \
  GDK_BACKEND=x11 APPIMAGE_EXTRACT_AND_RUN=1 TMPDIR="$WORK/tmp" \
  dbus-run-session -- xvfb-run -a "$APPIMAGE" >"$WORK/app.log" 2>&1 &
for _ in $(seq 120); do
  [ -s "$REGISTRATION" ] && break
  { [ -s "$SESSION" ] && ! pgrep -s "$(cat "$SESSION")" >/dev/null; } \
    && fail "Arca exited before registering the browser host"
  sleep 0.5
done
[ -s "$REGISTRATION" ] || fail "no registration in $REGISTRATION after 60 seconds"
# Let the Firefox registration land too, then close Arca: everything below has
# to work with the AppImage no longer running, as it is for a browser.
sleep 1
stop_arca
ok "Arca registered the browser host at startup"

# 3. The registrations name the copy, and the copy is the bundled host.
HOST="$HOME_DIR/.local/lib/arca-appimage/vault-native-host"
for file in "$REGISTRATION" "$HOME_DIR/.mozilla/native-messaging-hosts/no.sybr.vault.json"; do
  [ -s "$file" ] || fail "missing $file"
  named="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["path"])' "$file")"
  [ "$named" = "$HOST" ] || fail "$file names $named, not $HOST"
done
ok "Chrome and Firefox are registered with the host copied out of the AppImage"
cmp -s "$HOST" "$BUNDLED" || fail "the copied host is not the one in the AppImage"
[ -x "$HOST" ] || fail "the copied host is not executable"
ok "the copy is the AppImage's own host"

# 4. The link the host starts Arca from leads back to this AppImage.
LINK="$HOME_DIR/.local/lib/arca-appimage/Arca.AppImage"
[ "$(readlink "$LINK")" = "$APPIMAGE" ] || fail "$LINK leads to $(readlink "$LINK" || echo nothing), not $APPIMAGE"
ok "the host starts Arca from $(basename "$APPIMAGE")"

# 5. With Arca closed and its mount gone, the copy answers a browser, knows
# Arca is not running, and knows where to start it: in this home only the link
# can tell it, so it is taken away again to show that it was the link.
field() { python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]).get(sys.argv[2])))' "$1" "$2"; }
reply="$(hello "$HOST")"
case "$reply" in
  *'"name":"no.sybr.vault"'*) ok "the copied host answers the native-messaging handshake" ;;
  *) fail "the copied host did not answer hello: $reply" ;;
esac
[ "$(field "$reply" app_connected)" = false ] || fail "the host reached an Arca it should not: $reply"
if [ -e /usr/bin/vault-desktop ]; then
  echo "skip: a package install at /usr/bin/vault-desktop would start Arca as well"
else
  [ "$(field "$reply" app_launchable)" = true ] || fail "the host cannot find Arca to start: $reply"
  mv "$LINK" "$LINK.away"
  [ "$(field "$(hello "$HOST")" app_launchable)" = false ] || fail "the host finds Arca without the link"
  mv "$LINK.away" "$LINK"
  ok "the host finds Arca to start through the link, and only through it"
fi

echo "APPIMAGE HOST OK"
