#!/usr/bin/env bash
# Isolate the OS clipboard smoke test in a disposable headless compositor.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

wayland_test_dir="$(mktemp -d)"
chmod 700 "$wayland_test_dir"
sway_pid=""
cleanup() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        cat "$wayland_test_dir/sway.log" >&2
    fi
    if [ -n "$sway_pid" ]; then
        kill "$sway_pid" 2>/dev/null || true
        wait "$sway_pid" 2>/dev/null || true
    fi
    rm -rf "$wayland_test_dir"
    exit "$status"
}
trap cleanup EXIT

export XDG_RUNTIME_DIR="$wayland_test_dir"
export WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1
# Refuse accidental success through X11/XWayland or the user's own compositor.
unset DISPLAY WAYLAND_DISPLAY
printf 'seat seat0 fallback true\nxwayland disable\n' > "$wayland_test_dir/sway.cfg"
sway -c "$wayland_test_dir/sway.cfg" > "$wayland_test_dir/sway.log" 2>&1 &
sway_pid=$!

for attempt in {1..100}; do
    if ! kill -0 "$sway_pid" 2>/dev/null; then
        echo "Headless sway exited before creating its socket." >&2
        exit 1
    fi
    for socket in "$wayland_test_dir"/wayland-*; do
        if [ -S "$socket" ]; then
            export WAYLAND_DISPLAY="${socket##*/}"
            break 2
        fi
    done
    sleep 0.1
done
if [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "Headless sway did not create a Wayland socket within 10 seconds." >&2
    exit 1
fi

cargo test --locked -p vault-desktop -- --ignored real_clipboard
