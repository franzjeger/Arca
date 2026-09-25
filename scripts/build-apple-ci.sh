#!/usr/bin/env bash
# Compile both Apple schemes, unsigned, and report compiler diagnostics by count.
#
# The point of the count: this Swift is written on Linux and the macOS runner is
# the only compiler it ever meets, so "the log was empty" is the only evidence
# anyone has that it is clean — and an empty log looks identical whether the
# build was quiet, the diagnostics were filtered, or nothing was compiled at all.
# Printing a number turns silence into an assertion.
#
# Both Apple projects use Swift 6 with complete concurrency checking.
# Compiler diagnostics remain visible even when xcodebuild exits successfully.
#
# Full xcodebuild output goes to a file; only `file:line: warning|error` lines
# reach the console, plus the tail of a failing log.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGS="${RUNNER_TEMP:-/tmp}"
failed=0
total=0

build() {
    local dir="$1" scheme="$2" destination="$3" action="$4"
    local log="$LOGS/$scheme.log" diag="$LOGS/$scheme.diag"
    local status=0 count
    local derived="$ROOT/$dir/build"
    if [ -n "${ARCA_APPLE_BUILD_ROOT:-}" ]; then derived="$ARCA_APPLE_BUILD_ROOT/$scheme"; fi

    echo "==> $scheme ($destination) [$action]"
    # No -quiet: the full log is wanted in the file. Only the filtered lines and
    # the count are printed, so the console stays readable either way.
    ( cd "$ROOT/$dir" \
        && xcodegen generate \
        && xcodebuild -project Arca.xcodeproj -scheme "$scheme" -destination "$destination" \
            CODE_SIGNING_ALLOWED=NO -derivedDataPath "$derived" "$action" ) \
        > "$log" 2>&1 || status=$?

    # A compiler diagnostic is  /path/To/File.swift:12:5: warning: message
    # sort -u because a header included from several files repeats its warnings.
    grep -hE '^/.+:[0-9]+:[0-9]+: (warning|error): ' "$log" | sort -u > "$diag" || true
    count=$(wc -l < "$diag" | tr -d ' ')
    total=$(( total + count ))

    echo "    $count distinct compiler diagnostics"
    if [ "$count" -gt 0 ]; then
        sed 's/^/    /' "$diag"
    fi

    # A `test` action that ran zero tests exits 0 and prints nothing, which is
    # indistinguishable from one that ran and passed. Surface the count, and
    # treat its absence as a failure: a scheme that lost its test target would
    # otherwise go on reporting green forever.
    if [ "$action" = "test" ] && [ "$status" -eq 0 ]; then
        if grep -hE '^[[:space:]]*Executed [1-9][0-9]* test' "$log" | tail -1 \
            | sed 's/^[[:space:]]*/    /'; then
            :
        else
            echo "    NO TEST SUMMARY in the log — did any test actually run?"
            failed=1
        fi
    fi

    if [ "$status" -ne 0 ]; then
        echo "    $action FAILED (exit $status). Last 60 lines:"
        tail -60 "$log" | sed 's/^/    /'
        failed=1
    fi
    return 0
}

# macOS runs `test`: the ArcaHost scheme carries ArcaBridgeTests, and `test`
# builds everything `build` would first. iOS only builds — a generic simulator
# destination cannot run tests, and the tests are of the shared bridge anyway,
# which the macOS target compiles from the same file.
build apps/macos ArcaHost "platform=macOS"                     test
build apps/ios   Arca     "generic/platform=iOS Simulator"     build

echo
echo "==> $total compiler diagnostics across both schemes"
exit "$failed"
