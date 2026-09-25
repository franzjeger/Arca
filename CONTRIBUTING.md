# Contributing

Open a pull request against `main`. Required CI checks cover Linux, Windows,
macOS/Swift, Linux packaging and OS integration, and dependency audits. Keep
changes focused, preserve the lockfiles and describe the validation performed.
GitHub Actions are pinned to commit hashes and updated through Dependabot.

For local checks, use the pinned Rust toolchain and Node.js 22 or newer:

```sh
cd apps/desktop && npm ci && npx --no-install playwright install chromium
cd ../..
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
scripts/smoke-test.sh
```

On macOS, `scripts/build-apple-ci.sh` also runs the Swift bridge tests and builds
iOS. See `apps/macos/README.md` for local signing and `docs/RELEASE.md` for the
additional release gates and physical-device checks. A green PR is not release
certification.

Never commit vaults, exports, credentials, signing keys or provisioning profiles.
Report vulnerabilities privately as described in `SECURITY.md`.
