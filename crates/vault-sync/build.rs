//! Where the desktop OAuth client secret comes from — which is not this
//! repository.
//!
//! Google's own documentation says an installed-app secret is not confidential:
//! it ships inside every copy of the binary, and PKCE is what actually binds an
//! authorization code to the process that asked for it. That is a reason not to
//! panic about it, not a reason to publish it. A credential in public git
//! history cannot be withdrawn, only rotated, and rotation costs a release.
//!
//! Two sources, in order:
//!
//! 1. `ARCA_GOOGLE_CLIENT_SECRET` in the environment — what the release and
//!    install scripts set.
//! 2. `~/.arca/google-client-secret`, one line, mode 600, next to the updater
//!    key. This is what makes a plain `cargo build` or `npm run tauri dev` on a
//!    developer machine work with no extra ceremony.
//!
//! Neither present is a *supported* state, not a broken one: `sync_configured()`
//! reports false and the sign-in refuses up front with a sentence a person can
//! read. That is what CI builds, and what anyone cloning this repository builds.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=ARCA_GOOGLE_CLIENT_SECRET");

    let path = home().map(|home| home.join(".arca").join("google-client-secret"));

    // Only when it exists. `rerun-if-changed` on a missing path means "always
    // rerun", which would rebuild this crate and everything above it on every
    // cargo invocation. The cost of the omission is that creating the file for
    // the first time is not noticed: cargo recorded no dependency on a path
    // that did not exist, so the next build happily reuses a binary with sync
    // compiled out. `touch crates/vault-sync/build.rs` is what forces the
    // re-run. (`cargo clean -p vault-sync` does not: it reports "Removed 0
    // files" and leaves the build-script output in place.)
    if let Some(path) = path.as_ref().filter(|path| path.exists()) {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let secret = from_env().or_else(|| path.and_then(read_trimmed));
    if let Some(secret) = secret {
        // Single-line by construction (trimmed), which `cargo:rustc-env`
        // requires: a newline here would be read as the start of a new
        // directive.
        println!("cargo:rustc-env=ARCA_GOOGLE_CLIENT_SECRET={secret}");
    } else {
        // Say so. A build without the secret is supported, but it is otherwise
        // indistinguishable from one with it until sign-in refuses at runtime —
        // which is a long way from the build that caused it.
        println!(
            "cargo:warning=no Google client secret found, so Drive sync is compiled out of \
             this build (see docs/SYNC.md). After adding ~/.arca/google-client-secret, run \
             `touch crates/vault-sync/build.rs` or the next build will reuse this one."
        );
    }
}

fn from_env() -> Option<String> {
    std::env::var("ARCA_GOOGLE_CLIENT_SECRET")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_string())
        .filter(|contents| !contents.is_empty())
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|home| !home.as_os_str().is_empty())
}
