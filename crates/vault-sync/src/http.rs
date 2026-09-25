//! The one HTTP client this crate uses.
//!
//! Blocking on purpose: sync runs on its own thread on every platform, and a
//! blocking client keeps the engine an ordinary function that can be called
//! from a test without a runtime.
//!
//! Clients are built once and held for the process' lifetime, not per request.
//! `reqwest::blocking` starts a background Tokio runtime for each client it
//! builds, so building one per HTTP call — which the desktop implementation
//! did — spawns and tears down a runtime, and throws away the connection pool
//! and TLS session, for every list, download and preflight.

use std::time::Duration;

/// Long enough for a slow mobile connection, short enough that a black-holed
/// connection cannot pin the sync thread. A timed-out cycle is not lost: the
/// dirty flag survives and the next tick retries.
const TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .build()
        // Only fails if the TLS backend or the runtime cannot be created, which
        // is a broken process rather than a condition to handle.
        .expect("http client builds")
}
