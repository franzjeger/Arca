//! Local autofill bridge.
//!
//! A loopback-only (127.0.0.1) line-delimited-JSON server that the native
//! messaging host connects to, so the browser extension can autofill
//! credentials from the unlocked vault.
//!
//! Security model (see THREAT_MODEL.md):
//!   * **Loopback only** — bound to 127.0.0.1 on an ephemeral port, never
//!     reachable off-device.
//!   * **Token** — a random per-run token written to a `0600` connection-info
//!     file (only the user can read it); required on every connection.
//!   * **Unlock gate** — `match`/`fill` only succeed while the vault is
//!     unlocked.
//!   * **Origin binding** — `fill` returns a credential only when the requested
//!     page's host matches the stored login's host, so a page on one site can
//!     never pull another site's password.
//!   * **Least exposure** — `match` returns metadata only (id/title/username);
//!     the password crosses solely on an explicit `fill` for a matched id.
//!   * **Optional per-fill consent** — with the `confirm_autofill` setting on,
//!     a `fill` blocks on an in-app Allow/Deny prompt, making the desktop app
//!     the final approver (defence in depth if the extension is compromised).

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::Duration;

pub use vault_bridge::proto::BookmarkWire;
use vault_bridge::proto::Response;

/// How long a blocked `fill` waits for the user's Allow/Deny before defaulting
/// to deny.
const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Version of the newline-delimited JSON protocol this build speaks.
///
/// The bridge stopped being a private arrangement between the app and its own
/// native-messaging host as soon as a second consumer appeared — a passkey
/// client inside an Electron app cannot use native messaging, so it opens this
/// socket directly. Two consumers on an unversioned protocol is how a change
/// here silently breaks something over there, and the failure would surface as
/// "passkeys stopped working" rather than as a protocol mismatch.
///
/// Bump this when an existing request or response changes shape in a way an
/// older client would get *wrong*. Adding a new request type, or a field an
/// older client simply ignores, is not such a change. Shared with the clients
/// through `vault-bridge`, which owns the protocol it names.
const PROTOCOL_VERSION: u32 = vault_bridge::PROTOCOL;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Pending autofill-consent requests, keyed by a per-request id. When
/// `confirm_autofill` is on, the bridge thread parks on the receiver while the
/// frontend shows an Allow/Deny prompt; `resolve_autofill_consent` sends the
/// decision. Managed by Tauri so the command and the bridge share it.
#[derive(Default)]
pub struct PendingConsents(pub Mutex<HashMap<String, Sender<bool>>>);

/// Pending passkey user-verification requests, keyed by request id. Kept in a
/// SEPARATE map from [`PendingConsents`] on purpose: an autofill consent is a
/// presence-only Allow/Deny (resolved by `resolve_autofill_consent` with no
/// password check), whereas a passkey verification may only be satisfied `true`
/// after `verify_passkey_approval` has checked the master password. Sharing one
/// map would let a presence-only resolver set the WebAuthn UV flag without any
/// verification. Only `resolve_verification` (from the password-checked command,
/// or a cancel that always sends `false`) drains this map.
///
/// Each entry is the parked ceremony's sender, and whether this one may only
/// be satisfied by a checked master password (`true`) or by a plain
/// confirmation click (`false`). The flag lives HERE, set by the bridge, so a
/// frontend cannot turn a password prompt into a click by calling the other
/// command.
#[derive(Default)]
pub struct PendingVerifications(pub Mutex<HashMap<String, (Sender<bool>, bool)>>);

/// Account selection does not approve signing or satisfy user verification.
#[derive(Default)]
pub struct PendingPasskeyChoices(pub Mutex<HashMap<String, Sender<Option<String>>>>);

/// What the user is being asked to approve for a single fill.
pub struct ConsentContext {
    pub site: String,
    pub account: String,
    pub title: String,
}

/// The anti-phishing match key, from `vault-core` so the desktop bridge, the
/// AutoFill FFI and the duplicate finder cannot drift apart again. Also used for
/// item-list site grouping, so the UI groups by exactly the hosts autofill
/// matches on.
pub(crate) use vault_core::host_of;

fn unauthorized() -> Response {
    error("unauthorized")
}

fn error(message: impl Into<String>) -> Response {
    Response::Error {
        message: message.into(),
    }
}

mod bookmarks;
mod logins;
mod passkeys;
mod server;

use bookmarks::*;
use logins::*;
use passkeys::*;
use server::*;

pub use logins::resolve_consent;
pub use passkeys::{confirm_verification, resolve_passkey_choice, resolve_verification};
pub use server::{start, stop};

#[cfg(test)]
mod tests;
