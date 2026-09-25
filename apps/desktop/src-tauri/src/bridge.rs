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
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use vault_core::{Item, VaultItem};

use crate::state::AppState;

/// How long a blocked `fill` waits for the user's Allow/Deny before defaulting
/// to deny.
const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest newline-delimited request accepted from the local bridge client.
/// Authentication happens inside the message, so cap allocation before JSON
/// parsing even for an unauthenticated local process.
const MAX_BRIDGE_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

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
/// older client simply ignores, is not such a change.
const PROTOCOL_VERSION: u32 = 2;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The app's half of the handshake: `HMAC-SHA256(token, nonce)`, hex.
///
/// Authentication used to run one way — the client proved it had the token and
/// the app proved nothing, so any process answering `{"type":"ok"}` on the
/// port was believed. Arca's port is freed the moment it exits, and nothing
/// removed the info file, so the next `save_probe` after a crash could hand a
/// submitted password to whoever had bound that port; a `fill` answer could
/// push attacker-chosen credentials into a login form. Only the real app knows
/// the token, so only the real app can produce this.
pub(crate) fn handshake_proof(token: &str, nonce: &str) -> String {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(token.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(nonce.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

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
#[derive(Default)]
/// Pending passkey approvals: the parked ceremony's sender, and whether this
/// one may only be satisfied by a checked master password (`true`) or by a
/// plain confirmation click (`false`). The flag lives HERE, set by the bridge,
/// so a frontend cannot turn a password prompt into a click by calling the
/// other command.
pub struct PendingVerifications(pub Mutex<HashMap<String, (Sender<bool>, bool)>>);

/// Account selection does not approve signing or satisfy user verification.
#[derive(Default)]
pub struct PendingPasskeyChoices(pub Mutex<HashMap<String, Sender<Option<String>>>>);

#[derive(Clone, Serialize)]
struct PasskeyChoice {
    id: String,
    account: String,
    title: String,
    #[serde(skip)]
    credential_id: Vec<u8>,
}

/// What the user is being asked to approve for a single fill.
pub struct ConsentContext {
    pub site: String,
    pub account: String,
    pub title: String,
}

/// One bookmark across the extension boundary.
///
/// Deliberately not the vault's own type: this crosses to a browser extension,
/// so it carries a title, a URL and a folder and nothing else — no item id, no
/// timestamps, nothing that would let a compromised extension reason about the
/// rest of the vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BookmarkWire {
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub folder: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    Hello {
        token: String,
        /// Protocol the client speaks. Absent means a client written before
        /// versioning existed, which by definition speaks version 1.
        #[serde(default)]
        protocol: Option<u32>,
        /// Client-chosen random challenge. The reply carries an HMAC of it
        /// under the shared token, which is how the client knows it is talking
        /// to Arca and not to whoever grabbed the port. Absent from v1 clients.
        #[serde(default)]
        nonce: Option<String>,
    },
    Match {
        url: String,
    },
    Fill {
        id: String,
        url: String,
    },
    /// Register a new WebAuthn passkey (navigator.credentials.create).
    PasskeyCreate {
        /// The page origin, e.g. "https://github.com". Validated against `rp_id`.
        origin: String,
        rp_id: String,
        #[serde(default)]
        user_name: String,
        #[serde(default)]
        user_handle: Vec<u8>,
        /// Credential ids the RP says it already has (WebAuthn
        /// excludeCredentials). If we hold one of them, registration must be
        /// refused with "excluded" (-> InvalidStateError in the page) WITHOUT
        /// prompting - this is what makes sites stop re-asking.
        #[serde(default)]
        exclude_credentials: Vec<Vec<u8>>,
    },
    /// Assert an existing passkey (navigator.credentials.get).
    PasskeyGet {
        origin: String,
        rp_id: String,
        /// SHA-256 of the clientDataJSON the extension's isolated relay built
        /// from the page's challenge and the frame's own origin. Never the
        /// page's: the relying party trusts the origin this hash covers.
        client_data_hash: Vec<u8>,
        /// Credential ids the RP will accept; empty means "any for this rp".
        #[serde(default)]
        allow_credentials: Vec<Vec<u8>>,
        /// The user picked this passkey in Arca's own in-page picker. That
        /// click was a deliberate act on Arca's UI naming the account, so the
        /// desktop does not ask again — see `approve_passkey_inner`. Set by
        /// the relay from a trusted click it recorded itself; the page's
        /// request has no way to set it.
        #[serde(default)]
        picked: bool,
    },
    /// Ask whether a just-submitted login is worth offering to save.
    SaveProbe {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Store a new / updated login captured from a submitted form (after the
    /// user clicked "Save" in the browser prompt).
    /// Bookmarks read out of the browser, on their way into the vault.
    ImportBookmarks {
        items: Vec<BookmarkWire>,
    },
    /// Arca's whole bookmark list, on its way out to the browser.
    ListBookmarks,
    SaveLogin {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Bring Arca forward and ask for Touch ID, because the browser needs a
    /// password right now.
    ///
    /// The one moment an unlock prompt is the answer rather than an
    /// interruption: the user clicked a locked field's badge, so they have said
    /// what they want. Nothing is unlocked by this request itself — it puts the
    /// window in front and the user still authenticates.
    #[serde(rename = "request_unlock")]
    Unlock,
    /// A fresh random password for a sign-up form.
    ///
    /// Deliberately does NOT require an unlocked vault. Nothing here reads or
    /// writes one — the answer is bytes from the CSPRNG — and requiring unlock
    /// would put a master password between the user and the one moment they are
    /// most likely to give up and type "Sommer2026!" instead.
    ///
    /// Saving it does require unlock, but that is the existing save-on-submit
    /// path and it asks at a point where the user has already committed.
    GeneratePassword {
        #[serde(default)]
        length: Option<usize>,
        #[serde(default)]
        symbols: Option<bool>,
    },
    /// Mint a password and store it as a new login, in one step.
    ///
    /// For the `arca` command line, which exists so provisioning work can
    /// finish. Creating an account with a generated one-time password is
    /// ordinary administration; before this, the only ways to do it were to
    /// type the password into a terminal by hand or to let it sit in plain text
    /// in whatever transcript the automation was writing.
    ///
    /// Generating and saving are ONE request on purpose. Two calls would mean
    /// the password crosses the socket, gets held by the caller, and comes back
    /// — for no gain, since the app has both halves already. Here the secret is
    /// created and filed inside the app, and the caller learns its id.
    ///
    /// `reveal` is the caller saying it needs the value itself, and it is not
    /// the default. Whoever asks gets it; nobody gets it by accident.
    CreateLogin {
        title: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        url: String,
        #[serde(default)]
        notes: String,
        #[serde(default)]
        length: Option<usize>,
        #[serde(default)]
        symbols: Option<bool>,
        #[serde(default)]
        reveal: bool,
    },
    /// Retract an item, by id.
    ///
    /// A SOFT delete: the item moves to Deleted and can be restored from the
    /// app. Purging for real is not offered here and should not be. Automation
    /// that can create a credential should be able to take it back — an
    /// offboarding script, a failed run cleaning up after itself — but nothing
    /// running unattended needs the power to make a vault entry unrecoverable.
    DeleteItem {
        id: String,
    },
    /// Retract bookmarks the user deleted from Arca's folder in a browser.
    ///
    /// Matched on URL plus folder — the same key the import deduplicates on —
    /// because the extension never learns vault ids and should not have to. An
    /// empty `url` with a `folder` means a whole folder went, so everything at
    /// or under that path goes with it.
    ///
    /// SOFT, like every other delete here: the items move to Deleted and are
    /// restorable. A browser event is a thin thing to destroy data on, and this
    /// one can arrive because a rebuild was mid-flight.
    DeleteBookmarks {
        #[serde(default)]
        url: String,
        #[serde(default)]
        folder: String,
    },
    /// The password of one stored login, by id.
    ///
    /// This is a read of a secret, and it is deliberate. It widens nothing:
    /// `fill` already returns a password to anything that can read the bridge
    /// token, and that token is readable by any process running as this user.
    /// The boundary here has always been the user account, never the process.
    ReadPassword {
        id: String,
    },
}

impl Request {
    /// Whether this request is the user deciding to use the vault, as opposed
    /// to the extension talking to us on its own.
    ///
    /// Only the deliberate ones reset the idle timer. `Hello` and `Ping` are
    /// connection checks, `Match` fires when a password field takes focus, and
    /// `SaveProbe` fires on every submitted form — counting any of those would
    /// let one open tab hold the vault unlocked indefinitely. That is not a
    /// longer timeout, it is no timeout, arrived at by accident.
    /// Requests the USB key may open a locked vault for: the ones a person is
    /// directly behind. `Match` is included because it is what puts
    /// credentials in the picker when a field takes focus — without it the
    /// stick would only help after a failed fill.
    fn wants_vault_open(&self) -> bool {
        matches!(
            self,
            Request::Match { .. }
                | Request::Fill { .. }
                | Request::PasskeyCreate { .. }
                | Request::PasskeyGet { .. }
                | Request::SaveLogin { .. }
                | Request::CreateLogin { .. }
                | Request::ReadPassword { .. }
                | Request::DeleteItem { .. }
        )
    }

    fn is_deliberate_use(&self) -> bool {
        match self {
            // Picked a credential, approved a passkey, chose to save, asked for
            // a password. Each is a click.
            Request::Fill { .. }
            | Request::PasskeyCreate { .. }
            | Request::PasskeyGet { .. }
            | Request::SaveLogin { .. }
            | Request::CreateLogin { .. }
            | Request::ReadPassword { .. }
            | Request::DeleteItem { .. }
            | Request::DeleteBookmarks { .. }
            | Request::GeneratePassword { .. } => true,
            // NOT activity: the vault is locked, so there is no idle timer to
            // reset, and counting it would let a page keep a future session
            // alive by asking to unlock.
            Request::Unlock
            | Request::Hello { .. }
            | Request::Match { .. }
            // Bookmark sync is one request that completes on its own, and
            // push-out is the kind of thing that later grows a timer. Counting
            // it would then let a browser hold the vault open just by existing,
            // so it does not count now, before anyone can rely on it doing so.
            | Request::ImportBookmarks { .. }
            | Request::ListBookmarks
            | Request::SaveProbe { .. } => false,
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    /// Handshake accepted. Carries the protocol so a client that is not our own
    /// native host can check what it is talking to before relying on it. Still
    /// serialises with `"type":"ok"`, so clients that only test the tag — the
    /// native host does exactly that — are unaffected.
    Ok {
        protocol: u32,
        version: &'static str,
        build: &'static str,
        commit: &'static str,
        pid: u32,
        /// `HMAC-SHA256(token, nonce)`, hex. Present whenever the client sent a
        /// nonce; it is the app's half of the mutual authentication.
        #[serde(skip_serializing_if = "Option::is_none")]
        proof: Option<String>,
    },
    Logins {
        items: Vec<LoginMatch>,
    },
    Credentials {
        username: String,
        password: String,
    },
    /// Result of `PasskeyCreate`: the new credential id + CBOR attestation.
    PasskeyCredential {
        credential_id: Vec<u8>,
        attestation_object: Vec<u8>,
    },
    /// Result of `PasskeyGet`: the assertion the RP verifies.
    PasskeyAssertion {
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    },
    /// Result of `SaveProbe`. `action` is one of "new", "update", "known",
    /// "disabled" (setting off), or "locked". For "update", `username` names
    /// the stored login that would be overwritten, so the browser can show
    /// WHICH account before the user agrees — essential when the page had no
    /// username field and the app resolved the target on its own.
    SaveDecision {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    /// A login was stored/updated via `SaveLogin`.
    Saved,
    /// Result of `GeneratePassword`.
    GeneratedPassword {
        password: String,
    },
    /// A login was created. `password` is present only when the caller asked
    /// for it, so the common path returns an id and nothing secret.
    CreatedLogin {
        id: String,
        title: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Password {
        password: String,
    },
    /// What was retracted. The TITLE comes back so a caller can confirm the
    /// right thing went, rather than trusting that an id it was handed
    /// somewhere else pointed where it thought.
    Deleted {
        id: String,
        title: String,
    },
    /// How many bookmarks a browser-side deletion retracted.
    DeletedBookmarks {
        removed: usize,
    },
    /// Arca was brought forward and asked the user to unlock. Says nothing
    /// about whether they did — the extension retries and finds out.
    /// How many of an import were new.
    ImportedBookmarks {
        added: usize,
    },
    /// The master list, for the extension to apply.
    Bookmarks {
        items: Vec<BookmarkWire>,
    },
    UnlockRequested,
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize, PartialEq)]
struct LoginMatch {
    id: String,
    /// The passkey's credential id, so the picker's choice reaches the
    /// ceremony as an `allowCredentials` entry. Empty for passwords.
    ///
    /// Not a secret — it is what the browser sends the relying party anyway.
    /// Without it, picking one of two passkeys for the same site would sign
    /// with whichever the app found first, and the choice would be theatre.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    credential_id: Vec<u8>,
    title: String,
    username: String,
    /// Credential type for the picker UI: "password" for a stored login,
    /// "passkey" for a WebAuthn credential. A passkey row is informational (it
    /// signs in via the site's own passkey ceremony, not by filling a field).
    kind: String,
}

/// Port + token, written for the native host to read.
#[derive(Serialize, Deserialize)]
struct BridgeInfo {
    port: u16,
    token: String,
}

fn info_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("native-bridge.json")
}

/// Delete the connection-info file. Called when the app exits.
///
/// The port in it is freed the instant Arca stops, so leaving the file behind
/// points every client at a port that now belongs to nobody — or to whoever
/// binds it next. The handshake proof already stops an impostor from being
/// believed; removing the file stops clients from trying at all, and stops a
/// stale token from sitting on disk indefinitely.
pub fn stop(app_data_dir: &Path) {
    let _ = std::fs::remove_file(info_path(app_data_dir));
}

/// The anti-phishing match key, from `vault-core` so the desktop bridge, the
/// AutoFill FFI and the duplicate finder cannot drift apart again. Also used for
/// item-list site grouping, so the UI groups by exactly the hosts autofill
/// matches on.
pub(crate) use vault_core::host_of;

/// Whether a stored login's URL should autofill on the requested page.
/// Matching is exact after normalization (`www.` is stripped): trust is not
/// inherited by sibling or subdomains, especially on multi-tenant suffixes.
/// Whether a credential stored at `stored_url` may be listed for, or filled on,
/// `requested_url`.
///
/// Host equality is not enough: this also refuses an `https`-to-`http`
/// downgrade and a port change. See [`vault_core::Origin`] for why.
fn domain_matches(stored_url: &str, requested_url: &str) -> bool {
    vault_core::origin_of(stored_url).may_fill(&vault_core::origin_of(requested_url))
}

/// WebAuthn RP-ID validation: `rp_id` must equal the page origin's host or be a
/// *registrable* parent-domain suffix of it. So a page on `sub.github.com` may
/// use rp_id `github.com`, but a page on `evil.com` may NOT — this is the core
/// anti-phishing binding for passkey create/get.
///
/// Crucially, `rp_id` must NOT be a public suffix / eTLD (`com`, `co.uk`,
/// `github.io`): the Public Suffix List guard stops a page scoping a passkey so
/// broadly that mutually-distrusting tenants (e.g. every `*.github.io`) could
/// share it — exactly what a browser's WebAuthn client enforces.
/// `rp_id_matches_origin`, plus the origins the relying party itself published
/// (WebAuthn L3 Related Origin Requests).
///
/// NEVER call this while holding the app-state lock: the first use per rpId
/// makes an HTTPS request. The direct rule is tried first, so the common case
/// costs nothing.
fn rp_id_allows_origin(rp_id: &str, origin: &str) -> bool {
    if rp_id_matches_origin(rp_id, origin) {
        return true;
    }
    // The RP publishes full origins (`https://www.example.com` is not
    // `https://example.com` in that file either), so the page's host must reach
    // the comparison with its `www.` intact.
    let host = vault_core::webauthn_host_of(origin);
    if host.is_empty() {
        return false;
    }
    crate::related_origins::is_related(rp_id, &host)
}

fn rp_id_matches_origin(rp_id: &str, origin: &str) -> bool {
    // NOT `host_of`: that strips `www.` for password matching, and an rpId is a
    // name the page and the relying party agree on exactly. A page on
    // `https://www.example.com` that omits `rp.id` defaults it to the full
    // hostname, so stripping here compared `www.example.com` against
    // `example.com`, called it a mismatch, and refused the ceremony — and any
    // passkey already stored under a `www.` rpId became unusable.
    let host = vault_core::webauthn_host_of(origin);
    let rp = rp_id.trim().to_lowercase();
    if rp.is_empty() || host.is_empty() {
        return false;
    }
    // rp_id must equal or be a parent suffix of the origin host.
    if host != rp && !host.ends_with(&format!(".{rp}")) {
        return false;
    }
    // ...and rp_id and the origin must share the SAME registrable domain, which
    // also rejects rp_id being a bare public suffix (no registrable domain).
    match (psl::domain_str(&rp), psl::domain_str(&host)) {
        (Some(rp_reg), Some(host_reg)) => rp_reg == host_reg,
        _ => false,
    }
}

/// Find an active login matching (normalized host, lowercased username).
/// Returns `(id, current_password)` for change detection.
#[cfg(test)]
fn find_login(vault: &vault_core::Vault, host: &str, username: &str) -> Option<(Uuid, String)> {
    let user = username.to_lowercase();
    for s in vault.list_items(false).ok()? {
        let Ok(item) = vault.get_item(s.id) else {
            continue;
        };
        if let VaultItem::Login {
            url,
            username: un,
            password,
            ..
        } = &item.data
        {
            if host_of(url) == host && un.to_lowercase() == user {
                return Some((item.id, password.clone()));
            }
        }
    }
    None
}

/// Resolve which stored login a save/update should land on.
///
/// With a username we match it by fill-safe origin + username, so distinct
/// accounts and distinct services on different ports stay distinct. A
/// token-based password reset has NO username field
/// — `username` is empty there — yet it is almost always a reset OF an account
/// already in the vault. When that origin has exactly one login we target it:
/// that is the account being reset, and the update keeps its stored username and
/// only replaces the password. Two or more logins for the origin is genuinely
/// ambiguous with no username to disambiguate, so we refuse to guess (guessing
/// could overwrite the wrong account's password) and return None — the caller
/// then files a new entry the user can merge in the app. This never fires on
/// ordinary sign-in pages: those carry a username field, so `username` is
/// non-empty and the exact match applies.
/// A short, non-secret reason for a save that did not reach the disk.
///
/// The browser shows this on the page, so it carries an error *kind* and never
/// a path, a host or anything from the vault. It exists because every distinct
/// way a save can fail — a blocked write, a corrupt file on disk, a vault the
/// running key cannot merge — arrived at the user as the same bare "internal",
/// which is why the same report kept coming back with nothing to act on.
fn save_failure_reason(e: &vault_store::Error) -> String {
    match e {
        // The common one, and the one worth naming: another process had the
        // vault file open (Windows) or the write itself failed.
        vault_store::Error::Io(io) => {
            format!("the vault file could not be written ({})", io.kind())
        }
        // A well-formed file the running vault cannot reconcile — a different
        // vault's key, typically after sync replaced the file underneath us.
        vault_store::Error::Core(_) => {
            "the vault file on disk could not be merged with this vault".into()
        }
        _ => "internal".into(),
    }
}

fn find_login_for_save(
    vault: &vault_core::Vault,
    requested_url: &str,
    username: &str,
) -> Option<(Uuid, String, String)> {
    if !username.is_empty() {
        for s in vault.list_items(false).ok()? {
            let Ok(item) = vault.get_item(s.id) else {
                continue;
            };
            if let VaultItem::Login {
                url,
                username: stored,
                password,
                ..
            } = &item.data
            {
                // Saving has to use the same trust boundary as filling. A host
                // can serve unrelated applications on :443, :9443, :8006, …;
                // host-only matching silently updated the wrong credential.
                if domain_matches(url, requested_url) && stored.eq_ignore_ascii_case(username) {
                    return Some((item.id, stored.clone(), password.clone()));
                }
            }
        }
        return None;
    }
    let mut only: Option<(Uuid, String, String)> = None;
    for s in vault.list_items(false).ok()? {
        let Ok(item) = vault.get_item(s.id) else {
            continue;
        };
        if let VaultItem::Login {
            url,
            username: un,
            password,
            ..
        } = &item.data
        {
            if domain_matches(url, requested_url) {
                if only.is_some() {
                    return None; // ambiguous: more than one login for this origin
                }
                only = Some((item.id, un.clone(), password.clone()));
            }
        }
    }
    only
}

/// Open the vault with the device key, loading it from disk first if it is not
/// in memory yet. Returns whether the vault is ACTUALLY unlocked afterwards.
///
/// The return value is the whole point. `quick_unlock` fails for reasons a
/// successful biometric says nothing about — it was never enabled, or the
/// keychain key no longer unwraps this header — and a caller that assumes it
/// worked tells the rest of the app the vault is open when it is not.
///
/// Only compiled where a biometric can drive it (and under `cfg(test)`), since
/// on Linux an unlock always goes through the master password.
#[cfg(any(target_os = "windows", test))]
fn try_device_unlock(state: &Mutex<AppState>) -> bool {
    let Ok(mut st) = state.lock() else {
        return false;
    };
    if st.vault.is_none() && st.store.exists() {
        st.vault = st.store.load().ok();
    }
    let AppState { store, vault, .. } = &mut *st;
    let unlocked = vault
        .as_mut()
        .is_some_and(|v| store.quick_unlock(v).is_ok() && v.is_unlocked());
    if unlocked {
        // Only then: an unlock that did not happen is not the user using Arca,
        // and counting it would push the idle deadline out for nothing.
        st.touch();
    }
    unlocked
}

/// Bring the main window forward and ask the frontend for a master-password
/// unlock.
///
/// The fallback whenever this side cannot open the vault by itself: on Linux
/// there is no biometric at all, and on macOS/Windows a successful Touch ID or
/// Hello still leaves the vault shut when quick unlock is not usable. Without
/// this the browser is left asking a vault that never opens.
fn ask_window_to_unlock(app: Option<&AppHandle>) {
    let Some(app) = app else { return };
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    let _ = app.emit("unlock-requested", ());
}

/// Handle one parsed request. `authed` tracks whether this connection has
/// presented the token. Factored out (no sockets) so the security gates are
/// unit-testable.
fn handle_request(
    req: Request,
    state: &Mutex<AppState>,
    token: &str,
    authed: &mut bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
) -> Response {
    // Using the passwords IS using Arca.
    //
    // The idle timer only ever saw the Arca window, so an hour spent filling
    // logins in the browser looked exactly like an hour away from the desk: the
    // vault locked underneath you, and the next fill wanted Touch ID.
    //
    // But only when the request WORKED. It used to touch before validation, so
    // a site's automatic passkey retries against a suppressed origin, or fills
    // refused on origin mismatch, kept the vault open with nobody at the desk —
    // the accidental "no timeout" the deliberate-use list warns about.
    let deliberate = *authed && req.is_deliberate_use();
    // A USB key enrolled and inserted: a request that needs the vault open
    // finds it open, with no window and no password. This is the
    // whole point of the key — "unlock" stops being a step between the
    // browser and the credential. Only for requests the user is behind (a
    // field they focused, a fill, a passkey); a form submit's save probe or a
    // bookmark timer must not be what keeps the vault open.
    if *authed && req.wants_vault_open() && crate::keyfile_unlock::unlock_if_locked(state) {
        if let Some(app) = app {
            let _ = app.emit("vault-unlocked", ());
        }
    }
    let resp = dispatch(req, state, token, authed, app, consent);
    if deliberate && !matches!(resp, Response::Error { .. }) {
        if let Ok(mut st) = state.lock() {
            st.touch();
        }
    }
    resp
}

fn dispatch(
    req: Request,
    state: &Mutex<AppState>,
    token: &str,
    authed: &mut bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
) -> Response {
    match req {
        Request::Hello {
            token: presented,
            protocol,
            nonce,
        } => {
            // Token first: an unauthenticated caller must not learn anything
            // about this build, not even which protocol it speaks.
            // Constant-time: SECURITY.md lists it as a design property, and a
            // byte-by-byte compare on a loopback socket leaks a timing signal
            // for free. `subtle` because `==` on String short-circuits.
            let ok = presented.len() == token.len()
                && bool::from(subtle::ConstantTimeEq::ct_eq(
                    presented.as_bytes(),
                    token.as_bytes(),
                ));
            if !ok {
                return Response::Error {
                    message: "unauthorized".into(),
                };
            }
            // We can serve a client older than us; we cannot serve one newer,
            // because we do not know what it means and guessing is worse than
            // saying so. Absent is the pre-versioning native host, i.e. v1.
            match protocol {
                None => {}
                Some(v) if (1..=PROTOCOL_VERSION).contains(&v) => {}
                Some(_) => {
                    return Response::Error {
                        message: "unsupported_protocol".into(),
                    }
                }
            }
            *authed = true;
            Response::Ok {
                protocol: PROTOCOL_VERSION,
                version: APP_VERSION,
                build: env!("ARCA_BUILD"),
                commit: env!("ARCA_COMMIT"),
                pid: std::process::id(),
                proof: nonce.as_deref().map(|n| handshake_proof(token, n)),
            }
        }
        _ if !*authed => Response::Error {
            message: "unauthorized".into(),
        },
        Request::Match { url } => {
            let st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                return Response::Error {
                    message: "locked".into(),
                };
            };
            let mut items = Vec::new();
            // Passkeys whose rp_id does not match this page directly. Resolved
            // after the lock is released.
            let mut deferred: Vec<(String, LoginMatch)> = Vec::new();
            if let Ok(summaries) = vault.list_items(false) {
                for s in summaries {
                    if let Ok(item) = vault.get_item(s.id) {
                        match &item.data {
                            VaultItem::Login {
                                url: u,
                                username,
                                title,
                                ..
                            } if domain_matches(u, &url) => {
                                items.push(LoginMatch {
                                    id: item.id.to_string(),
                                    title: title.clone(),
                                    username: username.clone(),
                                    kind: "password".into(),
                                    credential_id: Vec::new(),
                                });
                            }
                            // Passkeys for this site: surfaced so the picker can
                            // show the user a passkey exists. Matched by the same
                            // rule the ceremony uses. Those that do not match
                            // DIRECTLY are set aside — deciding them needs the
                            // relying party's related-origins file, and fetching
                            // it under this lock would stall every other command
                            // behind a network request.
                            VaultItem::Passkey {
                                rp_id,
                                user_name,
                                title,
                                credential_id,
                                ..
                            } => {
                                let entry = LoginMatch {
                                    id: item.id.to_string(),
                                    title: title.clone(),
                                    username: user_name.clone(),
                                    kind: "passkey".into(),
                                    credential_id: credential_id.clone(),
                                };
                                if rp_id_matches_origin(rp_id, &url) {
                                    items.push(entry);
                                } else {
                                    deferred.push((rp_id.clone(), entry));
                                }
                            }
                            // Non-matching logins/passkeys and other item kinds
                            // (SSH keys, secure notes) are not autofillable here.
                            _ => {}
                        }
                    }
                }
            }
            drop(st);

            // Now the network part, off the lock. Only for passkeys that did not
            // match outright, and only one request per relying party per twelve
            // hours — a vault with no such passkeys does no I/O at all.
            for (rp_id, entry) in deferred {
                if rp_id_allows_origin(&rp_id, &url) {
                    items.push(entry);
                }
            }
            Response::Logins { items }
        }
        Request::Fill { id, url } => {
            // Resolve + validate under the lock, then extract just what we need
            // and release it before any (possibly slow) user consent prompt.
            let confirm;
            let username;
            let password;
            let title;
            {
                let st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        return Response::Error {
                            message: "internal".into(),
                        }
                    }
                };
                let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                let Ok(uuid) = Uuid::parse_str(&id) else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                let Ok(item) = vault.get_item(uuid) else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                // Trashed is trashed. `get_item` answers for deleted items too —
                // it is the Trash view's reader as much as autofill's — so a
                // credential the user retired stayed fillable by id for as long
                // as it sat in the bin. `Match` never offers one (it lists
                // active items), which made this reachable only by an id from an
                // earlier session or from something else on this machine, and
                // invisible to the user either way.
                if item.is_deleted() {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                }
                let VaultItem::Login {
                    url: u,
                    username: un,
                    password: pw,
                    title: t,
                    ..
                } = &item.data
                else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                // Origin binding: never hand a credential to a non-matching host.
                if !domain_matches(u, &url) {
                    return Response::Error {
                        message: "origin_mismatch".into(),
                    };
                }
                confirm = st.settings.confirm_autofill;
                username = un.clone();
                password = pw.clone();
                title = t.clone();
            }

            // Optional per-fill consent: the app is the final approver.
            if confirm {
                let ctx = ConsentContext {
                    site: host_of(&url),
                    account: username.clone(),
                    title: title.clone(),
                };
                if !consent(&ctx) {
                    return Response::Error {
                        message: "denied".into(),
                    };
                }
                // The prompt can outlast the vault: with lock-on-blur, glancing
                // back at the browser while Arca asks locks it, and a credential
                // must not leave after that. Re-check now that the wait is over.
                let locked = state
                    .lock()
                    .map(|st| !st.vault.as_ref().is_some_and(|v| v.is_unlocked()))
                    .unwrap_or(true);
                if locked {
                    return Response::Error {
                        message: "locked".into(),
                    };
                }
            }

            if let Some(app) = app {
                let _ = app.emit("autofilled", format!("{title} ({})", host_of(&url)));
            }
            Response::Credentials { username, password }
        }
        Request::PasskeyCreate {
            origin,
            rp_id,
            user_name,
            user_handle,
            exclude_credentials,
        } => {
            // Kill switch: when passkey handling is off, ignore the ceremony so
            // the browser / platform authenticator takes over (the shim falls
            // back on this error). No prompt, ever.
            if !passkeys_enabled(state) {
                return Response::Error {
                    message: "passkeys_disabled".into(),
                };
            }
            // Anti-phishing: the RP id must belong to the page's origin.
            log_passkey_request(state, &origin, &rp_id, true);
            // Related Origin Requests apply to the ceremony too — a passkey
            // registered for login.microsoft.com must be usable on the page
            // Microsoft actually redirects you to. No lock is held here.
            if !rp_id_allows_origin(&rp_id, &origin) {
                return Response::Error {
                    message: "origin_mismatch".into(),
                };
            }
            // Must be unlocked before we prompt the user.
            let mut blocked_same_account = false;
            {
                let st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        return Response::Error {
                            message: "internal".into(),
                        }
                    }
                };
                let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                // Refuse a create WITHOUT prompting when we already hold a
                // passkey for this relying party — this is the loop killer.
                // Sites like GitHub re-fire `create` on nearly every sign-in;
                // if we serviced each one we'd pop a Touch ID prompt and pile up
                // a duplicate credential every single time (exactly the reported
                // bug). Refusing here makes the page see InvalidStateError, the
                // spec's "you already have a credential" signal, so it stops.
                //
                // Two conditions trigger the refusal, both BEFORE any prompt:
                //   1. The site listed a credential we hold in excludeCredentials
                //      (the polite, spec-driven path), OR
                //   2. we hold ANY passkey for this rp_id with the same
                //      user_handle — even when the site sent no exclude list.
                //      Byte-equal handle so a genuinely different account can
                //      still register once. (An RP that legitimately wants to
                //      re-register must first remove the old passkey in Arca.)
                //
                // Case 2 is a house rule, not the spec, and it has a nasty
                // failure mode: if the RP does NOT actually hold the credential
                // — a registration it rejected, or one deleted server-side —
                // then re-registering is the only way back, and this silently
                // refuses it. The page renders our InvalidStateError as "you
                // already have a passkey", which is a lie from the RP's point of
                // view, and nothing anywhere says the way out is to delete the
                // passkey in Arca first. So case 2 is reported to the user;
                // case 1 is the RP's own polite signal and needs no narration.
                if let Ok(summaries) = vault.list_items(false) {
                    for sum in summaries {
                        let Ok(item) = vault.get_item(sum.id) else {
                            continue;
                        };
                        if let VaultItem::Passkey {
                            rp_id: r,
                            credential_id: cid,
                            user_handle: uh,
                            ..
                        } = &item.data
                        {
                            if *r != rp_id {
                                continue;
                            }
                            if exclude_credentials.iter().any(|e| e == cid) {
                                return Response::Error {
                                    message: "excluded".into(),
                                };
                            }
                            if *uh == user_handle {
                                blocked_same_account = true;
                                break;
                            }
                        }
                    }
                }
            }
            if blocked_same_account {
                // Emitted outside the state lock: this reaches the webview, and
                // the webview answers by calling commands that take that lock.
                if let Some(app) = app {
                    let _ = app.emit("passkey-registration-blocked", rp_id.clone());
                }
                return Response::Error {
                    message: "excluded".into(),
                };
            }
            // Registration ALWAYS requires an explicit user approval; a silent
            // create must never register a credential. `true` = this is a NEW
            // passkey, so the prompt says "create" (not "sign in").
            let require_password = passkey_reprompt(state);
            let Some(user_verified) =
                approve_passkey(&rp_id, true, app, consent, false, require_password)
            else {
                return Response::Error {
                    message: "denied".into(),
                };
            };
            let Ok(new_pk) = vault_core::passkey::create(&rp_id, user_verified) else {
                return Response::Error {
                    message: "internal".into(),
                };
            };
            let credential_id = new_pk.credential_id.clone();
            let attestation_object = new_pk.attestation_object;
            {
                let mut st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        return Response::Error {
                            message: "internal".into(),
                        }
                    }
                };
                let AppState { store, vault, .. } = &mut *st;
                let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                // Dedup: if a passkey for the same relying party AND the same
                // user handle already exists, REPLACE it (reuse its id) instead
                // of piling up a duplicate. Only when the user handle is
                // non-empty — an empty handle can't distinguish accounts, so we
                // must not collapse them.
                //
                // This is a RACE GUARD, not the ordinary path: the check above
                // already refused that exact condition before prompting, so the
                // only way to arrive here holding a match is for one to have
                // been written while the approval dialog was open. Do not read
                // it as "re-registration replaces the old key" — re-registration
                // never gets this far.
                let existing_id = if user_handle.is_empty() {
                    None
                } else {
                    vault.list_items(false).ok().and_then(|sums| {
                        sums.into_iter().find_map(|s| {
                            let item = vault.get_item(s.id).ok()?;
                            match &item.data {
                                VaultItem::Passkey {
                                    rp_id: r,
                                    user_handle: uh,
                                    ..
                                } if *r == rp_id && *uh == user_handle => Some(s.id),
                                _ => None,
                            }
                        })
                    })
                };
                let mut item = Item::new(
                    VaultItem::Passkey {
                        title: rp_id.clone(),
                        rp_id: rp_id.clone(),
                        user_name,
                        user_handle,
                        credential_id: new_pk.credential_id,
                        private_key: new_pk.private_key.to_vec(),
                        sign_count: 0,
                    },
                    crate::state::now_millis(),
                );
                if let Some(id) = existing_id {
                    item.id = id;
                }
                let new_id = item.id;
                if vault.upsert_item(item).is_err() {
                    return Response::Error {
                        message: "internal".into(),
                    };
                }
                if store.save_synced(vault).is_err() {
                    // Roll the in-memory passkey back out. Left in place, it is
                    // an orphan the site never registered, and the exclude-list
                    // check would answer "excluded" on every retry — locking the
                    // user out of registering until they hunt it down by hand.
                    // Only for a fresh registration: reusing an existing id via
                    // the race guard means undoing would delete a real passkey.
                    if existing_id.is_none() {
                        let _ = vault.purge_item(new_id, crate::state::now_millis());
                    }
                    return Response::Error {
                        message: "internal".into(),
                    };
                }
                crate::sync::mark_dirty();
            }
            if let Some(app) = app {
                let _ = app.emit("passkey-created", rp_id);
            }
            Response::PasskeyCredential {
                credential_id,
                attestation_object,
            }
        }
        Request::PasskeyGet {
            origin,
            rp_id,
            client_data_hash,
            allow_credentials,
            picked,
        } => {
            if !passkeys_enabled(state) {
                return Response::Error {
                    message: "passkeys_disabled".into(),
                };
            }
            log_passkey_request(state, &origin, &rp_id, false);
            // Related Origin Requests apply to the ceremony too — a passkey
            // registered for login.microsoft.com must be usable on the page
            // Microsoft actually redirects you to. No lock is held here.
            if !rp_id_allows_origin(&rp_id, &origin) {
                return Response::Error {
                    message: "origin_mismatch".into(),
                };
            }
            // Discover eligible accounts without choosing the first matching key.
            let choices = {
                let st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        return Response::Error {
                            message: "internal".into(),
                        }
                    }
                };
                let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                vault
                    .list_items(false)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|summary| {
                        let item = vault.get_item(summary.id).ok()?;
                        if let VaultItem::Passkey {
                            rp_id: r,
                            credential_id,
                            user_name,
                            ..
                        } = &item.data
                        {
                            let allowed = allow_credentials.is_empty()
                                || allow_credentials.contains(credential_id);
                            if *r == rp_id && allowed {
                                return Some(PasskeyChoice {
                                    id: summary.id.to_string(),
                                    account: user_name.clone(),
                                    title: summary.title.clone(),
                                    credential_id: credential_id.clone(),
                                });
                            }
                        }
                        None
                    })
                    .collect::<Vec<_>>()
            };
            if choices.is_empty() {
                log_passkey_outcome(state, &rp_id, "no_passkey_stored");
                return Response::Error {
                    message: "not_found".into(),
                };
            }
            // Who chooses, and whether choosing already counts as approving.
            //
            // Picked in Arca's in-page picker: the user clicked a row that named
            // this account, in Arca's own UI, a moment ago. Asking "which
            // account?" again — or "really?" — is the double prompt this exists
            // to remove. Anything else goes through the desktop chooser, whose
            // click IS the approval: one account shows one button, several show
            // several. (Headless/tests: no app, so a single match is selected
            // outright and the injected consent closure approves, as before.)
            let (selected, confirmed) = match (choices.len(), app) {
                (1, _) if picked => (choices[0].id.clone(), true),
                (1, None) => (choices[0].id.clone(), false),
                (_, None) => {
                    return Response::Error {
                        message: "account_selection_required".into(),
                    };
                }
                (_, Some(app)) => {
                    let Some(id) = request_passkey_choice(app, &rp_id, &choices) else {
                        log_passkey_outcome(state, &rp_id, "declined_in_chooser");
                        return Response::Error {
                            message: "account_selection_cancelled".into(),
                        };
                    };
                    (id, true)
                }
            };
            let Some(choice) = choices.iter().find(|c| c.id == selected) else {
                return Response::Error {
                    message: "account_selection_cancelled".into(),
                };
            };
            // Reload after the choice: the vault may have locked or synced while
            // the dialog was open. Never substitute a different account.
            let (credential_id, user_handle, private_key) = {
                let st = match state.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        return Response::Error {
                            message: "internal".into(),
                        }
                    }
                };
                let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                let item = selected
                    .parse::<Uuid>()
                    .ok()
                    .and_then(|id| vault.get_item(id).ok());
                match &item {
                    Some(Item {
                        data:
                            VaultItem::Passkey {
                                rp_id: r,
                                credential_id: cid,
                                user_handle,
                                private_key,
                                ..
                            },
                        deleted_at: None,
                        ..
                    }) if *r == rp_id && *cid == choice.credential_id => {
                        (cid.clone(), user_handle.clone(), private_key.clone())
                    }
                    _ => {
                        return Response::Error {
                            message: "not_found".into(),
                        }
                    }
                }
            };

            // An assertion ALWAYS requires an explicit user approval — otherwise
            // the authenticator would falsely claim user presence/verification,
            // which relying parties trust for step-up defenses. `false` = this
            // is a sign-in, so the prompt says "sign in" (not "create").
            let require_password = passkey_reprompt(state);
            let Some(user_verified) =
                approve_passkey(&rp_id, false, app, consent, confirmed, require_password)
            else {
                // Cancelled, or a biometric prompt that never came back — which
                // looks to the user like the browser hanging on the sign-in.
                log_passkey_outcome(state, &rp_id, "declined_or_no_verification");
                return Response::Error {
                    message: "denied".into(),
                };
            };

            // The prompt can outlast the vault, exactly as it can for a fill:
            // the private key was read before the wait, and idle or blur lock
            // can fire while the user is looking at the dialog. Signing anyway
            // would let a locked vault authenticate a sign-in — a stronger act
            // than releasing a password, since the relying party takes the
            // assertion as proof the user was present just now.
            let locked = state
                .lock()
                .map(|st| !st.vault.as_ref().is_some_and(|v| v.is_unlocked()))
                .unwrap_or(true);
            if locked {
                log_passkey_outcome(state, &rp_id, "locked_during_prompt");
                return Response::Error {
                    message: "locked".into(),
                };
            }

            let Ok((authenticator_data, signature)) =
                vault_core::passkey::assert(&private_key, &rp_id, &client_data_hash, user_verified)
            else {
                return Response::Error {
                    message: "internal".into(),
                };
            };
            log_passkey_outcome(state, &rp_id, "signed");
            if let Some(app) = app {
                let _ = app.emit("passkey-used", rp_id);
            }
            Response::PasskeyAssertion {
                credential_id,
                authenticator_data,
                signature,
                user_handle,
            }
        }
        // Bookmarks are not secrets, but the SET of them is: it describes
        // where someone works, banks and reads. So both directions need the
        // vault open, exactly like a password would.
        Request::ImportBookmarks { items } => {
            let Ok(mut st) = state.lock() else {
                return Response::Error {
                    message: "internal".into(),
                };
            };
            let mut seen: std::collections::HashSet<(String, String)> =
                std::collections::HashSet::new();
            // The ids, not just a count: a save that fails has to be undone item
            // by item, and nothing else in the vault may be touched.
            let mut added: Vec<Uuid> = Vec::new();
            let now = crate::state::now_millis();
            {
                let Some(vault) = st.vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                if let Ok(summaries) = vault.list_items(false) {
                    for sum in summaries {
                        let Ok(item) = vault.get_item(sum.id) else {
                            continue;
                        };
                        if let VaultItem::Bookmark { url, folder, .. } = &item.data {
                            seen.insert((url.clone(), folder.clone()));
                        }
                    }
                }
                for b in items {
                    if b.url.is_empty() || !seen.insert((b.url.clone(), b.folder.clone())) {
                        continue;
                    }
                    let item = vault_core::Item::new(
                        VaultItem::Bookmark {
                            title: b.title,
                            url: b.url,
                            folder: b.folder,
                            notes: String::new(),
                        },
                        now,
                    );
                    let id = item.id;
                    if vault.upsert_item(item).is_ok() {
                        added.push(id);
                    }
                }
            }
            if !added.is_empty() {
                // A bulk insert is what a rollback point is for.
                st.store.snapshot_now();
                let AppState { store, vault, .. } = &mut *st;
                if let Some(v) = vault.as_mut() {
                    if store.save_synced(v).is_err() {
                        // Undo the whole import. Left in memory it would be
                        // deduplicated against on the next run — the extension
                        // would be told those bookmarks are already filed while
                        // the disk has never heard of them, and they would be
                        // gone for good at the next lock.
                        for id in &added {
                            let _ = v.purge_item(*id, now);
                        }
                        return Response::Error {
                            message: "internal".into(),
                        };
                    }
                }
                // Every other bridge write marks dirty; this one didn't, so an
                // import stayed local-only until some unrelated edit pushed it.
                crate::sync::mark_dirty();
            }
            Response::ImportedBookmarks { added: added.len() }
        }

        Request::ListBookmarks => {
            let Ok(st) = state.lock() else {
                return Response::Error {
                    message: "internal".into(),
                };
            };
            let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                return Response::Error {
                    message: "locked".into(),
                };
            };
            let mut items = Vec::new();
            if let Ok(summaries) = vault.list_items(false) {
                for sum in summaries {
                    let Ok(item) = vault.get_item(sum.id) else {
                        continue;
                    };
                    if let VaultItem::Bookmark {
                        title, url, folder, ..
                    } = &item.data
                    {
                        items.push(BookmarkWire {
                            title: title.clone(),
                            url: url.clone(),
                            folder: folder.clone(),
                        });
                    }
                }
            }
            Response::Bookmarks { items }
        }

        Request::SaveProbe {
            url,
            username,
            password,
        } => {
            if password.is_empty() {
                return Response::SaveDecision {
                    action: "known".into(), // nothing worth saving
                    username: None,
                };
            }
            let st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            if !st.settings.save_prompt {
                return Response::SaveDecision {
                    action: "disabled".into(),
                    username: None,
                };
            }
            let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                return Response::SaveDecision {
                    action: "locked".into(),
                    username: None,
                };
            };
            let host = host_of(&url);
            if host.is_empty() {
                return Response::SaveDecision {
                    action: "disabled".into(),
                    username: None,
                };
            }
            let (action, target) = match find_login_for_save(vault, &url, &username) {
                None => ("new", None),
                Some((_, _, cur)) if cur == password => ("known", None),
                Some((_, stored, _)) => ("update", Some(stored)),
            };
            Response::SaveDecision {
                action: action.into(),
                username: target,
            }
        }
        Request::SaveLogin {
            url,
            username,
            password,
        } => {
            if password.is_empty() {
                return Response::Error {
                    message: "empty".into(),
                };
            }
            let mut st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            if !st.settings.save_prompt {
                return Response::Error {
                    message: "disabled".into(),
                };
            }
            let host = host_of(&url);
            if host.is_empty() {
                return Response::Error {
                    message: "invalid".into(),
                };
            }
            {
                let AppState { store, vault, .. } = &mut *st;
                let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                match find_login_for_save(vault, &url, &username) {
                    // Already stored with this password: nothing to do.
                    Some((_, _, cur)) if cur == password => return Response::Saved,
                    // Same site + username, new password: update in place.
                    Some((id, _, _)) => {
                        let Ok(current) = vault.get_item(id) else {
                            return Response::Error {
                                message: "internal".into(),
                            };
                        };
                        if let VaultItem::Login {
                            title,
                            username: un,
                            url: u,
                            totp_secret,
                            notes,
                            ..
                        } = &current.data
                        {
                            let item = Item {
                                id: current.id,
                                created_at: current.created_at,
                                modified_at: crate::state::now_millis(),
                                deleted_at: None,
                                revision: current.revision,
                                revision_ancestors: current.revision_ancestors.clone(),
                                password_history: current.password_history.clone(),
                                sync_conflict: current.sync_conflict.clone(),
                                data: VaultItem::Login {
                                    title: title.clone(),
                                    username: un.clone(),
                                    url: u.clone(),
                                    password,
                                    totp_secret: totp_secret.clone(),
                                    notes: notes.clone(),
                                },
                            };
                            if vault.upsert_item(item).is_err() {
                                return Response::Error {
                                    message: "internal".into(),
                                };
                            }
                            if let Err(e) = store.save_synced(vault) {
                                // Put the OLD password back. The disk still has
                                // it, so leaving the new one in memory makes the
                                // two disagree, and the vault is the copy the
                                // user is shown: the next probe answers "known"
                                // (no save bar, nothing to click again) and the
                                // next save returns Saved, while the password
                                // that was actually typed exists nowhere after
                                // the app quits. An honest failure the browser
                                // can retry is worth more than a lost secret.
                                let _ = vault.upsert_item(current);
                                return Response::Error {
                                    message: save_failure_reason(&e),
                                };
                            }
                        }
                    }
                    // Brand-new login for this site.
                    None => {
                        let item = Item::new(
                            VaultItem::Login {
                                title: host.clone(),
                                username,
                                password,
                                url,
                                totp_secret: None,
                                notes: String::new(),
                            },
                            crate::state::now_millis(),
                        );
                        let new_id = item.id;
                        if vault.upsert_item(item).is_err() {
                            return Response::Error {
                                message: "internal".into(),
                            };
                        }
                        if let Err(e) = store.save_synced(vault) {
                            // Same trade as the update branch, from the other
                            // side: an entry that never reached the disk must
                            // not sit in memory claiming the site is already
                            // saved. Purged rather than soft-deleted — it was
                            // never a vault entry, and it must not surface in
                            // the Trash as something the user could restore.
                            let _ = vault.purge_item(new_id, crate::state::now_millis());
                            return Response::Error {
                                message: save_failure_reason(&e),
                            };
                        }
                    }
                }
            }
            crate::sync::mark_dirty();
            if let Some(app) = app {
                let _ = app.emit("login-saved", host);
            }
            Response::Saved
        }
        Request::Unlock => {
            let already_open = state
                .lock()
                .ok()
                .and_then(|st| st.vault.as_ref().map(|v| v.is_unlocked()))
                .unwrap_or(false);
            if already_open {
                // Racing a fill that already succeeded, or a second field on the
                // same page. Do not steal focus from what the user is doing.
                return Response::UnlockRequested;
            }
            // The browser is about to be blurred, then focused again — that is
            // the flow, not the user leaving. Hold off blur-locking long enough
            // for them to authenticate here and click a credential there.
            if let Ok(mut st) = state.lock() {
                st.blur_grace_until =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
            }

            // A USB key that is plugged in opens the vault before any prompt
            // is considered, on every platform: no Touch ID sheet, no Hello
            // dialog, no window. That is what the key is for.
            if crate::keyfile_unlock::unlock_if_locked(state) {
                if let Some(app) = app {
                    let _ = app.emit("vault-unlocked", ());
                }
                return Response::UnlockRequested;
            }

            // Unlock RIGHT HERE, without bringing the window forward.
            //
            // Routing this through our lock screen meant the window jumped in
            // front of the page you were signing in to, and left you looking at
            // Arca instead of the field you started from. Apple's own Passwords
            // proves the prompt needs no app in the foreground.
            //
            // macOS: Touch ID is a free-floating system dialog.
            // Windows: Hello must be PARENTED to a window of ours, but parenting
            // is not focus — the dialog takes focus itself, the app stays put.
            // The prompt runs before the state lock, because it blocks on a
            // human.
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            {
                // Windows only: a hidden window is not a usable parent, so make
                // sure it exists on screen — without raising it.
                #[cfg(target_os = "windows")]
                if let Some(app) = app {
                    if let Some(w) = app.get_webview_window("main") {
                        if !w.is_visible().unwrap_or(false) {
                            let _ = w.show();
                        }
                    }
                }

                #[cfg(target_os = "macos")]
                let unlocked = match crate::protected_unlock::unlock(state, app) {
                    Ok(()) => true,
                    Err(error)
                        if error.code == "biometric_failed"
                            || error.code == "unlock_cancelled"
                            || error.code == "unlock_in_progress" =>
                    {
                        return Response::UnlockRequested
                    }
                    Err(_) => false,
                };
                #[cfg(target_os = "windows")]
                let unlocked = crate::biometric::authenticate(app, "unlock your password vault")
                    .is_ok()
                    && try_device_unlock(state);
                // Touch ID succeeding is not the vault opening. Quick unlock may
                // never have been enabled, or its device key may no longer unwrap
                // this header (a restored file, a peer's header, an interrupted
                // re-enable) — and the result used to be dropped, with
                // "vault-unlocked" emitted regardless. The lock screen then went
                // away over a still-locked vault, the extension re-requested an
                // unlock, and the user got a biometric prompt every few seconds
                // with nothing to show for any of them.
                if unlocked {
                    // The window may be on screen showing its lock screen;
                    // without this it would sit there claiming to be locked while
                    // the vault is open.
                    if let Some(app) = app {
                        let _ = app.emit("vault-unlocked", ());
                    }
                } else {
                    // Nothing this side can do opens it: fall back to the master
                    // password in our own window, the same route Linux always
                    // takes. Saying so is the only way the user learns why the
                    // fingerprint they just gave did not work.
                    ask_window_to_unlock(app);
                }
            }

            // Everywhere else (Linux): there is no biometric to call, so the
            // master password has to be typed — and that needs a window. This is
            // a platform limit, not a shortcut.
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            ask_window_to_unlock(app);
            Response::UnlockRequested
        }
        Request::GeneratePassword { length, symbols } => {
            // Clamped rather than refused. The caller is a browser extension,
            // and a site that caps passwords at 16 is a real thing; failing the
            // request would send the user to type one themselves, which is the
            // outcome this whole feature exists to avoid.
            let opts = vault_core::password::PasswordOptions {
                length: length.unwrap_or(20).clamp(8, 64),
                symbols: symbols.unwrap_or(true),
                ..Default::default()
            };
            match vault_core::password::generate_password(&opts) {
                Ok(pw) => Response::GeneratedPassword {
                    password: pw.to_string(),
                },
                Err(_) => Response::Error {
                    message: "internal".into(),
                },
            }
        }
        Request::CreateLogin {
            title,
            username,
            url,
            notes,
            length,
            symbols,
            reveal,
        } => {
            if title.trim().is_empty() {
                return Response::Error {
                    message: "title_required".into(),
                };
            }
            // Same clamp as the extension's generator, for the same reason: a
            // service that caps passwords at 16 is a real thing, and refusing
            // sends the caller off to invent one by hand.
            let opts = vault_core::password::PasswordOptions {
                length: length.unwrap_or(24).clamp(8, 64),
                symbols: symbols.unwrap_or(true),
                ..Default::default()
            };
            let Ok(password) = vault_core::password::generate_password(&opts) else {
                return Response::Error {
                    message: "internal".into(),
                };
            };
            let password = password.to_string();

            let mut st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            let id = {
                let AppState { store, vault, .. } = &mut *st;
                let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                let item = vault_core::Item::new(
                    VaultItem::Login {
                        title: title.clone(),
                        username: username.clone(),
                        password: password.clone(),
                        url: url.clone(),
                        totp_secret: None,
                        notes: notes.clone(),
                    },
                    crate::state::now_millis(),
                );
                let id = item.id;
                if vault.upsert_item(item).is_err() {
                    return Response::Error {
                        message: "internal".into(),
                    };
                }
                if store.save_synced(vault).is_err() {
                    // The caller is told the creation failed, so the login must
                    // not exist anywhere afterwards. Left in memory it would be
                    // the credential a provisioning script believes it did not
                    // create — offered by autofill until the app quits, then
                    // gone, with the account on the far end still expecting it.
                    let _ = vault.purge_item(id, crate::state::now_millis());
                    return Response::Error {
                        message: "internal".into(),
                    };
                }
                id
            };
            crate::sync::mark_dirty();
            Response::CreatedLogin {
                id: id.to_string(),
                title,
                password: if reveal { Some(password) } else { None },
            }
        }
        Request::DeleteBookmarks { url, folder } => {
            if url.trim().is_empty() && folder.trim().is_empty() {
                // Would match the whole collection. Refused rather than
                // interpreted generously.
                return Response::Error {
                    message: "need a url or a folder".into(),
                };
            }
            let mut st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let removed = {
                let AppState { store, vault, .. } = &mut *st;
                let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                let mut hits = Vec::new();
                if let Ok(summaries) = vault.list_items(false) {
                    for sum in summaries {
                        let Ok(item) = vault.get_item(sum.id) else {
                            continue;
                        };
                        if let VaultItem::Bookmark {
                            url: u, folder: f, ..
                        } = &item.data
                        {
                            let matches = if url.trim().is_empty() {
                                // A folder went: everything at or under it.
                                f == &folder || f.starts_with(&format!("{folder}/"))
                            } else {
                                u == &url && f == &folder
                            };
                            if matches {
                                hits.push(item.id);
                            }
                        }
                    }
                }
                if hits.is_empty() {
                    0
                } else {
                    // A bulk retraction is exactly what a rollback point is for.
                    store.snapshot_now();
                    let mut deleted = Vec::new();
                    for id in hits {
                        if vault.delete_item(id, now).is_ok() {
                            deleted.push(id);
                        }
                    }
                    if store.save_synced(vault).is_err() {
                        // Restore every one of them. The reply says nothing was
                        // removed, and a bookmark that is in the Trash in memory
                        // but present on disk is the worst of both: it vanishes
                        // from the app now and comes back at the next unlock.
                        // Only ids this call actually retracted are restored, so
                        // an item already in the Trash stays there.
                        for id in &deleted {
                            let _ = vault.restore_item(*id, now);
                        }
                        return Response::Error {
                            message: "internal".into(),
                        };
                    }
                    deleted.len()
                }
            };
            if removed > 0 {
                crate::sync::mark_dirty();
            }
            Response::DeletedBookmarks { removed }
        }
        Request::DeleteItem { id } => {
            let Ok(uuid) = id.parse::<uuid::Uuid>() else {
                return Response::Error {
                    message: "invalid_id".into(),
                };
            };
            let mut st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let title = {
                let AppState { store, vault, .. } = &mut *st;
                let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
                    return Response::Error {
                        message: "locked".into(),
                    };
                };
                // Read the title BEFORE deleting, so the reply can say what
                // went even though the item is now flagged.
                let Ok(item) = vault.get_item(uuid) else {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                };
                // Already in the Trash: `get_item` finds it, `delete_item`
                // cheerfully re-stamps it, and the reply claimed a retraction
                // that did not happen. An offboarding script that reads that as
                // "this account's credential was live and is now gone" is being
                // told something untrue. The bridge only ever sees active items
                // anyway, so from its side the item is simply not there.
                if item.is_deleted() {
                    return Response::Error {
                        message: "not_found".into(),
                    };
                }
                let title = item.data.title().to_string();
                if vault.delete_item(uuid, now).is_err() {
                    return Response::Error {
                        message: "internal".into(),
                    };
                }
                if store.save_synced(vault).is_err() {
                    // Take it back out of the Trash. The disk still has it
                    // active, so leaving it deleted in memory hides a credential
                    // the user still has — until the next unlock re-reads the
                    // file and it reappears with no explanation. Safe because
                    // the item was demonstrably NOT deleted a moment ago.
                    let _ = vault.restore_item(uuid, now);
                    return Response::Error {
                        message: "internal".into(),
                    };
                }
                title
            };
            crate::sync::mark_dirty();
            Response::Deleted { id, title }
        }
        Request::ReadPassword { id } => {
            let Ok(uuid) = id.parse::<uuid::Uuid>() else {
                return Response::Error {
                    message: "invalid_id".into(),
                };
            };
            let st = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return Response::Error {
                        message: "internal".into(),
                    }
                }
            };
            let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                return Response::Error {
                    message: "locked".into(),
                };
            };
            match vault.get_item(uuid) {
                // A trashed login is not a login you can read, for the same
                // reason `fill` refuses one: the user retired that credential,
                // and nothing in the app still offers it. `get_item` serves the
                // Trash view as well as this one, so the filter has to be here.
                Ok(item) if item.is_deleted() => Response::Error {
                    message: "not_found".into(),
                },
                Ok(item) => match &item.data {
                    VaultItem::Login { password, .. } => Response::Password {
                        password: password.clone(),
                    },
                    _ => Response::Error {
                        message: "not_a_login".into(),
                    },
                },
                Err(_) => Response::Error {
                    message: "not_found".into(),
                },
            }
        }
    }
}

/// Mandatory user approval for a passkey create/get. Returns `Some(user_verified)`
/// on approval — `true` when a genuine user verification gated it — or `None`
/// on denial. A passkey operation must NEVER proceed without this.
/// Whether Arca should handle passkey ceremonies at all (the Settings kill
/// switch). Defaults to on if the state lock is unavailable.
fn passkeys_enabled(state: &Mutex<AppState>) -> bool {
    state
        .lock()
        .map(|st| st.settings.handle_passkeys)
        .unwrap_or(true)
}

/// How long a decline silences further passkey prompts for the same relying
/// party, by how many times in a row it has been declined.
///
/// A single fixed cooldown was the original design and it was wrong: a page
/// that keeps firing ceremonies just gets a fresh prompt every time the window
/// expires, forever. Ninety seconds is not a cooldown, it is a snooze button
/// nobody asked for, and from the user's chair it is indistinguishable from the
/// nag never stopping.
///
/// The escalation matters more than the exact numbers. The browser side tries
/// to tell a real "sign in with a passkey" click from a page auto-firing one,
/// but it only has `navigator.userActivation`, which means "the user did
/// *something* in the last few seconds" — click anywhere on a login page and a
/// background ceremony sails straight through. That heuristic will always be
/// approximate, so this side, which is the one that actually puts a Touch ID
/// prompt on screen, must be the one that can say no permanently.
const PASSKEY_DECLINE_BACKOFF: [Duration; 3] = [
    Duration::from_secs(90),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
];

/// Consecutive declines after which a site is suppressed for the rest of the
/// session. Deliberately not forever-across-restarts: quitting the app is a
/// clear, discoverable way back, and persisting a refusal the user cannot see
/// would strand a genuine sign-in with no explanation.
const PASSKEY_DECLINE_LIMIT: u32 = 4;

/// A handful of declines and then stop, not an unbounded ladder. Checked here
/// rather than in a test because a test that loops to this value would hang
/// instead of failing if it ever grew.
const _: () = assert!(PASSKEY_DECLINE_LIMIT <= 10);

struct PasskeyDecline {
    at: Instant,
    /// Consecutive declines with no approval in between.
    count: u32,
}

/// Per-(site, action) decline state (see the backoff above).
static PASSKEY_DECLINED_AT: LazyLock<Mutex<HashMap<String, PasskeyDecline>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn passkey_decline_map() -> std::sync::MutexGuard<'static, HashMap<String, PasskeyDecline>> {
    match PASSKEY_DECLINED_AT.lock() {
        Ok(m) => m,
        Err(e) => e.into_inner(),
    }
}

/// Whether to stay silent instead of prompting again.
fn passkey_suppressed(key: &str) -> bool {
    let map = passkey_decline_map();
    let Some(decline) = map.get(key) else {
        return false;
    };
    if decline.count >= PASSKEY_DECLINE_LIMIT {
        return true;
    }
    let step = (decline.count as usize).saturating_sub(1);
    decline.at.elapsed() < PASSKEY_DECLINE_BACKOFF[step.min(PASSKEY_DECLINE_BACKOFF.len() - 1)]
}

/// Record a decline. Returns true when this one crossed into "suppressed for
/// the session", so the caller can say so rather than going quiet unexplained.
fn record_passkey_decline(key: &str) -> bool {
    let mut map = passkey_decline_map();
    let decline = map.entry(key.to_string()).or_insert(PasskeyDecline {
        at: Instant::now(),
        count: 0,
    });
    decline.at = Instant::now();
    decline.count += 1;
    decline.count == PASSKEY_DECLINE_LIMIT
}

/// Reset the backoff for a key (after a successful approval, so a later genuine
/// ceremony is not suppressed).
fn clear_passkey_decline(key: &str) {
    passkey_decline_map().remove(key);
}

/// Approve a passkey ceremony. `is_create` distinguishes registering a NEW
/// passkey from signing in with an existing one — the user sees a different
/// prompt for each, so accepting a background "create a passkey" can never be
/// mistaken for a login. The decline cooldown is keyed per (site, action) so a
/// declined create never suppresses a real sign-in.
/// Whether the user wants the master password on every passkey use (the
/// stricter, pre-0.7 behaviour), rather than the unlocked vault plus a click.
fn passkey_reprompt(state: &Mutex<AppState>) -> bool {
    state
        .lock()
        .map(|st| st.settings.passkey_reprompt)
        .unwrap_or(true)
}

fn approve_passkey(
    rp_id: &str,
    is_create: bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
    confirmed: bool,
    require_password: bool,
) -> Option<bool> {
    let cooldown_key = format!("{rp_id}/{}", if is_create { "create" } else { "get" });
    // If the user just declined this same action for this site, a background tab
    // is almost certainly re-firing it — suppress silently instead of nagging.
    // (Only active in production, where `app` drives a real prompt; unit tests
    // inject their own consent and must run every time.)
    if app.is_some() && passkey_suppressed(&cooldown_key) {
        return None;
    }
    let result = approve_passkey_inner(rp_id, is_create, app, consent, confirmed, require_password);
    if let Some(app) = app {
        match result {
            None => {
                if record_passkey_decline(&cooldown_key) {
                    // Going quiet without saying so would look like a bug the
                    // next time the user genuinely wanted to sign in.
                    let _ = app.emit(
                        "passkey-suppressed",
                        PasskeySuppressedDto {
                            site: rp_id.to_string(),
                            is_create,
                        },
                    );
                }
            }
            Some(_) => clear_passkey_decline(&cooldown_key),
        }
    }
    result
}

/// Told to the UI when a site is muted for the session, so the user learns it
/// from Arca rather than from a sign-in that mysteriously stops working.
#[derive(Clone, serde::Serialize)]
struct PasskeySuppressedDto {
    site: String,
    is_create: bool,
}

/// Append one line about an incoming passkey ceremony, so a prompt that appears
/// out of nowhere can be traced instead of guessed at.
///
/// This exists because the "GitHub keeps asking for Touch ID" report has come
/// back repeatedly with nothing to read: the ceremony arrives from a browser
/// context we cannot see, and the app recorded nothing at all. A prompt the
/// user did not expect is exactly the event that needs a paper trail.
///
/// Non-secret by construction — an origin and an rp_id, which the relying party
/// already knows. Bounded so it cannot grow without limit.
/// Record how a ceremony ENDED.
///
/// The arrival line alone was not enough the first time it mattered: a UniFi
/// sign-in was logged as having reached the app, and the log had nothing to say
/// about whether it found a passkey, was refused, timed out on a Touch ID
/// prompt nobody saw, or signed successfully. Those need four different fixes.
pub fn log_passkey_outcome(state: &Mutex<AppState>, rp_id: &str, outcome: &str) {
    log_line(state, &format!("\tresult\trp_id={rp_id}\t{outcome}"));
}

fn log_passkey_request(state: &Mutex<AppState>, origin: &str, rp_id: &str, is_create: bool) {
    let kind = if is_create { "create" } else { "get" };
    log_line(state, &format!("{kind}\torigin={origin}\trp_id={rp_id}"));
}

/// Append one tab-separated line to `passkey-requests.log`, timestamped.
///
/// The vault's own directory — no extra dependency, and it is where every other
/// file of ours already lives. The lock is taken and dropped here, never held
/// across the write.
fn log_line(state: &Mutex<AppState>, rest: &str) {
    use std::io::Write;
    // `try_lock`, NOT `lock`. This is called from inside request handlers, and
    // one of them called it while already holding the guard — a std::sync
    // Mutex is not reentrant, so the app deadlocked on its own debug log and
    // the passkey test hung forever. A log line is worth losing; a hung
    // credential bridge is not, and the next caller to make the same mistake
    // should get a missing line rather than a frozen browser.
    let Some(dir) = state
        .try_lock()
        .ok()
        .and_then(|st| st.store.path().parent().map(|p| p.to_path_buf()))
    else {
        return;
    };
    let path = dir.join("passkey-requests.log");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{stamp}\t{rest}\n");

    // Trim before appending, so the file stays roughly bounded without needing
    // a rotation scheme for what is a debugging aid.
    const MAX_LINES: usize = 500;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let count = existing.lines().count();
        if count >= MAX_LINES {
            let keep: String = existing
                .lines()
                .skip(count - MAX_LINES / 2)
                .map(|l| format!("{l}\n"))
                .collect();
            let _ = std::fs::write(&path, keep);
        }
    }
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// `confirmed`: the user already approved this exact ceremony by a click in
/// Arca's own UI (the in-page picker row, the desktop chooser). `require_password`:
/// the "ask for the master password on every passkey use" setting.
///
/// USER VERIFICATION, as Arca means it. The vault is open, and opening it was
/// the verification: the master password, Touch ID, Windows Hello or the USB
/// key the user enrolled for exactly that purpose, bounded by the idle lock.
/// A sign-in then needs presence — one deliberate click that names the site
/// and the account — not a second password. That is what 1Password and Apple
/// Passwords do; it is what the double prompt was standing in the way of. The
/// setting restores the old per-use password for people who want it, and
/// macOS keeps Touch ID because it is one touch and genuinely biometric.
fn approve_passkey_inner(
    rp_id: &str,
    is_create: bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
    confirmed: bool,
    require_password: bool,
) -> Option<bool> {
    // The reason string the user reads — clearly different for registering a new
    // passkey vs signing in, so a create can't be mistaken for a login.
    let reason = if is_create {
        format!("create a NEW passkey for {rp_id}")
    } else {
        format!("sign in to {rp_id}")
    };
    // macOS: Touch ID — a genuine platform user verification. It's a system
    // prompt, so it works even though the ceremony is triggered from the
    // background (the browser).
    #[cfg(target_os = "macos")]
    if app.is_some() {
        return match crate::biometric::authenticate(None, &reason) {
            Ok(()) => Some(true),
            Err(_) => None,
        };
    }
    // Windows/Linux: the OS platform-authenticator (Windows Hello) dialog can't
    // receive keyboard input when invoked from our background bridge thread, so
    // we do user verification in our OWN window instead — the user re-enters the
    // master password. A correct password is a genuine user-verification factor
    // (the very secret that unlocks the vault), so we may honestly set UV=1.
    #[cfg(not(target_os = "macos"))]
    if let Some(app) = app {
        if confirmed && !require_password {
            return Some(true);
        }
        return request_passkey_verification(app, rp_id, is_create, require_password);
    }
    #[cfg(target_os = "macos")]
    let _ = (confirmed, require_password);
    // Tests / headless (no AppHandle): the injected consent closure provides
    // user presence only (user_verified = false).
    let _ = app;
    let ctx = ConsentContext {
        site: rp_id.to_string(),
        account: String::new(),
        title: reason,
    };
    consent(&ctx).then_some(false)
}

/// Windows/Linux user verification for a passkey ceremony: emit a request to the
/// frontend (which prompts for the master password in our own window), bring the
/// window forward, and block this bridge thread until the password is verified
/// (`Some(true)`) or the user cancels / it times out (`None`). Reuses the
/// `PendingConsents` channel; `verify_passkey_approval` only resolves it `true`
/// after the master password checks out.
#[cfg(not(target_os = "macos"))]
fn request_passkey_verification(
    app: &AppHandle,
    rp_id: &str,
    is_create: bool,
    require_password: bool,
) -> Option<bool> {
    let verify_id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        // Dedicated verification map — never the shared consent map — so only a
        // password-checked resolve (or, when the bridge said a click is enough,
        // the confirm command) can satisfy this `true`.
        let pending = app.state::<PendingVerifications>();
        let Ok(mut map) = pending.0.lock() else {
            return None;
        };
        map.insert(verify_id.clone(), (tx, require_password));
    }
    let _ = app.emit(
        "passkey-verify-request",
        serde_json::json!({
            "id": verify_id,
            "site": rp_id,
            "isCreate": is_create,
            "requirePassword": require_password,
        }),
    );
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
    let verified = rx.recv_timeout(CONSENT_TIMEOUT).unwrap_or(false);
    if let Ok(mut map) = app.state::<PendingVerifications>().0.lock() {
        map.remove(&verify_id);
    }
    verified.then_some(true)
}

fn request_passkey_choice(
    app: &AppHandle,
    rp_id: &str,
    choices: &[PasskeyChoice],
) -> Option<String> {
    let id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let pending = app.state::<PendingPasskeyChoices>();
        let mut map = pending.0.lock().ok()?;
        // Keep one visible chooser; concurrent requests fail closed.
        if !map.is_empty() {
            return None;
        }
        map.insert(id.clone(), tx);
    }
    let emitted = app
        .emit(
            "passkey-choice-request",
            serde_json::json!({"id": id, "site": rp_id, "accounts": choices}),
        )
        .is_ok();
    if emitted {
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
    let choice = if emitted {
        rx.recv_timeout(CONSENT_TIMEOUT).ok().flatten()
    } else {
        None
    };
    if let Ok(mut map) = app.state::<PendingPasskeyChoices>().0.lock() {
        map.remove(&id);
    }
    let _ = app.emit("passkey-choice-closed", &id);
    choice.filter(|id| choices.iter().any(|c| &c.id == id))
}

pub fn resolve_passkey_choice(app: &AppHandle, id: &str, item_id: Option<String>) {
    if let Ok(mut map) = app.state::<PendingPasskeyChoices>().0.lock() {
        if let Some(tx) = map.remove(id) {
            let _ = tx.send(item_id);
        }
    }
}

/// Production consent: emit the request to the frontend, bring the window
/// forward, and block this bridge thread until the user answers (or times out,
/// which denies). Returns `true` only on an explicit Allow.
fn request_consent(app: &AppHandle, ctx: &ConsentContext) -> bool {
    let consent_id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        let pending = app.state::<PendingConsents>();
        let Ok(mut map) = pending.0.lock() else {
            return false;
        };
        map.insert(consent_id.clone(), tx);
    }
    let _ = app.emit(
        "fill-consent-request",
        serde_json::json!({
            "id": consent_id,
            "site": ctx.site,
            "account": ctx.account,
            "title": ctx.title,
        }),
    );
    // Surface the prompt over the browser the user is filling into.
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
    let approved = rx.recv_timeout(CONSENT_TIMEOUT).unwrap_or(false);
    // Drop the sender if it's still registered (timeout path).
    if let Ok(mut map) = app.state::<PendingConsents>().0.lock() {
        map.remove(&consent_id);
    }
    approved
}

/// Deliver a user's Allow/Deny decision to the parked bridge thread.
pub fn resolve_consent(app: &AppHandle, id: &str, approved: bool) {
    if let Ok(mut map) = app.state::<PendingConsents>().0.lock() {
        if let Some(tx) = map.remove(id) {
            let _ = tx.send(approved);
        }
    }
}

/// Resolve a pending passkey user-verification. Called only from the
/// password-checked `verify_passkey_approval` command (with `true`) and the
/// `cancel_passkey_verification` command (always `false`), so the presence-only
/// autofill-consent path can never set UV=1.
pub fn resolve_verification(app: &AppHandle, id: &str, approved: bool) {
    if let Ok(mut map) = app.state::<PendingVerifications>().0.lock() {
        if let Some((tx, _)) = map.remove(id) {
            let _ = tx.send(approved);
        }
    }
}

/// Approve a pending passkey ceremony with a click alone. Refused — and the
/// ceremony left waiting for the password — when the bridge registered it as
/// password-required; a UI cannot downgrade the check by calling this instead.
pub fn confirm_verification(app: &AppHandle, id: &str) -> bool {
    let pending = app.state::<PendingVerifications>();
    let Ok(mut map) = pending.0.lock() else {
        return false;
    };
    match map.get(id) {
        Some((_, false)) => {
            if let Some((tx, _)) = map.remove(id) {
                let _ = tx.send(true);
            }
            true
        }
        _ => false,
    }
}

fn write_info(path: &Path, info: &BridgeInfo) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let json = serde_json::to_vec(info)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(&json)?;
    Ok(())
}

/// Start the bridge server. Binds a loopback port, writes the connection-info
/// file, and serves connections on a background thread.
pub fn start(app: AppHandle, app_data_dir: &Path) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    write_info(
        &info_path(app_data_dir),
        &BridgeInfo {
            port,
            token: token.clone(),
        },
    )?;

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Defense in depth: only loopback peers.
            if stream
                .peer_addr()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false)
            {
                let app = app.clone();
                let token = token.clone();
                std::thread::spawn(move || {
                    let _ = serve(stream, &app, &token);
                });
            }
        }
    });
    Ok(())
}

fn serve(stream: TcpStream, app: &AppHandle, token: &str) -> std::io::Result<()> {
    // A peer that connects and then says nothing held its thread forever.
    // Message SIZE was bounded; connection LIFETIME was not. Well above the
    // 30 s consent wait, which happens between reads, not during one.
    stream.set_read_timeout(Some(std::time::Duration::from_secs(300)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let state = app.state::<Mutex<AppState>>();
    let mut authed = false;
    let mut consent = |ctx: &ConsentContext| request_consent(app, ctx);
    loop {
        let mut line = String::new();
        let read = {
            let mut limited = Read::take(&mut reader, MAX_BRIDGE_MESSAGE_BYTES as u64 + 1);
            limited.read_line(&mut line)?
        };
        if read == 0 {
            break;
        }
        if read > MAX_BRIDGE_MESSAGE_BYTES {
            let out = serde_json::to_string(&Response::Error {
                message: "bad_request".into(),
            })
            .unwrap_or_else(|_| String::from("{\"type\":\"error\"}"));
            writer.write_all(out.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(
                req,
                state.inner(),
                token,
                &mut authed,
                Some(app),
                &mut consent,
            ),
            Err(_) => Response::Error {
                message: "bad_request".into(),
            },
        };
        // One wrong token ends the connection: no unlimited retries on an
        // open socket.
        let unauthorized =
            matches!(&resp, Response::Error { message } if message == "unauthorized");
        let mut out =
            serde_json::to_string(&resp).unwrap_or_else(|_| String::from("{\"type\":\"error\"}"));
        out.push('\n');
        writer.write_all(out.as_bytes())?;
        writer.flush()?;
        if unauthorized {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
