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
pub use vault_bridge::proto::BookmarkWire;
use vault_bridge::proto::{LoginMatch, Request, Response};

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

/// What a request means for the vault's lock state: the app's policy, not
/// part of the protocol.
trait Intent {
    fn wants_vault_open(&self) -> bool;
    fn is_deliberate_use(&self) -> bool;
}

impl Intent for Request {
    /// Requests the USB key may open a locked vault for: the ones a person is
    /// directly behind. `Match` is included because it is what puts
    /// credentials in the picker when a field takes focus — without it the
    /// stick would only help after a failed fill. A `Match` with no URL names
    /// no site: it is `arca status`, or a native host before protocol 3
    /// checking the app is up, and asking must not be what unlocks.
    fn wants_vault_open(&self) -> bool {
        match self {
            Request::Match { url } => !url.is_empty(),
            Request::Fill { .. }
            | Request::PasskeyCreate { .. }
            | Request::PasskeyGet { .. }
            | Request::SaveLogin { .. }
            | Request::CreateLogin { .. }
            | Request::ReadPassword { .. }
            | Request::DeleteItem { .. } => true,
            _ => false,
        }
    }

    /// Whether this request is the user deciding to use the vault, as opposed
    /// to the extension talking to us on its own.
    ///
    /// Only the deliberate ones reset the idle timer. `Hello` and `Auth` are
    /// the handshake, `Match` fires when a password field takes focus, and
    /// `SaveProbe` fires on every submitted form — counting any of those would
    /// let one open tab hold the vault unlocked indefinitely. That is not a
    /// longer timeout, it is no timeout, arrived at by accident.
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
            | Request::Auth { .. }
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
    for item in vault.active_items().ok()? {
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
        for item in vault.active_items().ok()? {
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
    for item in vault.active_items().ok()? {
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

fn unauthorized() -> Response {
    error("unauthorized")
}

fn error(message: impl Into<String>) -> Response {
    Response::Error {
        message: message.into(),
    }
}

/// What an authenticated client learns about this build.
fn welcome(proof: Option<String>) -> Response {
    Response::Ok {
        protocol: PROTOCOL_VERSION,
        version: APP_VERSION.into(),
        build: env!("ARCA_BUILD").into(),
        commit: env!("ARCA_COMMIT").into(),
        pid: std::process::id(),
        proof,
    }
}

/// The first message on a connection; see `vault_bridge::auth` for protocol 3.
fn hello(
    token: &str,
    presented: Option<String>,
    protocol: Option<u32>,
    nonce: Option<String>,
    session: &mut Session,
) -> Response {
    *session = Session::New;
    let Some(presented) = presented else {
        // Protocol 3: prove ourselves first, without the token crossing.
        if protocol != Some(PROTOCOL_VERSION) {
            return unauthorized();
        }
        let Some(client_nonce) = nonce.filter(|n| vault_bridge::auth::is_nonce(n)) else {
            return unauthorized();
        };
        let Some(app_nonce) = vault_bridge::auth::nonce() else {
            return error("internal");
        };
        let proof = vault_bridge::auth::app_proof(token, &client_nonce, &app_nonce);
        *session = Session::Challenged {
            client_nonce,
            app_nonce: app_nonce.clone(),
        };
        return Response::Challenge {
            nonce: app_nonce,
            proof,
        };
    };
    // Protocols 1 and 2 put the token in this message. Checked before the
    // version, so a caller that cannot authenticate learns nothing about us.
    if !vault_bridge::auth::same(&presented, token) {
        return unauthorized();
    }
    // We can serve a client older than us; we cannot serve one newer,
    // because we do not know what it means and guessing is worse than
    // saying so. Absent is the pre-versioning native host, i.e. v1.
    if protocol.is_some_and(|v| !(1..=PROTOCOL_VERSION).contains(&v)) {
        return error("unsupported_protocol");
    }
    *session = Session::Authed;
    welcome(nonce.map(|n| vault_bridge::auth::v2_proof(token, &n)))
}

/// Where one connection stands in the handshake.
#[derive(Debug, Default, PartialEq)]
pub(crate) enum Session {
    #[default]
    New,
    /// Protocol 3: the app has proved itself over the client's nonce and is
    /// waiting for the client's proof over the pair.
    Challenged {
        client_nonce: String,
        app_nonce: String,
    },
    Authed,
}

impl Session {
    fn is_authed(&self) -> bool {
        matches!(self, Session::Authed)
    }
}

/// Handle one parsed request. `session` tracks this connection's handshake.
/// Factored out (no sockets) so the security gates are unit-testable.
fn handle_request(
    req: Request,
    state: &Mutex<AppState>,
    token: &str,
    session: &mut Session,
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
    let deliberate = session.is_authed() && req.is_deliberate_use();
    // A USB key enrolled and inserted: a request that needs the vault open
    // finds it open, with no window and no password. This is the
    // whole point of the key — "unlock" stops being a step between the
    // browser and the credential. Only for requests the user is behind (a
    // field they focused, a fill, a passkey); a form submit's save probe or a
    // bookmark timer must not be what keeps the vault open.
    if session.is_authed()
        && req.wants_vault_open()
        && crate::keyfile_unlock::unlock_if_locked(state)
    {
        if let Some(app) = app {
            crate::session::unlocked(app);
        }
    }
    let resp = dispatch(req, state, token, session, app, consent);
    if deliberate && !matches!(resp, Response::Error { .. }) {
        if let Ok(mut st) = state.lock() {
            st.touch();
        }
    }
    resp
}

/// What a request handler needs besides its request: the app state, the
/// window (absent in tests), and the in-app autofill approval.
struct Ctx<'a> {
    state: &'a Mutex<AppState>,
    app: Option<&'a AppHandle>,
    consent: &'a mut dyn FnMut(&ConsentContext) -> bool,
}

fn dispatch(
    req: Request,
    state: &Mutex<AppState>,
    token: &str,
    session: &mut Session,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
) -> Response {
    let mut ctx = Ctx {
        state,
        app,
        consent,
    };
    match req {
        Request::Hello {
            token: presented,
            protocol,
            nonce,
        } => hello(token, presented, protocol, nonce, session),
        Request::Auth { proof } => {
            let Session::Challenged {
                client_nonce,
                app_nonce,
            } = std::mem::take(session)
            else {
                return unauthorized();
            };
            let expected = vault_bridge::auth::client_proof(token, &client_nonce, &app_nonce);
            if !vault_bridge::auth::same(&proof, &expected) {
                return unauthorized();
            }
            *session = Session::Authed;
            welcome(None)
        }
        _ if !session.is_authed() => unauthorized(),
        Request::Match { url } => list_matches(&mut ctx, url),
        Request::Fill { id, url } => fill(&mut ctx, id, url),
        Request::PasskeyCreate {
            origin,
            rp_id,
            user_name,
            user_handle,
            exclude_credentials,
        } => passkey_create(
            &mut ctx,
            origin,
            rp_id,
            user_name,
            user_handle,
            exclude_credentials,
        ),
        Request::PasskeyGet {
            origin,
            rp_id,
            client_data_hash,
            allow_credentials,
            picked,
        } => passkey_get(
            &mut ctx,
            origin,
            rp_id,
            client_data_hash,
            allow_credentials,
            picked,
        ),
        Request::ImportBookmarks { items } => import_bookmarks(&mut ctx, items),
        Request::ListBookmarks => list_bookmarks(&mut ctx),
        Request::SaveProbe {
            url,
            username,
            password,
        } => save_probe(&mut ctx, url, username, password),
        Request::SaveLogin {
            url,
            username,
            password,
        } => save_login(&mut ctx, url, username, password),
        Request::Unlock => unlock_for_browser(&mut ctx),
        Request::GeneratePassword { length, symbols } => generate(generator(length, symbols, 20)),
        Request::CreateLogin {
            title,
            username,
            url,
            notes,
            length,
            symbols,
            reveal,
        } => create_login(
            &mut ctx,
            title,
            username,
            url,
            notes,
            generator(length, symbols, 24),
            reveal,
        ),
        Request::DeleteBookmarks { url, folder } => delete_bookmarks(&mut ctx, url, folder),
        Request::DeleteItem { id } => delete_item(&mut ctx, id),
        Request::ReadPassword { id } => read_password(&mut ctx, id),
    }
}

fn list_matches(ctx: &mut Ctx, url: String) -> Response {
    let state = ctx.state;
    let st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return error("locked");
    };
    let mut items = Vec::new();
    // Passkeys whose rp_id does not match this page directly. Resolved
    // after the lock is released.
    let mut deferred: Vec<(String, LoginMatch)> = Vec::new();
    if let Ok(active) = vault.active_items() {
        for item in active {
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

fn fill(ctx: &mut Ctx, id: String, url: String) -> Response {
    let state = ctx.state;
    let app = ctx.app;
    let consent = &mut *ctx.consent;
    // Resolve + validate under the lock, then extract just what we need
    // and release it before any (possibly slow) user consent prompt.
    let confirm;
    let username;
    let password;
    let title;
    {
        let st = match state.lock() {
            Ok(s) => s,
            Err(_) => return error("internal"),
        };
        let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        let Ok(uuid) = Uuid::parse_str(&id) else {
            return error("not_found");
        };
        let Ok(item) = vault.get_item(uuid) else {
            return error("not_found");
        };
        // Trashed is trashed. `get_item` answers for deleted items too —
        // it is the Trash view's reader as much as autofill's — so a
        // credential the user retired stayed fillable by id for as long
        // as it sat in the bin. `Match` never offers one (it lists
        // active items), which made this reachable only by an id from an
        // earlier session or from something else on this machine, and
        // invisible to the user either way.
        if item.is_deleted() {
            return error("not_found");
        }
        let VaultItem::Login {
            url: u,
            username: un,
            password: pw,
            title: t,
            ..
        } = &item.data
        else {
            return error("not_found");
        };
        // Origin binding: never hand a credential to a non-matching host.
        if !domain_matches(u, &url) {
            return error("origin_mismatch");
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
            return error("denied");
        }
        // The prompt can outlast the vault: with lock-on-blur, glancing
        // back at the browser while Arca asks locks it, and a credential
        // must not leave after that. Re-check now that the wait is over.
        let locked = state
            .lock()
            .map(|st| !st.vault.as_ref().is_some_and(|v| v.is_unlocked()))
            .unwrap_or(true);
        if locked {
            return error("locked");
        }
    }

    if let Some(app) = app {
        let _ = app.emit("autofilled", format!("{title} ({})", host_of(&url)));
    }
    Response::Credentials { username, password }
}

fn passkey_create(
    ctx: &mut Ctx,
    origin: String,
    rp_id: String,
    user_name: String,
    user_handle: Vec<u8>,
    exclude_credentials: Vec<Vec<u8>>,
) -> Response {
    let state = ctx.state;
    let app = ctx.app;
    let consent = &mut *ctx.consent;
    // Kill switch: when passkey handling is off, ignore the ceremony so
    // the browser / platform authenticator takes over (the shim falls
    // back on this error). No prompt, ever.
    if !passkeys_enabled(state) {
        return error("passkeys_disabled");
    }
    // Anti-phishing: the RP id must belong to the page's origin.
    log_passkey_request(state, &origin, &rp_id, true);
    // Related Origin Requests apply to the ceremony too — a passkey
    // registered for login.microsoft.com must be usable on the page
    // Microsoft actually redirects you to. No lock is held here.
    if !rp_id_allows_origin(&rp_id, &origin) {
        return error("origin_mismatch");
    }
    match registered_already(state, &rp_id, &user_handle, &exclude_credentials) {
        Err(response) => return response,
        Ok(Some(Registered::Excluded)) => return error("excluded"),
        Ok(Some(Registered::SameAccount)) => {
            // Emitted outside the state lock: this reaches the webview, and
            // the webview answers by calling commands that take that lock.
            if let Some(app) = app {
                let _ = app.emit("passkey-registration-blocked", rp_id.clone());
            }
            return error("excluded");
        }
        Ok(None) => {}
    }
    // Registration ALWAYS requires an explicit user approval; a silent
    // create must never register a credential. `true` = this is a NEW
    // passkey, so the prompt says "create" (not "sign in").
    let require_password = passkey_reprompt(state);
    let Some(user_verified) = approve_passkey(&rp_id, true, app, consent, false, require_password)
    else {
        return error("denied");
    };
    let Ok(new_pk) = vault_core::passkey::create(&rp_id, user_verified) else {
        return error("internal");
    };
    let credential_id = new_pk.credential_id.clone();
    let attestation_object = new_pk.attestation_object;
    let key = (new_pk.credential_id, new_pk.private_key.to_vec());
    if let Err(response) = store_new_passkey(state, &rp_id, user_name, user_handle, key) {
        return response;
    }
    if let Some(app) = app {
        let _ = app.emit("passkey-created", rp_id);
    }
    Response::PasskeyCredential {
        credential_id,
        attestation_object,
    }
}

/// A passkey this relying party already has, which a registration would
/// duplicate.
enum Registered {
    /// The site listed it in `excludeCredentials`.
    Excluded,
    /// Same relying party and user handle, whatever the site listed.
    SameAccount,
}

/// Checked before the user is asked anything, with the vault unlocked.
fn registered_already(
    state: &Mutex<AppState>,
    rp_id: &str,
    user_handle: &[u8],
    exclude_credentials: &[Vec<u8>],
) -> Result<Option<Registered>, Response> {
    let st = state.lock().map_err(|_| error("internal"))?;
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
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
    for item in vault.active_items().into_iter().flatten() {
        if let VaultItem::Passkey {
            rp_id: r,
            credential_id: cid,
            user_handle: uh,
            ..
        } = &item.data
        {
            if r.as_str() != rp_id {
                continue;
            }
            if exclude_credentials.iter().any(|e| e == cid) {
                return Ok(Some(Registered::Excluded));
            }
            if uh.as_slice() == user_handle {
                return Ok(Some(Registered::SameAccount));
            }
        }
    }
    Ok(None)
}

/// Store a passkey just created for `rp_id`: its credential id and private
/// key. Rolled back out if the vault cannot be saved.
fn store_new_passkey(
    state: &Mutex<AppState>,
    rp_id: &str,
    user_name: String,
    user_handle: Vec<u8>,
    (credential_id, private_key): (Vec<u8>, Vec<u8>),
) -> Result<(), Response> {
    let mut st = state.lock().map_err(|_| error("internal"))?;
    let AppState { store, vault, .. } = &mut *st;
    let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
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
        vault.active_items().ok().and_then(|mut active| {
            active.find_map(|item| match &item.data {
                VaultItem::Passkey {
                    rp_id: r,
                    user_handle: uh,
                    ..
                } if r == rp_id && *uh == user_handle => Some(item.id),
                _ => None,
            })
        })
    };
    let mut item = Item::new(
        VaultItem::Passkey {
            title: rp_id.to_owned(),
            rp_id: rp_id.to_owned(),
            user_name,
            user_handle,
            credential_id,
            private_key,
            sign_count: 0,
        },
        crate::state::now_millis(),
    );
    if let Some(id) = existing_id {
        item.id = id;
    }
    let new_id = item.id;
    vault.upsert_item(item).map_err(|_| error("internal"))?;
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
        return Err(error("internal"));
    }
    crate::sync::mark_dirty();
    Ok(())
}

fn passkey_get(
    ctx: &mut Ctx,
    origin: String,
    rp_id: String,
    client_data_hash: Vec<u8>,
    allow_credentials: Vec<Vec<u8>>,
    picked: bool,
) -> Response {
    let state = ctx.state;
    let app = ctx.app;
    let consent = &mut *ctx.consent;
    if !passkeys_enabled(state) {
        return error("passkeys_disabled");
    }
    log_passkey_request(state, &origin, &rp_id, false);
    // Related Origin Requests apply to the ceremony too — a passkey
    // registered for login.microsoft.com must be usable on the page
    // Microsoft actually redirects you to. No lock is held here.
    if !rp_id_allows_origin(&rp_id, &origin) {
        return error("origin_mismatch");
    }
    // Discover eligible accounts without choosing the first matching key.
    let choices = match passkey_choices(state, &rp_id, &allow_credentials) {
        Ok(choices) => choices,
        Err(response) => return response,
    };
    if choices.is_empty() {
        log_passkey_outcome(state, &rp_id, "no_passkey_stored");
        return error("not_found");
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
            return error("account_selection_required");
        }
        (_, Some(app)) => {
            let Some(id) = request_passkey_choice(app, &rp_id, &choices) else {
                log_passkey_outcome(state, &rp_id, "declined_in_chooser");
                return error("account_selection_cancelled");
            };
            (id, true)
        }
    };
    let Some(choice) = choices.iter().find(|c| c.id == selected) else {
        return error("account_selection_cancelled");
    };
    // Reload after the choice: the vault may have locked or synced while
    // the dialog was open. Never substitute a different account.
    let ChosenPasskey {
        credential_id,
        user_handle,
        private_key,
    } = match chosen_passkey(state, &selected, &rp_id, &choice.credential_id) {
        Ok(chosen) => chosen,
        Err(response) => return response,
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
        return error("denied");
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
        return error("locked");
    }

    let Ok((authenticator_data, signature)) =
        vault_core::passkey::assert(&private_key, &rp_id, &client_data_hash, user_verified)
    else {
        return error("internal");
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

/// The passkeys stored for `rp_id` that the site allows, as accounts to
/// choose from.
fn passkey_choices(
    state: &Mutex<AppState>,
    rp_id: &str,
    allow_credentials: &[Vec<u8>],
) -> Result<Vec<PasskeyChoice>, Response> {
    let st = state.lock().map_err(|_| error("internal"))?;
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
    };
    Ok(vault
        .active_items()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            if let VaultItem::Passkey {
                rp_id: r,
                credential_id,
                user_name,
                ..
            } = &item.data
            {
                let allowed =
                    allow_credentials.is_empty() || allow_credentials.contains(credential_id);
                if r == rp_id && allowed {
                    return Some(PasskeyChoice {
                        id: item.id.to_string(),
                        account: user_name.clone(),
                        title: item.data.title().to_owned(),
                        credential_id: credential_id.clone(),
                    });
                }
            }
            None
        })
        .collect())
}

/// What signing an assertion needs of the passkey the user chose.
struct ChosenPasskey {
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    private_key: Vec<u8>,
}

/// The chosen passkey, if it is still the one chosen: same item, relying
/// party and credential, and not deleted.
fn chosen_passkey(
    state: &Mutex<AppState>,
    selected: &str,
    rp_id: &str,
    credential_id: &[u8],
) -> Result<ChosenPasskey, Response> {
    let st = state.lock().map_err(|_| error("internal"))?;
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
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
        }) if r == rp_id && cid.as_slice() == credential_id => Ok(ChosenPasskey {
            credential_id: cid.clone(),
            user_handle: user_handle.clone(),
            private_key: private_key.clone(),
        }),
        _ => Err(error("not_found")),
    }
}

fn import_bookmarks(ctx: &mut Ctx, items: Vec<BookmarkWire>) -> Response {
    let state = ctx.state;
    let Ok(mut st) = state.lock() else {
        return error("internal");
    };
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    // The ids, not just a count: a save that fails has to be undone item
    // by item, and nothing else in the vault may be touched.
    let mut added: Vec<Uuid> = Vec::new();
    let now = crate::state::now_millis();
    {
        let Some(vault) = st.vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        if let Ok(active) = vault.active_items() {
            for item in active {
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
                return error("internal");
            }
        }
        // Every other bridge write marks dirty; this one didn't, so an
        // import stayed local-only until some unrelated edit pushed it.
        crate::sync::mark_dirty();
    }
    Response::ImportedBookmarks { added: added.len() }
}

fn list_bookmarks(ctx: &mut Ctx) -> Response {
    let state = ctx.state;
    let Ok(st) = state.lock() else {
        return error("internal");
    };
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return error("locked");
    };
    let mut items = Vec::new();
    if let Ok(active) = vault.active_items() {
        for item in active {
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

fn save_probe(ctx: &mut Ctx, url: String, username: String, password: String) -> Response {
    let state = ctx.state;
    if password.is_empty() {
        return Response::SaveDecision {
            action: "known".into(), // nothing worth saving
            username: None,
        };
    }
    let st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
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

fn save_login(ctx: &mut Ctx, url: String, username: String, password: String) -> Response {
    let state = ctx.state;
    let app = ctx.app;
    if password.is_empty() {
        return error("empty");
    }
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    if !st.settings.save_prompt {
        return error("disabled");
    }
    let host = host_of(&url);
    if host.is_empty() {
        return error("invalid");
    }
    {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        match find_login_for_save(vault, &url, &username) {
            // Already stored with this password: nothing to do.
            Some((_, _, cur)) if cur == password => return Response::Saved,
            // Same site + username, new password: update in place.
            Some((id, _, _)) => {
                let Ok(current) = vault.get_item(id) else {
                    return error("internal");
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
                        return error("internal");
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
                        return error(save_failure_reason(&e));
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
                    return error("internal");
                }
                if let Err(e) = store.save_synced(vault) {
                    // Same trade as the update branch, from the other
                    // side: an entry that never reached the disk must
                    // not sit in memory claiming the site is already
                    // saved. Purged rather than soft-deleted — it was
                    // never a vault entry, and it must not surface in
                    // the Trash as something the user could restore.
                    let _ = vault.purge_item(new_id, crate::state::now_millis());
                    return error(save_failure_reason(&e));
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

fn unlock_for_browser(ctx: &mut Ctx) -> Response {
    let state = ctx.state;
    let app = ctx.app;
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
        st.blur_grace_until = Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
    }

    // A USB key that is plugged in opens the vault before any prompt
    // is considered, on every platform: no Touch ID sheet, no Hello
    // dialog, no window. That is what the key is for.
    if crate::keyfile_unlock::unlock_if_locked(state) {
        if let Some(app) = app {
            crate::session::unlocked(app);
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
            Err(failure)
                if failure.code == "biometric_failed"
                    || failure.code == "unlock_cancelled"
                    || failure.code == "unlock_in_progress" =>
            {
                return if failure.code == "unlock_in_progress" {
                    Response::UnlockRequested
                } else {
                    error("unlock_cancelled")
                }
            }
            Err(_) => false,
        };
        #[cfg(target_os = "windows")]
        let unlocked = crate::biometric::authenticate(app, "unlock your password vault").is_ok()
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
                crate::session::unlocked(app);
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

/// A generator request over the bridge. Clamped rather than refused: a site
/// that caps passwords at 16 is a real thing, and failing the request would
/// send the user to type one themselves, the outcome generating exists to
/// avoid.
fn generator(
    length: Option<usize>,
    symbols: Option<bool>,
    default_length: usize,
) -> vault_core::password::PasswordOptions {
    vault_core::password::PasswordOptions {
        length: length.unwrap_or(default_length).clamp(8, 64),
        symbols: symbols.unwrap_or(true),
        ..Default::default()
    }
}

fn generate(opts: vault_core::password::PasswordOptions) -> Response {
    match vault_core::password::generate_password(&opts) {
        Ok(pw) => Response::GeneratedPassword {
            password: pw.to_string(),
        },
        Err(_) => error("internal"),
    }
}

fn create_login(
    ctx: &mut Ctx,
    title: String,
    username: String,
    url: String,
    notes: String,
    opts: vault_core::password::PasswordOptions,
    reveal: bool,
) -> Response {
    let state = ctx.state;
    if title.trim().is_empty() {
        return error("title_required");
    }
    let Ok(password) = vault_core::password::generate_password(&opts) else {
        return error("internal");
    };
    let password = password.to_string();

    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let id = {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
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
            return error("internal");
        }
        if store.save_synced(vault).is_err() {
            // The caller is told the creation failed, so the login must
            // not exist anywhere afterwards. Left in memory it would be
            // the credential a provisioning script believes it did not
            // create — offered by autofill until the app quits, then
            // gone, with the account on the far end still expecting it.
            let _ = vault.purge_item(id, crate::state::now_millis());
            return error("internal");
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

fn delete_bookmarks(ctx: &mut Ctx, url: String, folder: String) -> Response {
    let state = ctx.state;
    if url.trim().is_empty() && folder.trim().is_empty() {
        // Would match the whole collection. Refused rather than
        // interpreted generously.
        return error("need a url or a folder");
    }
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let removed = {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        let mut hits = Vec::new();
        if let Ok(active) = vault.active_items() {
            for item in active {
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
                return error("internal");
            }
            deleted.len()
        }
    };
    if removed > 0 {
        crate::sync::mark_dirty();
    }
    Response::DeletedBookmarks { removed }
}

fn delete_item(ctx: &mut Ctx, id: String) -> Response {
    let state = ctx.state;
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return error("invalid_id");
    };
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let title = {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        // Read the title BEFORE deleting, so the reply can say what
        // went even though the item is now flagged.
        let Ok(item) = vault.get_item(uuid) else {
            return error("not_found");
        };
        // Already in the Trash: `get_item` finds it, `delete_item`
        // cheerfully re-stamps it, and the reply claimed a retraction
        // that did not happen. An offboarding script that reads that as
        // "this account's credential was live and is now gone" is being
        // told something untrue. The bridge only ever sees active items
        // anyway, so from its side the item is simply not there.
        if item.is_deleted() {
            return error("not_found");
        }
        let title = item.data.title().to_string();
        if vault.delete_item(uuid, now).is_err() {
            return error("internal");
        }
        if store.save_synced(vault).is_err() {
            // Take it back out of the Trash. The disk still has it
            // active, so leaving it deleted in memory hides a credential
            // the user still has — until the next unlock re-reads the
            // file and it reappears with no explanation. Safe because
            // the item was demonstrably NOT deleted a moment ago.
            let _ = vault.restore_item(uuid, now);
            return error("internal");
        }
        title
    };
    crate::sync::mark_dirty();
    Response::Deleted { id, title }
}

fn read_password(ctx: &mut Ctx, id: String) -> Response {
    let state = ctx.state;
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return error("invalid_id");
    };
    let st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return error("locked");
    };
    match vault.get_item(uuid) {
        // A trashed login is not a login you can read, for the same
        // reason `fill` refuses one: the user retired that credential,
        // and nothing in the app still offers it. `get_item` serves the
        // Trash view as well as this one, so the filter has to be here.
        Ok(item) if item.is_deleted() => error("not_found"),
        Ok(item) => match &item.data {
            VaultItem::Login { password, .. } => Response::Password {
                password: password.clone(),
            },
            _ => error("not_a_login"),
        },
        Err(_) => error("not_found"),
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
    let mut session = Session::New;
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
            let out = serde_json::to_string(&error("bad_request"))
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
                &mut session,
                Some(app),
                &mut consent,
            ),
            Err(_) => error("bad_request"),
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
