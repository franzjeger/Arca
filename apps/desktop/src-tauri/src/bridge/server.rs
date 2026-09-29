//! The socket: the connection file, the handshake, and routing each request
//! to its handler. What a request means for the lock state lives here too:
//! it is the app's policy, not the protocol's.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use vault_bridge::proto::Request;

use crate::state::AppState;

use super::*;

/// Largest newline-delimited request accepted from the local bridge client.
/// Authentication happens inside the message, so cap allocation before JSON
/// parsing even for an unauthenticated local process.
pub(super) const MAX_BRIDGE_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// What a request means for the vault's lock state: the app's policy, not
/// part of the protocol.
pub(super) trait Intent {
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
pub(super) struct BridgeInfo {
    pub(super) port: u16,
    pub(super) token: String,
}

pub(super) fn info_path(app_data_dir: &Path) -> PathBuf {
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
pub(super) fn try_device_unlock(state: &Mutex<AppState>) -> bool {
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
pub(super) fn ask_window_to_unlock(app: Option<&AppHandle>) {
    let Some(app) = app else { return };
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    let _ = app.emit("unlock-requested", ());
}

/// What an authenticated client learns about this build.
pub(super) fn welcome(proof: Option<String>) -> Response {
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
pub(super) fn hello(
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
    pub(super) fn is_authed(&self) -> bool {
        matches!(self, Session::Authed)
    }
}

/// Handle one parsed request. `session` tracks this connection's handshake.
/// Factored out (no sockets) so the security gates are unit-testable.
pub(super) fn handle_request(
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
pub(super) struct Ctx<'a> {
    pub(super) state: &'a Mutex<AppState>,
    pub(super) app: Option<&'a AppHandle>,
    pub(super) consent: &'a mut dyn FnMut(&ConsentContext) -> bool,
}

pub(super) fn dispatch(
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

pub(super) fn unlock_for_browser(ctx: &mut Ctx) -> Response {
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

pub(super) fn write_info(path: &Path, info: &BridgeInfo) -> std::io::Result<()> {
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

pub(super) fn serve(stream: TcpStream, app: &AppHandle, token: &str) -> std::io::Result<()> {
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
