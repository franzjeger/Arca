//! Native-messaging host for the Arca browser extension.
//!
//! Browsers speak the "native messaging" wire protocol: each message is a
//! 4-byte length prefix (native byte order — little-endian on all supported
//! platforms) followed by that many bytes of UTF-8 JSON. This binary reads
//! requests on stdin and writes responses on stdout.
//!
//! Login lookup and credential release are delegated to the desktop app, which
//! exclusively owns the unlocked vault. This host is a framed relay; it never
//! opens the vault file itself.
//!
//! SECURITY: this process never holds the vault key. A password crosses it only
//! in the response to an explicit fill that the unlocked desktop app accepted
//! for the exact normalized origin; list/search responses contain metadata.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, BufReader, Read, Write};
mod bridge_schema;
mod launch;

use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const HOST_NAME: &str = "no.sybr.vault";
const PROTOCOL_VERSION: u32 = 1;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the desktop app's newline-JSON bridge protocol this host is
/// written against. Must match `PROTOCOL_VERSION` in the app's `bridge.rs`;
/// a mismatch means the two shipped out of step, and refusing the connection
/// reads as itself rather than as garbled requests.
const BRIDGE_PROTOCOL: u32 = 2;
/// Reject absurd frame sizes (browsers cap extension->host at 1 MiB).
const MAX_MESSAGE_BYTES: u32 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    /// Handshake; the extension announces itself.
    Hello {
        #[serde(default)]
        #[allow(dead_code)]
        version: Option<String>,
        /// Native-messaging protocol spoken by the extension. Absent means
        /// the original v1 extension, for backwards compatibility.
        #[serde(default)]
        protocol: Option<u32>,
    },
    /// Liveness check.
    Ping,
    /// The user deleted a bookmark, or a folder, out of Arca's folder.
    DeleteBookmarks {
        #[serde(default)]
        url: String,
        #[serde(default)]
        folder: String,
    },
    /// Something the extension wants written down where a human with a
    /// terminal can read it.
    ///
    /// An extension's console lives in the browser's memory and nowhere else:
    /// no file, no `log show`, nothing a terminal can reach. So a bug in the
    /// service worker is invisible unless someone is standing in front of that
    /// browser with DevTools open — which, when the person reporting it and
    /// the person fixing it are not the same person, means it is invisible.
    ///
    /// This is the same trick that settled two arguments today: the AutoFill
    /// publish log and the passkey request log. Write it down and stop
    /// guessing.
    Log {
        #[serde(default)]
        level: String,
        message: String,
    },
    /// Ask for logins whose site matches `url` (the active tab's URL).
    ListMatchingLogins { url: String },
    /// Fetch the credential for a chosen login id, to fill into `url`.
    Fill { id: String, url: String },
    /// Register a WebAuthn passkey (navigator.credentials.create).
    PasskeyCreate {
        origin: String,
        rp_id: String,
        #[serde(default)]
        user_name: String,
        #[serde(default)]
        user_handle: Vec<u8>,
        #[serde(default)]
        exclude_credentials: Vec<Vec<u8>>,
    },
    /// Hand the browser's bookmarks to Arca.
    ImportBookmarks {
        #[serde(default)]
        items: Vec<serde_json::Value>,
    },
    /// Fetch Arca's whole bookmark list, to apply to this browser.
    ListBookmarks,
    /// Assert a WebAuthn passkey (navigator.credentials.get).
    PasskeyGet {
        origin: String,
        rp_id: String,
        client_data_hash: Vec<u8>,
        #[serde(default)]
        allow_credentials: Vec<Vec<u8>>,
        /// Chosen in Arca's in-page picker (passed through; the app decides
        /// what it is worth).
        #[serde(default)]
        picked: bool,
    },
    /// Ask whether a submitted login is worth offering to save.
    SaveProbe {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Store a captured login (after the user clicked Save).
    SaveLogin {
        url: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Ask the desktop app to come forward and prompt for unlock.
    #[serde(rename = "request_unlock")]
    Unlock,
    /// A fresh random password for a sign-up form.
    GeneratePassword {
        #[serde(default)]
        length: Option<usize>,
        #[serde(default)]
        symbols: Option<bool>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    /// How many bookmarks an import added.
    ImportedBookmarks {
        added: u64,
    },
    /// How many a browser-side deletion retracted.
    DeletedBookmarks {
        removed: u64,
    },
    /// Arca's bookmark list, for the extension to apply to this browser.
    Bookmarks {
        items: Vec<serde_json::Value>,
    },
    Hello {
        name: String,
        version: String,
        protocol: u32,
        /// Whether the authenticated desktop bridge is reachable (even if locked).
        app_connected: bool,
        /// Whether an explicit unlock can start a standard installation.
        app_launchable: bool,
        /// Desktop app version, when its authenticated bridge reports one.
        #[serde(skip_serializing_if = "Option::is_none")]
        app_version: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        app_build: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        app_commit: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        app_pid: Option<u32>,
    },
    Pong,
    Logins {
        url: String,
        app_connected: bool,
        /// Credential *metadata* only — never passwords.
        items: Vec<LoginMatch>,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// The credential for a `fill` request. Only emitted after the desktop app
    /// authorized it (unlocked + origin match).
    Credentials {
        username: String,
        password: String,
    },
    /// Result of a passkey registration.
    PasskeyCredential {
        credential_id: Vec<u8>,
        attestation_object: Vec<u8>,
    },
    /// Result of a passkey assertion.
    PasskeyAssertion {
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    },
    /// Result of a save probe: "new" | "update" | "known" | "disabled" | "locked".
    /// For "update", `username` is the stored login the app would overwrite,
    /// passed through so the page can show which account before the user
    /// agrees.
    SaveDecision {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    /// A login was stored.
    Saved,
    /// A generated password, on its way to a sign-up form. Never stored here.
    GeneratedPassword {
        password: String,
    },
    /// The app was asked to come forward and prompt.
    UnlockRequested,
    Error {
        message: String,
    },
}

/// Non-secret summary of a matching login, safe to hand to the extension UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LoginMatch {
    id: String,
    /// Identifies the exact passkey selected in the browser's account picker.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credential_id: Vec<u8>,
    title: String,
    username: String,
    url: String,
    /// "password" for a stored login, "passkey" for a WebAuthn credential.
    /// Defaults to "password" so an older desktop app (no `kind`) still lists
    /// its logins.
    #[serde(default = "bridge_schema::default_kind")]
    kind: String,
}

fn handle(request: Request) -> Response {
    match request {
        Request::Hello { protocol, .. } => {
            if protocol.unwrap_or(1) != PROTOCOL_VERSION {
                return Response::Error {
                    message: "unsupported_protocol".to_string(),
                };
            }
            let app = desktop_app_info();
            Response::Hello {
                name: HOST_NAME.to_string(),
                version: VERSION.to_string(),
                protocol: PROTOCOL_VERSION,
                app_connected: app.is_some(),
                app_launchable: launch::available(),
                app_version: app.as_ref().and_then(|a| a.version.clone()),
                app_build: app.as_ref().and_then(|a| a.build.clone()),
                app_commit: app.as_ref().and_then(|a| a.commit.clone()),
                app_pid: app.as_ref().and_then(|a| a.pid),
            }
        }
        Request::Ping => Response::Pong,
        Request::DeleteBookmarks { url, folder } => {
            match bridge_request(serde_json::json!({
                "type": "delete_bookmarks", "url": url, "folder": folder,
            })) {
                Some(v) if v.get("type").and_then(|t| t.as_str()) == Some("deleted_bookmarks") => {
                    Response::DeletedBookmarks {
                        removed: v.get("removed").and_then(|r| r.as_u64()).unwrap_or(0),
                    }
                }
                _ => Response::Error {
                    message: "Could not delete (app locked or not running).".to_string(),
                },
            }
        }
        Request::Log { level, message } => {
            write_extension_log(&level, &message);
            Response::Pong
        }
        Request::ListMatchingLogins { url } => match query_desktop_app(&url) {
            Some(items) => Response::Logins {
                url,
                app_connected: true,
                items,
                note: None,
            },
            None => Response::Logins {
                url,
                app_connected: false,
                items: Vec::new(),
                note: Some("The Arca desktop app isn't running or is locked.".to_string()),
            },
        },
        Request::Fill { id, url } => match fill_credential(&id, &url) {
            Ok((username, password)) => Response::Credentials { username, password },
            // The reason verbatim, for the extension to act on. It renders the
            // wording; a host that pre-writes prose forces the UI to string-match
            // its own sentences to tell "locked" from "wrong site".
            Err(reason) => Response::Error { message: reason },
        },
        Request::PasskeyCreate {
            origin,
            rp_id,
            user_name,
            user_handle,
            exclude_credentials,
        } => match passkey_create(
            &origin,
            &rp_id,
            &user_name,
            &user_handle,
            &exclude_credentials,
        ) {
            Ok((credential_id, attestation_object)) => Response::PasskeyCredential {
                credential_id,
                attestation_object,
            },
            Err(message) => Response::Error { message },
        },
        Request::PasskeyGet {
            origin,
            rp_id,
            client_data_hash,
            allow_credentials,
            picked,
        } => match passkey_get(
            &origin,
            &rp_id,
            &client_data_hash,
            &allow_credentials,
            picked,
        ) {
            Ok((credential_id, authenticator_data, signature, user_handle)) => {
                Response::PasskeyAssertion {
                    credential_id,
                    authenticator_data,
                    signature,
                    user_handle,
                }
            }
            Err(message) => Response::Error { message },
        },
        Request::ImportBookmarks { items } => {
            match bridge_request(serde_json::json!({
                "type": "import_bookmarks", "items": items,
            })) {
                Some(v) if v.get("type").and_then(|t| t.as_str()) == Some("imported_bookmarks") => {
                    Response::ImportedBookmarks {
                        added: v.get("added").and_then(|a| a.as_u64()).unwrap_or(0),
                    }
                }
                _ => Response::Error {
                    message: "Could not import bookmarks (app locked or not running).".to_string(),
                },
            }
        }
        Request::ListBookmarks => {
            match bridge_request(serde_json::json!({ "type": "list_bookmarks" })) {
                Some(v) if v.get("type").and_then(|t| t.as_str()) == Some("bookmarks") => {
                    Response::Bookmarks {
                        items: v
                            .get("items")
                            .and_then(|i| i.as_array())
                            .cloned()
                            .unwrap_or_default(),
                    }
                }
                // The app ANSWERED, and what it said was not a bookmark list —
                // in practice "locked". A known state, and the caller may act
                // on it at once: bookmarks vanishing when the vault locks is
                // the entire point of the feature.
                Some(v) => Response::Error {
                    message: v
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("locked")
                        .to_string(),
                },
                // No answer at all. A quit app looks like this — and so does a
                // blip: a host that failed to spawn, a bridge file being
                // rewritten, a lost race at browser startup.
                //
                // These two used to share one message, "app locked or not
                // running", and the caller deleted the user's bookmark folder
                // on either. So a momentary miss destroyed the folder, which is
                // what "saving bookmarks doesn't work" actually was. Say which
                // one it is and let the caller decide.
                None => Response::Error {
                    message: "unreachable".to_string(),
                },
            }
        }
        Request::SaveProbe {
            url,
            username,
            password,
        } => match save_probe(&url, &username, &password) {
            Some((action, username)) => Response::SaveDecision { action, username },
            None => Response::Error {
                message: "Save probe failed (app locked or not running).".to_string(),
            },
        },
        Request::SaveLogin {
            url,
            username,
            password,
        } => {
            if save_login(&url, &username, &password) {
                Response::Saved
            } else {
                Response::Error {
                    message: "Could not save login (app locked or not running).".to_string(),
                }
            }
        }
        Request::Unlock => {
            if let Err(message) = launch::ensure_running(|| desktop_app_info().is_some()) {
                return Response::Error { message };
            }
            // Send once only: a lost response must never replay a user prompt.
            match bridge_request(serde_json::json!({ "type": "request_unlock" })) {
                Some(response) if response["type"] == "unlock_requested" => {
                    Response::UnlockRequested
                }
                Some(response) => Response::Error {
                    message: response["message"]
                        .as_str()
                        .unwrap_or("invalid_response")
                        .to_string(),
                },
                None => Response::Error {
                    message: "Could not reach Arca after startup. Try again.".to_string(),
                },
            }
        }
        Request::GeneratePassword { length, symbols } => match generate_password(length, symbols) {
            Some(password) => Response::GeneratedPassword { password },
            // Unlike the others this cannot mean "locked": the app generates
            // without an unlocked vault. If it failed, it is not running.
            None => Response::Error {
                message: "Could not generate a password (app not running).".to_string(),
            },
        },
    }
}

/// Ask the app for a generated password. This host does not link vault-core and
/// should not start: it is the piece a hostile web page reaches first, and the
/// less crypto lives behind that boundary the better. The app already owns the
/// generator.
fn generate_password(length: Option<usize>, symbols: Option<bool>) -> Option<String> {
    let resp = bridge_request(serde_json::json!({
        "type": "generate_password", "length": length, "symbols": symbols,
    }))?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("generated_password") {
        return None;
    }
    Some(resp.get("password")?.as_str()?.to_string())
}

/// Ask the app whether a submitted login is worth offering to save; returns the
/// decision string ("new"/"update"/"known"/"disabled"/"locked") and, for an
/// update, the stored username it would overwrite.
fn save_probe(url: &str, username: &str, password: &str) -> Option<(String, Option<String>)> {
    let resp = bridge_request(serde_json::json!({
        "type": "save_probe", "url": url, "username": username, "password": password,
    }))?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("save_decision") {
        return None;
    }
    let action = resp.get("action")?.as_str()?.to_string();
    let target = resp
        .get("username")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some((action, target))
}

/// Ask the app to store a captured login. Returns whether it was saved.
fn save_login(url: &str, username: &str, password: &str) -> bool {
    let Some(resp) = bridge_request(serde_json::json!({
        "type": "save_login", "url": url, "username": username, "password": password,
    })) else {
        return false;
    };
    resp.get("type").and_then(|v| v.as_str()) == Some("saved")
}

/// Decode a JSON array-of-bytes field into `Vec<u8>`.
fn json_bytes(v: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    v.get(key)?
        .as_array()?
        .iter()
        .map(|n| u8::try_from(n.as_u64()?).ok())
        .collect()
}

/// Ask the app to register a passkey. Returns (credential_id, attestation_object).
fn passkey_create(
    origin: &str,
    rp_id: &str,
    user_name: &str,
    user_handle: &[u8],
    exclude_credentials: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let request =
        passkey_create_payload(origin, rp_id, user_name, user_handle, exclude_credentials);
    let resp = bridge_request(request).ok_or_else(|| "not_running".to_string())?;
    decode_passkey_create(&resp)
}

fn passkey_create_payload(
    origin: &str,
    rp_id: &str,
    user_name: &str,
    user_handle: &[u8],
    exclude_credentials: &[Vec<u8>],
) -> serde_json::Value {
    serde_json::json!({
        "type": "passkey_create",
        "origin": origin,
        "rp_id": rp_id,
        "user_name": user_name,
        "user_handle": user_handle,
        "exclude_credentials": exclude_credentials,
    })
}

fn decode_passkey_create(resp: &serde_json::Value) -> Result<(Vec<u8>, Vec<u8>), String> {
    match resp.get("type").and_then(|v| v.as_str()) {
        Some("passkey_credential") => Ok((
            json_bytes(resp, "credential_id").ok_or_else(|| "invalid_response".to_string())?,
            json_bytes(resp, "attestation_object").ok_or_else(|| "invalid_response".to_string())?,
        )),
        // The shim must see `excluded` to raise InvalidStateError. Replacing it
        // with generic prose sent duplicate registrations into the OS picker.
        Some("error") => Err(resp
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("failed")
            .to_string()),
        _ => Err("invalid_response".to_string()),
    }
}

/// (credential_id, authenticator_data, signature, user_handle) from an assertion.
type AssertionParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Ask the app to assert a passkey.
fn passkey_get(
    origin: &str,
    rp_id: &str,
    client_data_hash: &[u8],
    allow_credentials: &[Vec<u8>],
    picked: bool,
) -> Result<AssertionParts, String> {
    let resp = bridge_request(serde_json::json!({
        "type": "passkey_get",
        "origin": origin,
        "rp_id": rp_id,
        "client_data_hash": client_data_hash,
        "allow_credentials": allow_credentials,
        "picked": picked,
    }))
    .ok_or_else(|| "not_running".to_string())?;
    if resp.get("type").and_then(|v| v.as_str()) != Some("passkey_assertion") {
        return Err(resp
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("failed")
            .to_string());
    }
    Ok((
        json_bytes(&resp, "credential_id").ok_or_else(|| "invalid_response".to_string())?,
        json_bytes(&resp, "authenticator_data").ok_or_else(|| "invalid_response".to_string())?,
        json_bytes(&resp, "signature").ok_or_else(|| "invalid_response".to_string())?,
        json_bytes(&resp, "user_handle").ok_or_else(|| "invalid_response".to_string())?,
    ))
}

/// Path to the bridge connection-info file the desktop app writes. Uses the
/// same per-user data dir Tauri's `app_data_dir()` resolves to.
///
/// NEVER RESOLVED UNDER TEST, and that is not tidiness — it is the fix for a
/// bug that tormented the user for days.
///
/// The tests below call `handle()` with real `PasskeyCreate`/`PasskeyGet`
/// requests for github.com. `handle` is production code: it reaches this
/// function, reads the REAL connection file, authenticates to the REAL running
/// desktop app, and the app does what it is supposed to do with a passkey
/// request — it raises a Touch ID prompt.
///
/// The old comment on those tests said "without a reachable, unlocked app these
/// resolve to an error". On a developer's own machine the app IS reachable and
/// unlocked, so instead every `cargo test` fired a genuine
/// "Arca is trying to create a NEW passkey for github.com" dialog at whoever
/// was sitting there. This crate is a workspace default-member and
/// `scripts/smoke-test.sh` runs `cargo test`, and the smoke test gates every
/// install — so every build, test and install did it again.
///
/// Four fixes went into the browser extension chasing those prompts. None of
/// them could have worked: the requests never went near a browser.
#[cfg(test)]
fn bridge_info_path() -> Option<std::path::PathBuf> {
    None
}

#[cfg(not(test))]
fn bridge_info_path() -> Option<std::path::PathBuf> {
    Some(dirs::data_dir()?.join(HOST_NAME).join("native-bridge.json"))
}

/// A fresh 128-bit challenge for the app to sign, hex-encoded.
///
/// From the OS CSPRNG, because a predictable nonce would let an impostor replay
/// a proof it had captured from an earlier, genuine handshake.
fn fresh_nonce() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// `HMAC-SHA256(token, nonce)`, hex. Must match `handshake_proof` in the app's
/// `bridge.rs` — the protocol-version guard keeps the two in step.
fn handshake_proof(token: &str, nonce: &str) -> String {
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(subtle::ConstantTimeEq::ct_eq(a, b))
}

/// Open an authenticated connection to the desktop app's loopback bridge and
/// send one request, returning the parsed JSON response.
fn bridge_request_with_info(
    payload: serde_json::Value,
) -> Option<(serde_json::Value, DesktopBuild)> {
    let info: serde_json::Value =
        serde_json::from_slice(&std::fs::read(bridge_info_path()?).ok()?).ok()?;
    let port = u16::try_from(info.get("port")?.as_u64()?).ok()?;
    let token = info.get("token")?.as_str()?;
    bridge_request_at(payload, port, token)
}

fn bridge_request_at(
    payload: serde_json::Value,
    port: u16,
    token: &str,
) -> Option<(serde_json::Value, DesktopBuild)> {
    // Invalid requests or incompatible replies must fail closed, never take
    // down the browser's long-lived native-messaging process.
    let probe = payload.get("type").and_then(|v| v.as_str()) == Some("match");
    let typed_req: bridge_schema::BridgeRequest = serde_json::from_value(payload).ok()?;
    let payload = serde_json::to_value(typed_req).ok()?;

    let stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(5),
    )
    .ok()?;
    // Long enough to outlast an in-app autofill-consent prompt (the app blocks
    // the reply until the user answers, up to ~30s) without hanging forever.
    stream
        .set_read_timeout(Some(Duration::from_secs(if probe { 2 } else { 90 })))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    let mut writer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);

    // Authenticate, declaring the protocol we speak and challenging the app to
    // prove it holds the same token. Authentication used to run one way: we
    // proved ourselves to whatever was on the port, and it proved nothing back.
    // Arca's port is released the moment it exits, so a process that grabbed it
    // could collect every submitted password (`save_probe`) and answer `fill`
    // with credentials of its choosing. Only the real app can compute the MAC.
    let nonce = fresh_nonce()?;

    let hello_req = bridge_schema::BridgeRequest::Hello {
        token: token.to_string(),
        protocol: Some(BRIDGE_PROTOCOL),
        nonce: Some(nonce.clone()),
    };
    writeln!(writer, "{}", serde_json::to_string(&hello_req).ok()?).ok()?;

    let hello = read_bridge_response(&mut reader)?;
    if hello.get("type").and_then(|v| v.as_str()) != Some("ok") {
        return None;
    }
    // Refuse an app that speaks a dialect we were not written against, rather
    // than sending it requests it may read differently than we meant them.
    let app_protocol = hello
        .get("protocol")
        .and_then(|v| v.as_u64())
        .unwrap_or(BRIDGE_PROTOCOL as u64);
    if app_protocol != BRIDGE_PROTOCOL as u64 {
        return None;
    }
    // The app's half of the handshake. Verified before a single byte of the
    // real request — which may carry a password — is written.
    let proof = hello.get("proof").and_then(|v| v.as_str())?;
    if !constant_time_eq(proof.as_bytes(), handshake_proof(token, &nonce).as_bytes()) {
        return None;
    }
    let app_version = DesktopBuild {
        version: hello
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        build: hello
            .get("build")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        commit: hello
            .get("commit")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        pid: hello
            .get("pid")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok()),
    };

    // Send the actual request and read its response.
    writeln!(writer, "{payload}").ok()?;

    let response = read_bridge_response(&mut reader)?;
    let _typed_resp: bridge_schema::BridgeResponse =
        serde_json::from_value(response.clone()).ok()?;

    Some((response, app_version))
}

/// Bound allocation even if an incompatible endpoint never sends a newline.
fn read_bridge_response(reader: &mut impl BufRead) -> Option<serde_json::Value> {
    let mut line = Vec::new();
    reader
        .take(u64::from(MAX_MESSAGE_BYTES) + 1)
        .read_until(b'\n', &mut line)
        .ok()?;
    if line.len() > MAX_MESSAGE_BYTES as usize || line.last() != Some(&b'\n') {
        return None;
    }
    serde_json::from_slice(&line).ok()
}

fn bridge_request(payload: serde_json::Value) -> Option<serde_json::Value> {
    bridge_request_with_info(payload).map(|(response, _)| response)
}

/// Whether the desktop app's bridge authenticates, plus its reported version.
struct DesktopBuild {
    version: Option<String>,
    build: Option<String>,
    commit: Option<String>,
    pid: Option<u32>,
}

fn desktop_app_info() -> Option<DesktopBuild> {
    bridge_request_with_info(serde_json::json!({ "type": "match", "url": "" }))
        .map(|(_, version)| version)
}

/// Ask the app for logins matching `url` (metadata only, no passwords).
fn query_desktop_app(url: &str) -> Option<Vec<LoginMatch>> {
    let resp = bridge_request(serde_json::json!({ "type": "match", "url": url }))?;
    decode_login_matches(resp, url)
}

fn decode_login_matches(resp: serde_json::Value, url: &str) -> Option<Vec<LoginMatch>> {
    let bridge_schema::BridgeResponse::Logins { items } = serde_json::from_value(resp).ok()? else {
        return None;
    };
    Some(
        items
            .into_iter()
            .map(|item| LoginMatch {
                id: item.id,
                credential_id: item.credential_id,
                title: item.title,
                username: item.username,
                url: url.to_string(),
                kind: item.kind,
            })
            .collect(),
    )
}

/// Ask the app for the credential of `id` to fill into `url`. The app enforces
/// unlock + origin matching before returning anything.
fn fill_credential(id: &str, url: &str) -> Result<(String, String), String> {
    let Some(resp) = bridge_request(serde_json::json!({ "type": "fill", "id": id, "url": url }))
    else {
        return Err("not_running".to_string());
    };
    if resp.get("type").and_then(|v| v.as_str()) != Some("credentials") {
        // Pass the app's REASON through. It already distinguishes "locked" from
        // "origin_mismatch" from "not_found"; flattening them into one sentence
        // listing all three meant the message never told anyone anything, and
        // the one that actually happens has a fix the extension can offer.
        return Err(resp
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("failed")
            .to_string());
    }
    let username = resp
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let password = resp
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Ok((username, password))
}

/// Read one framed message. Returns `Ok(None)` on clean EOF (browser closed
/// the pipe), which is the host's signal to exit.
fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<Request>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len == 0 {
        return Ok(None);
    }
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    let request = serde_json::from_slice::<Request>(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(request))
}

/// Write one framed message.
fn write_message<W: Write>(writer: &mut W, response: &Response) -> io::Result<()> {
    let payload =
        serde_json::to_vec(response).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response too large"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn main() {
    if std::env::args().any(|arg| arg == "--build-info") {
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"), "build": env!("ARCA_BUILD"),
                "commit": env!("ARCA_COMMIT"),
            })
        );
        return;
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        match read_message(&mut reader) {
            Ok(Some(request)) => {
                let response = handle(request);
                if write_message(&mut writer, &response).is_err() {
                    break;
                }
            }
            Ok(None) => break, // EOF: browser closed the connection.
            Err(_) => {
                // Malformed frame: report once and stop.
                let _ = write_message(
                    &mut writer,
                    &Response::Error {
                        message: "malformed message".to_string(),
                    },
                );
                break;
            }
        }
    }
}

/// Append one line to the extension's log.
///
/// Next to the vault, where every other file of ours already lives, and
/// written by the HOST rather than the app: the app may be locked or not
/// running at all, and the moments worth recording are exactly the ones where
/// something is not working.
///
/// Trimmed rather than rotated. This is a debugging aid, not an audit trail,
/// and a scheme to manage it would be more machinery than the thing itself.
fn write_extension_log(level: &str, message: &str) {
    use std::io::Write;
    let Some(dir) = dirs::data_dir().map(|d| d.join(HOST_NAME)) else {
        return;
    };
    let path = dir.join("extension.log");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Newlines would turn one entry into several and break line counting; a
    // stack trace arrives with plenty of them.
    let flat = message.replace('\n', " ⏎ ");
    let line = format!("{stamp}\t{level}\t{flat}\n");

    const MAX_LINES: usize = 400;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn login_metadata_keeps_the_selected_passkey_id() {
        let items = decode_login_matches(
            serde_json::json!({
                "type": "logins", "items": [
                    {"id": "password", "title": "Example", "username": "alice"},
                    {"id": "passkey", "title": "Example", "username": "bob",
                     "kind": "passkey", "credential_id": [1, 2, 255]}
                ]
            }),
            "https://example.test/login",
        )
        .unwrap();
        let browser = serde_json::to_value(items).unwrap();
        assert_eq!(browser[0]["kind"], "password");
        assert!(browser[0].get("credential_id").is_none());
        assert_eq!(browser[1]["credential_id"], serde_json::json!([1, 2, 255]));
        assert_eq!(browser[1]["url"], "https://example.test/login");
    }

    #[test]
    fn bridge_lines_reject_truncated_invalid_and_oversized_replies() {
        for bytes in [b"".as_slice(), b"{\"type\":\"saved\"}", b"not json\n"] {
            assert!(read_bridge_response(&mut Cursor::new(bytes)).is_none());
        }
        let oversized = vec![b' '; MAX_MESSAGE_BYTES as usize + 2];
        let mut reader = Cursor::new(oversized);
        assert!(read_bridge_response(&mut reader).is_none());
        assert_eq!(reader.position(), u64::from(MAX_MESSAGE_BYTES) + 1);
        assert_eq!(
            read_bridge_response(&mut Cursor::new(b"{\"type\":\"saved\"}\n")),
            Some(serde_json::json!({"type": "saved"}))
        );
    }

    /// A synthetic loopback server exercises the real authenticated transport;
    /// no tests ever discover or contact the user's running vault.
    fn synthetic_bridge(reply: &str, valid_proof: bool) -> Option<serde_json::Value> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let reply = reply.to_owned();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let hello = read_bridge_response(&mut reader).unwrap();
            assert_eq!(hello["token"], "synthetic-token");
            let proof = if valid_proof {
                handshake_proof("synthetic-token", hello["nonce"].as_str().unwrap())
            } else {
                "invalid-proof".into()
            };
            writeln!(
                socket,
                "{}",
                serde_json::json!({
                    "type": "ok", "protocol": BRIDGE_PROTOCOL, "proof": proof,
                    "version": VERSION, "build": "test", "commit": "test", "pid": 1
                })
            )
            .unwrap();
            let request = read_bridge_response(&mut reader);
            if valid_proof {
                assert_eq!(request.unwrap()["password"], "synthetic-secret");
                writeln!(socket, "{reply}").unwrap();
            } else {
                assert!(
                    request.is_none(),
                    "secret request sent before authentication"
                );
            }
        });
        let response = bridge_request_at(
            serde_json::json!({
                "type": "save_login", "url": "https://example.test", "username": "alice",
                "password": "synthetic-secret"
            }),
            port,
            "synthetic-token",
        );
        server.join().unwrap();
        response.map(|(response, _)| response)
    }

    #[test]
    fn authenticated_bridge_accepts_saved_and_rejects_incompatible_replies() {
        assert_eq!(
            synthetic_bridge(r#"{"type":"saved"}"#, true),
            Some(serde_json::json!({"type": "saved"}))
        );
        for reply in [
            r#"{"type":"unknown"}"#,
            r#"{"type":"logins","items":[{}]}"#,
            "invalid",
        ] {
            assert!(synthetic_bridge(reply, true).is_none());
        }
    }

    #[test]
    fn bridge_never_sends_secrets_to_an_unauthenticated_endpoint() {
        assert!(synthetic_bridge(r#"{"type":"saved"}"#, false).is_none());
    }

    #[test]
    fn malformed_bookmark_request_fails_without_panicking() {
        assert!(bridge_request_at(
            serde_json::json!({
                "type": "import_bookmarks", "items": [{"title": 42}]
            }),
            0,
            "synthetic-token"
        )
        .is_none());
    }

    /// Frame a JSON string the way a browser would, for round-trip tests.
    fn frame(json: &str) -> Vec<u8> {
        let bytes = json.as_bytes();
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    /// Shared handshake test vector.
    ///
    /// The app, the native host and the CLI each compute this MAC in their own
    /// crate, and a silent disagreement would break every bridge connection at
    /// once. The same three assertions live in `bridge.rs`, the native host and
    /// the CLI, so a change to one without the others fails here.
    #[test]
    fn handshake_proof_matches_the_shared_vector() {
        assert_eq!(
            handshake_proof("arca-test-token", "0123456789abcdef"),
            "e7b61fca20478c27d56236c0e24e1fc97e29d2a3ed757d7a61d0cee09b66c1fc"
        );
    }

    #[test]
    fn reads_a_framed_request() {
        let mut cur = Cursor::new(frame(r#"{"type":"hello","version":"1.0","protocol":1}"#));
        let req = read_message(&mut cur).unwrap().unwrap();
        assert!(matches!(req, Request::Hello { .. }));
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn hello_handshake_round_trips_through_the_wire() {
        // Frame a hello, read it, handle it, write the response, re-read length.
        let mut input = Cursor::new(frame(r#"{"type":"hello","protocol":1}"#));
        let req = read_message(&mut input).unwrap().unwrap();
        let resp = handle(req);

        let mut out = Vec::new();
        write_message(&mut out, &resp).unwrap();

        // Length prefix matches the JSON payload that follows.
        let len = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(len, out.len() - 4);
        let json: serde_json::Value = serde_json::from_slice(&out[4..]).unwrap();
        assert_eq!(json["type"], "hello");
        assert_eq!(json["name"], HOST_NAME);
        assert_eq!(json["protocol"], PROTOCOL_VERSION);
    }

    #[test]
    fn hello_refuses_an_incompatible_extension_protocol() {
        let response = handle(Request::Hello {
            version: Some(VERSION.to_string()),
            protocol: Some(PROTOCOL_VERSION + 1),
        });
        assert!(matches!(
            response,
            Response::Error { message } if message == "unsupported_protocol"
        ));
    }

    #[test]
    fn list_matching_logins_returns_a_logins_response() {
        // The connected/items result depends on whether the desktop app is
        // running locally, so assert only the response shape (dispatch), not
        // environment-dependent connectivity.
        let resp = handle(Request::ListMatchingLogins {
            url: "https://github.com/login".to_string(),
        });
        assert!(matches!(resp, Response::Logins { .. }));
    }

    #[test]
    fn passkey_create_preserves_exclusions_and_errors() {
        let mut input = Cursor::new(frame(
            r#"{"type":"passkey_create","origin":"https://example.test","rp_id":"example.test","user_handle":[7],"exclude_credentials":[[1,2],[3,4]]}"#,
        ));
        let Request::PasskeyCreate {
            origin,
            rp_id,
            user_name,
            user_handle,
            exclude_credentials,
        } = read_message(&mut input).unwrap().unwrap()
        else {
            panic!("wrong request")
        };
        let payload = passkey_create_payload(
            &origin,
            &rp_id,
            &user_name,
            &user_handle,
            &exclude_credentials,
        );
        assert_eq!(
            payload["exclude_credentials"],
            serde_json::json!([[1, 2], [3, 4]])
        );
        for reason in ["excluded", "locked", "denied", "origin_mismatch"] {
            let response = serde_json::json!({"type":"error", "message":reason});
            assert_eq!(decode_passkey_create(&response), Err(reason.to_string()));
        }
        assert_eq!(
            decode_passkey_create(
                &serde_json::json!({"type":"passkey_credential", "credential_id":[1], "attestation_object":[2]})
            ),
            Ok((vec![1], vec![2]))
        );
        assert_eq!(
            decode_passkey_create(
                &serde_json::json!({"type":"passkey_credential", "credential_id":[256], "attestation_object":[2]})
            ),
            Err("invalid_response".to_string())
        );
    }

    #[test]
    fn passkey_requests_are_dispatched() {
        // Without a reachable, unlocked app these resolve to an error; the point
        // is that both variants parse and route to a handler.
        let create = handle(Request::PasskeyCreate {
            origin: "https://github.com".to_string(),
            rp_id: "github.com".to_string(),
            user_name: "frank".to_string(),
            user_handle: vec![1, 2, 3],
            exclude_credentials: vec![],
        });
        assert!(matches!(
            create,
            Response::PasskeyCredential { .. } | Response::Error { .. }
        ));

        let get = handle(Request::PasskeyGet {
            origin: "https://github.com".to_string(),
            rp_id: "github.com".to_string(),
            client_data_hash: vec![0u8; 32],
            allow_credentials: vec![],

            picked: false,
        });
        assert!(matches!(
            get,
            Response::PasskeyAssertion { .. } | Response::Error { .. }
        ));
    }

    #[test]
    fn fill_request_is_dispatched() {
        // Without a reachable, unlocked app this resolves to an error; the point
        // is that Fill is parsed and routed.
        let resp = handle(Request::Fill {
            id: "00000000-0000-0000-0000-000000000000".to_string(),
            url: "https://github.com".to_string(),
        });
        assert!(matches!(
            resp,
            Response::Credentials { .. } | Response::Error { .. }
        ));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut bytes = (MAX_MESSAGE_BYTES + 1).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        let mut cur = Cursor::new(bytes);
        assert!(read_message(&mut cur).is_err());
    }
}
