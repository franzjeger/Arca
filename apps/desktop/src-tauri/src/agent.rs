//! ssh-agent protocol server.
//!
//! Arca acts as an ssh-agent so `ssh`/`git` can use the Ed25519 keys stored in
//! the vault WITHOUT the private key ever leaving the app: the agent advertises
//! the public identities and, on a sign request, hands the bytes to
//! `vault_core::ssh::sign`, which signs in-process and returns only the
//! signature. The private seed is read from the (unlocked) vault and dropped.
//!
//! Transport is platform-specific but the wire protocol is shared:
//!   * macOS/Linux — a Unix domain socket (`0600`, in the app data dir). Point
//!     `SSH_AUTH_SOCK` at it.
//!   * Windows — the named pipe `\\.\pipe\openssh-ssh-agent`, which the built-in
//!     Windows OpenSSH client uses automatically (no env var). The built-in
//!     `ssh-agent` service must be stopped so Arca can own that pipe.
//!
//! Security:
//!   * Signing requires the vault to be UNLOCKED. When locked, the agent lists
//!     zero identities and refuses to sign (like an ssh-agent with no keys
//!     added). "Unlocked" is the equivalent of `ssh-add`.
//!   * The Unix socket is user-only (`0600`); the Windows pipe's default DACL
//!     grants the creating user. Both are loopback-equivalent (not off-device).
//!   * Only REQUEST_IDENTITIES and SIGN_REQUEST are honored; adding/removing/
//!     locking external keys over the protocol is refused (keys are managed in
//!     Arca, not injected by clients).

use std::io::{Read, Write};
use std::sync::Mutex;

use tauri::{AppHandle, Manager};
use vault_core::{ssh, VaultItem};

use crate::state::AppState;

// Message numbers (draft-miller-ssh-agent).
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Cap on an incoming message (a sign payload is small; guards against a
/// malicious length prefix).
const MAX_MSG: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Transport-agnostic protocol (works over any Read + Write stream)
// ---------------------------------------------------------------------------

/// Serve one client connection until it closes.
fn serve<S: Read + Write>(app: &AppHandle, s: &mut S) -> std::io::Result<()> {
    loop {
        let msg = match read_msg(s) {
            Ok(m) => m,
            Err(_) => return Ok(()), // client closed
        };
        if msg.is_empty() {
            return Ok(());
        }
        let resp = match msg[0] {
            SSH_AGENTC_REQUEST_IDENTITIES => identities(app),
            SSH_AGENTC_SIGN_REQUEST => sign(app, &msg[1..]),
            _ => vec![SSH_AGENT_FAILURE],
        };
        write_msg(s, &resp)?;
    }
}

fn read_msg<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MSG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized agent message",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_msg<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Read an SSH `string` (u32 length + bytes) at `pos`, advancing it.
fn read_string(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let n = u32::from_be_bytes(buf.get(*pos..*pos + 4)?.try_into().ok()?) as usize;
    *pos += 4;
    let v = buf.get(*pos..*pos + n)?.to_vec();
    *pos += n;
    Some(v)
}

fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

/// (public_blob, comment) for every SSH key, when the vault is unlocked.
fn collect_identities(st: &AppState) -> Vec<(Vec<u8>, String)> {
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(summaries) = vault.list_items(false) {
        for s in summaries {
            let Ok(item) = vault.get_item(s.id) else {
                continue;
            };
            if let VaultItem::SshKey {
                public_key,
                comment,
                ..
            } = &item.data
            {
                if !public_key.is_empty() {
                    out.push((public_key.clone(), comment.clone()));
                }
            }
        }
    }
    out
}

/// The Ed25519 seed for the key whose public blob matches, if unlocked.
fn seed_for(st: &AppState, key_blob: &[u8]) -> Option<Vec<u8>> {
    let vault = st.vault.as_ref().filter(|v| v.is_unlocked())?;
    let summaries = vault.list_items(false).ok()?;
    for s in summaries {
        let Ok(item) = vault.get_item(s.id) else {
            continue;
        };
        if let VaultItem::SshKey {
            public_key,
            private_key,
            ..
        } = &item.data
        {
            if public_key == key_blob && !private_key.is_empty() {
                return Some(private_key.clone());
            }
        }
    }
    None
}

fn identities(app: &AppHandle) -> Vec<u8> {
    let state = app.state::<Mutex<AppState>>();
    let keys = match state.lock() {
        Ok(st) => collect_identities(&st),
        Err(_) => Vec::new(),
    };
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for (blob, comment) in keys {
        push_string(&mut out, &blob);
        push_string(&mut out, comment.as_bytes());
    }
    out
}

fn sign(app: &AppHandle, body: &[u8]) -> Vec<u8> {
    let mut pos = 0;
    let (Some(key_blob), Some(data)) = (read_string(body, &mut pos), read_string(body, &mut pos))
    else {
        return vec![SSH_AGENT_FAILURE];
    };
    // A trailing u32 of flags follows; ignored for Ed25519 (no rsa-sha2).

    let state = app.state::<Mutex<AppState>>();
    let seed = match state.lock() {
        Ok(st) => seed_for(&st, &key_blob),
        Err(_) => None,
    };
    let Some(seed) = seed else {
        // Unknown key or vault locked.
        return vec![SSH_AGENT_FAILURE];
    };
    match ssh::sign(&seed, &data) {
        Ok(sig) => {
            let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
            push_string(&mut out, &sig);
            out
        }
        Err(_) => vec![SSH_AGENT_FAILURE],
    }
}

// ---------------------------------------------------------------------------
// Platform transport
// ---------------------------------------------------------------------------

pub use transport::{socket_path, start};

#[cfg(unix)]
mod transport {
    use super::{serve, AppHandle};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use tauri::Manager;

    /// The agent socket path: `<app-data>/ssh-agent.sock`.
    pub fn socket_path(app: &AppHandle) -> PathBuf {
        let dir = app
            .path()
            .app_data_dir()
            .unwrap_or_else(|_| std::env::temp_dir());
        dir.join("ssh-agent.sock")
    }

    /// Bind the socket and serve in the background. Best-effort.
    pub fn start(app: AppHandle) {
        let path = socket_path(&app);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&path); // stale socket from a prior run
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ssh-agent: could not bind {}: {e}", path.display());
                return;
            }
        };
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut s) => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let _ = serve(&app, &mut s);
                        });
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

#[cfg(windows)]
mod transport {
    use super::{serve, AppHandle};
    use interprocess::local_socket::LocalSocketListener;
    use std::path::PathBuf;

    /// The named pipe the Windows OpenSSH client connects to by default.
    const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

    /// On Windows the "socket path" is the fixed OpenSSH pipe name (shown to the
    /// user; ssh/git use it automatically with no env var).
    pub fn socket_path(_app: &AppHandle) -> PathBuf {
        PathBuf::from(PIPE_NAME)
    }

    /// Bind the named pipe and serve. Best-effort: if the built-in Windows
    /// `ssh-agent` service already owns the pipe, the bind fails and the agent
    /// is unavailable until that service is stopped.
    pub fn start(app: AppHandle) {
        std::thread::spawn(move || {
            let listener = match LocalSocketListener::bind(PIPE_NAME) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "ssh-agent: could not bind {PIPE_NAME}: {e} \
                         (stop the built-in Windows ssh-agent service to free it)"
                    );
                    return;
                }
            };
            for conn in listener.incoming() {
                match conn {
                    Ok(mut s) => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let _ = serve(&app, &mut s);
                        });
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

#[cfg(not(any(unix, windows)))]
mod transport {
    use super::AppHandle;
    use std::path::PathBuf;

    pub fn socket_path(_app: &AppHandle) -> PathBuf {
        PathBuf::new()
    }
    pub fn start(_app: AppHandle) {}
}
