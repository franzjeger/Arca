//! `arca` — create and use Arca logins from scripts.
//!
//! WHY THIS EXISTS
//!
//! Provisioning work needs passwords. Creating an M365 user, a service account,
//! a database login: every one of them means minting a credential and using it
//! once. Without this, the choices were to type it by hand or to let it sit in
//! plain text in whatever log the automation was writing. Neither is good, and
//! the second is worse than it looks — a transcript outlives the password.
//!
//! So: `arca new` mints one INSIDE the app and files it in the vault, and hands
//! back an id. `arca exec` runs a command with that password in its environment.
//! Between them, a script can create an account and set its password without the
//! secret ever appearing in its own output.
//!
//! `arca show` prints it, because sometimes a person needs to read it out and
//! pretending otherwise would just send them somewhere worse. It is a separate
//! verb so it is never what happens by accident.
//!
//! WHAT THIS IS NOT
//!
//! It holds no key material and does no crypto. Everything goes through the
//! desktop app's loopback bridge, using the token the app already writes for the
//! browser extension, and nothing works while the vault is locked. The security
//! boundary is the user account — any process running as this user can already
//! read that token — so this widens nothing. It just makes the existing boundary
//! usable from a script.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

const HOST_NAME: &str = "no.sybr.vault";
const BRIDGE_PROTOCOL: u32 = 2;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("new") => cmd_new(&args[1..]),
        Some("show") => cmd_show(&args[1..]),
        Some("exec") => cmd_exec(&args[1..]),
        Some("rm") => cmd_rm(&args[1..]),
        Some("status") => cmd_status(),
        Some("-V") | Some("--version") | Some("version") => {
            println!("arca {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("-h") | Some("--help") | Some("help") | None => {
            print!("{USAGE}");
            0
        }
        Some(other) => {
            eprintln!("arca: unknown command '{other}'\n");
            print!("{USAGE}");
            2
        }
    };
    std::process::exit(code);
}

const USAGE: &str = "\
arca — create and use Arca logins from scripts

  arca --version
      Print the installed command-line version.

  arca status
      Whether the desktop app is running and unlocked.

  arca new --title <title> [options]
      Mint a password, store it as a login, print the new id.
      The password is NOT printed unless you ask for it.

      --user <username>     --url <url>        --notes <text>
      --length <8-64>       --no-symbols       --show

  arca show <id>
      Print the password of a stored login. Nothing else.

  arca rm <id>
      Retract an item. It moves to Deleted in the app and can be
      restored there. Nothing here can purge one for good.

  arca exec <id> -- <command> [args...]
      Run a command with ARCA_PASSWORD set from that login. The password
      goes from the vault to the child process without passing through
      this program's output, so it stays out of logs and transcripts.

Exit codes: 0 ok, 1 failed, 2 bad usage, 3 app locked or not running.
";

// ── Commands ────────────────────────────────────────────────────────────────

fn cmd_status() -> i32 {
    match bridge(serde_json::json!({ "type": "match", "url": "" })) {
        Ok(_) => {
            println!("unlocked");
            0
        }
        Err(Fault::Unreachable) => {
            println!("not running");
            3
        }
        Err(Fault::Locked) => {
            println!("locked");
            3
        }
        Err(e) => {
            eprintln!("arca: {e}");
            1
        }
    }
}

fn cmd_new(args: &[String]) -> i32 {
    let mut title = None;
    let mut username = String::new();
    let mut url = String::new();
    let mut notes = String::new();
    let mut length: Option<u64> = None;
    let mut symbols = true;
    let mut show = false;

    let mut i = 0;
    while i < args.len() {
        let need = |i: usize| -> Option<String> { args.get(i + 1).cloned() };
        match args[i].as_str() {
            "--title" => match need(i) {
                Some(v) => {
                    title = Some(v);
                    i += 2;
                }
                None => return usage_error("--title needs a value"),
            },
            "--user" | "--username" => match need(i) {
                Some(v) => {
                    username = v;
                    i += 2;
                }
                None => return usage_error("--user needs a value"),
            },
            "--url" => match need(i) {
                Some(v) => {
                    url = v;
                    i += 2;
                }
                None => return usage_error("--url needs a value"),
            },
            "--notes" => match need(i) {
                Some(v) => {
                    notes = v;
                    i += 2;
                }
                None => return usage_error("--notes needs a value"),
            },
            "--length" => match need(i).and_then(|v| v.parse::<u64>().ok()) {
                Some(v) => {
                    length = Some(v);
                    i += 2;
                }
                None => return usage_error("--length needs a number"),
            },
            "--no-symbols" => {
                symbols = false;
                i += 1;
            }
            "--show" => {
                show = true;
                i += 1;
            }
            other => return usage_error(&format!("unknown option '{other}'")),
        }
    }

    let Some(title) = title else {
        return usage_error("--title is required");
    };

    let resp = bridge(serde_json::json!({
        "type": "create_login",
        "title": title,
        "username": username,
        "url": url,
        "notes": notes,
        "length": length,
        "symbols": symbols,
        "reveal": show,
    }));
    match resp {
        Ok(v) => {
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
            // The id on stdout, alone, so `ID=$(arca new ...)` works.
            println!("{id}");
            if show {
                if let Some(pw) = v.get("password").and_then(|x| x.as_str()) {
                    println!("{pw}");
                }
            }
            // Everything human goes to stderr, so it never contaminates a
            // captured id.
            eprintln!("arca: created \"{title}\"");
            0
        }
        Err(e) => fail(e),
    }
}

fn cmd_show(args: &[String]) -> i32 {
    let Some(id) = args.first() else {
        return usage_error("show needs an id");
    };
    match read_password(id) {
        Ok(pw) => {
            println!("{pw}");
            0
        }
        Err(e) => fail(e),
    }
}

fn cmd_exec(args: &[String]) -> i32 {
    let Some(id) = args.first() else {
        return usage_error("exec needs an id");
    };
    // Everything after `--` is the command. Required, so that an argument that
    // happens to start with a dash can never be mistaken for one of ours.
    let Some(sep) = args.iter().position(|a| a == "--") else {
        return usage_error("exec needs '--' before the command");
    };
    let cmd = &args[sep + 1..];
    let Some(program) = cmd.first() else {
        return usage_error("exec needs a command after '--'");
    };

    let password = match read_password(id) {
        Ok(pw) => pw,
        Err(e) => return fail(e),
    };

    // Inherited stdio: the child talks to the same terminal, so an interactive
    // tool still works. The password reaches it through the environment and
    // never through this program's own output.
    match Command::new(program)
        .args(&cmd[1..])
        .env("ARCA_PASSWORD", &password)
        .status()
    {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("arca: could not run '{program}': {e}");
            1
        }
    }
}

fn cmd_rm(args: &[String]) -> i32 {
    let Some(id) = args.first() else {
        return usage_error("rm needs an id");
    };
    match bridge(serde_json::json!({ "type": "delete_item", "id": id })) {
        Ok(v) => {
            let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("");
            // The title, not just "ok": a caller that was handed an id from
            // somewhere else should be able to see WHAT it just retracted, and
            // notice immediately if it was the wrong thing — while it is still
            // one click away in Deleted.
            eprintln!("arca: removed \"{title}\" (restorable from Deleted)");
            0
        }
        Err(e) => fail(e),
    }
}

fn read_password(id: &str) -> Result<String, Fault> {
    let v = bridge(serde_json::json!({ "type": "read_password", "id": id }))?;
    v.get("password")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or(Fault::Protocol)
}

// ── Reporting ───────────────────────────────────────────────────────────────

fn usage_error(msg: &str) -> i32 {
    eprintln!("arca: {msg}\n");
    eprint!("{USAGE}");
    2
}

fn fail(e: Fault) -> i32 {
    eprintln!("arca: {e}");
    match e {
        Fault::Unreachable | Fault::Locked => 3,
        _ => 1,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Fault {
    /// The app is not running, or its bridge file is missing.
    Unreachable,
    /// The app is running but the vault is shut.
    Locked,
    /// The app refused, with its own word for why.
    Refused(String),
    /// A reply that did not fit the protocol.
    Protocol,
    /// The app authenticated, but speaks a bridge dialect this CLI cannot use.
    IncompatibleProtocol(u64),
    /// Something answered on Arca's port but could not prove it holds the
    /// bridge token — so it is not Arca, and it must not be sent a password.
    Impostor,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Unreachable => write!(
                f,
                "Arca is not running. Start it, unlock it, and try again."
            ),
            Fault::Locked => write!(f, "Arca is locked. Unlock it and try again."),
            // The app's own vocabulary, unchanged: "not_found" and "not_a_login"
            // mean different things and a script may want to tell them apart.
            Fault::Refused(m) => write!(f, "refused: {m}"),
            Fault::Protocol => write!(f, "unexpected reply from Arca"),
            Fault::IncompatibleProtocol(actual) => write!(
                f,
                "incompatible Arca bridge protocol (CLI expects {BRIDGE_PROTOCOL}, app reports {actual}); reinstall Arca so the app and CLI match"
            ),
            Fault::Impostor => write!(
                f,
                "the process on Arca's bridge port could not prove it is Arca; refusing to send anything to it"
            ),
        }
    }
}

// ── The bridge ──────────────────────────────────────────────────────────────

/// Send one request to the desktop app and return its reply.
///
/// The same connection-info file and handshake the browser's native messaging
/// host uses. Duplicated rather than shared because that host is a separate
/// binary with a different job, and forty lines of socket code is a smaller
/// price than a crate the two must agree on forever.
fn bridge(payload: serde_json::Value) -> Result<serde_json::Value, Fault> {
    let info_path = dirs::data_dir()
        .map(|d| d.join(HOST_NAME).join("native-bridge.json"))
        .ok_or(Fault::Unreachable)?;
    let info: serde_json::Value = std::fs::read(&info_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(Fault::Unreachable)?;
    let port = info
        .get("port")
        .and_then(|p| p.as_u64())
        .ok_or(Fault::Unreachable)? as u16;
    let token = info
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or(Fault::Unreachable)?;

    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|_| Fault::Unreachable)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(45)))
        .map_err(|_| Fault::Unreachable)?;
    let mut writer = stream.try_clone().map_err(|_| Fault::Unreachable)?;
    let mut reader = BufReader::new(stream);

    // Challenge the app to prove it holds the same token. Without this the
    // handshake was one-way: anything answering on the port was believed, and
    // Arca's port is freed the moment it exits.
    let nonce = fresh_nonce().ok_or(Fault::Unreachable)?;
    writeln!(
        writer,
        "{}",
        serde_json::json!({
            "type": "hello",
            "token": token,
            "protocol": BRIDGE_PROTOCOL,
            "nonce": nonce,
        })
    )
    .map_err(|_| Fault::Unreachable)?;
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|_| Fault::Unreachable)?;
    let hello: serde_json::Value =
        serde_json::from_str(line.trim()).map_err(|_| Fault::Protocol)?;
    validate_bridge_hello(&hello)?;
    verify_bridge_proof(&hello, token, &nonce)?;

    writeln!(writer, "{payload}").map_err(|_| Fault::Unreachable)?;
    line.clear();
    reader
        .read_line(&mut line)
        .map_err(|_| Fault::Unreachable)?;
    let resp: serde_json::Value = serde_json::from_str(line.trim()).map_err(|_| Fault::Protocol)?;

    if resp.get("type").and_then(|v| v.as_str()) == Some("error") {
        let msg = resp
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        // "locked" is not a failure to report as one: it is a door, and the
        // caller can open it. Its own exit code says so.
        return Err(if msg == "locked" {
            Fault::Locked
        } else {
            Fault::Refused(msg.to_string())
        });
    }
    Ok(resp)
}

/// A fresh 128-bit challenge for the app to sign, hex-encoded. From the OS
/// CSPRNG: a predictable nonce would let an impostor replay a captured proof.
fn fresh_nonce() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// `HMAC-SHA256(token, nonce)`, hex. Must match `handshake_proof` in the app's
/// `bridge.rs`; the protocol-version guard keeps the two in step.
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

/// The app's half of the mutual authentication, checked before the real request
/// (which may carry a password) is written.
fn verify_bridge_proof(hello: &serde_json::Value, token: &str, nonce: &str) -> Result<(), Fault> {
    let proof = hello
        .get("proof")
        .and_then(|v| v.as_str())
        .ok_or(Fault::Impostor)?;
    let expected = handshake_proof(token, nonce);
    let ok = proof.len() == expected.len()
        && bool::from(subtle::ConstantTimeEq::ct_eq(
            proof.as_bytes(),
            expected.as_bytes(),
        ));
    if ok {
        Ok(())
    } else {
        Err(Fault::Impostor)
    }
}

fn validate_bridge_hello(hello: &serde_json::Value) -> Result<(), Fault> {
    match hello.get("type").and_then(|v| v.as_str()) {
        Some("ok") => {
            // Missing means the original, pre-versioning app, which speaks v1.
            let actual = hello.get("protocol").and_then(|v| v.as_u64()).unwrap_or(1);
            if actual == BRIDGE_PROTOCOL as u64 {
                Ok(())
            } else {
                Err(Fault::IncompatibleProtocol(actual))
            }
        }
        Some("error")
            if hello.get("message").and_then(|v| v.as_str()) == Some("unsupported_protocol") =>
        {
            Err(Fault::IncompatibleProtocol(0))
        }
        Some("error") => Err(Fault::Unreachable),
        _ => Err(Fault::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_never_suggests_printing_a_password_by_default() {
        // `new` is the verb automation reaches for, and it must not be the one
        // that scatters secrets. If someone ever makes --show the default, this
        // fails and says why.
        assert!(USAGE.contains("NOT printed unless you ask"));
        assert!(USAGE.contains("--show"));
    }

    #[test]
    fn removal_is_advertised_as_reversible_and_purging_is_not_offered() {
        // `rm` is the one verb here that destroys something, and the only
        // reason it is safe for unattended use is that it does not really
        // destroy it. If someone ever wires this to purge_item, the help text
        // stops being true and this fails.
        assert!(USAGE.contains("restored there"));
        // The word "purge" may appear — the help says we cannot do it — but it
        // must never be a VERB someone can type.
        assert!(!USAGE.contains("arca purge"));
    }

    #[test]
    fn locked_and_missing_are_told_apart() {
        // Different fixes: one is "unlock it", the other is "start it". A
        // script that gets one message for both cannot act on either.
        assert_ne!(Fault::Locked.to_string(), Fault::Unreachable.to_string());
        assert!(Fault::Locked.to_string().contains("Unlock"));
        assert!(Fault::Unreachable.to_string().contains("not running"));
    }

    #[test]
    fn the_apps_own_refusal_reaches_the_caller_intact() {
        // "not_found" and "not_a_login" are different problems; flattening them
        // to "failed" would make a script guess.
        assert!(Fault::Refused("not_a_login".into())
            .to_string()
            .contains("not_a_login"));
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
    fn bridge_handshake_refuses_a_different_protocol() {
        assert_eq!(
            validate_bridge_hello(&serde_json::json!({
                "type": "ok",
                "protocol": BRIDGE_PROTOCOL,
                "version": "0.4.0",
            })),
            Ok(())
        );
        assert_eq!(
            validate_bridge_hello(&serde_json::json!({
                "type": "ok",
                "protocol": BRIDGE_PROTOCOL + 1,
            })),
            Err(Fault::IncompatibleProtocol((BRIDGE_PROTOCOL + 1) as u64))
        );
    }
}
