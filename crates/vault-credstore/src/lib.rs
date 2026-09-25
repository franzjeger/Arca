//! Publish Arca's logins and passkeys to the OS AutoFill store (macOS).
//!
//! macOS only offers a credential provider for sites it has been told that
//! provider holds something for. Until this crate, the only thing that ever
//! told it was a button in a separate development harness — so a user's system
//! AutoFill was as current as the last time they remembered to press it, and
//! the app they actually run published nothing at all.
//!
//! METADATA ONLY: a domain, a username, a record id, and for passkeys the
//! credential id and user handle the relying party already knows. No password
//! and no private key crosses this boundary. That is why it is safe to publish
//! and to leave published while the vault is locked — the AutoFill extension
//! fetches the secret itself, one per fill, behind its own biometric.
//!
//! The Objective-C shim is in `src/credstore.m`, about a hundred readable
//! lines. It lives in its own crate so the app crates keep
//! `#![forbid(unsafe_code)]`.

#![cfg_attr(not(target_os = "macos"), allow(unused))]

use std::fmt;

/// One entry to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// A stored login. `domain` is the host the system matches on.
    Password {
        domain: String,
        user: String,
        record: String,
    },
    /// A stored passkey. Binary fields are raw bytes; the shim takes base64.
    Passkey {
        rp_id: String,
        user: String,
        credential_id: Vec<u8>,
        user_handle: Vec<u8>,
        record: String,
    },
}

/// What the store did with a publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    /// Accepted.
    Ok,
    /// AutoFill is switched off for Arca in System Settings. The store accepts
    /// a replace call in that state and silently discards it, so this is
    /// reported rather than treated as success — the app can then say which
    /// switch to turn on instead of looking broken.
    AutoFillDisabled,
    /// The store refused. Details are in the system log.
    Failed,
}

impl fmt::Display for Published {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Published::Ok => write!(f, "published"),
            Published::AutoFillDisabled => write!(f, "AutoFill is off for Arca"),
            Published::Failed => write!(f, "the system refused the identities"),
        }
    }
}

/// Base64, standard alphabet with padding — what `NSData` expects.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// JSON-escape a string. Small and local rather than a dependency: the only
/// values here are hosts, usernames and uuids.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The wire form the shim parses. Public for the test below and for anyone
/// debugging what actually reached the OS.
pub fn to_json(identities: &[Identity]) -> String {
    let rows: Vec<String> = identities
        .iter()
        .map(|id| match id {
            Identity::Password {
                domain,
                user,
                record,
            } => format!(
                r#"{{"kind":"password","domain":"{}","user":"{}","record":"{}"}}"#,
                escape(domain),
                escape(user),
                escape(record)
            ),
            Identity::Passkey {
                rp_id,
                user,
                credential_id,
                user_handle,
                record,
            } => format!(
                r#"{{"kind":"passkey","rp":"{}","user":"{}","credential_id":"{}","user_handle":"{}","record":"{}"}}"#,
                escape(rp_id),
                escape(user),
                base64(credential_id),
                base64(user_handle),
                escape(record)
            ),
        })
        .collect();
    format!("[{}]", rows.join(","))
}

/// Replace everything Arca has published with `identities`.
///
/// BLOCKS on the system store; call it off any UI thread.
#[cfg(target_os = "macos")]
pub fn replace(identities: &[Identity]) -> Published {
    use std::ffi::CString;
    use std::os::raw::c_char;

    extern "C" {
        fn arca_credstore_replace(json: *const c_char) -> i32;
    }

    let Ok(json) = CString::new(to_json(identities)) else {
        return Published::Failed;
    };
    // SAFETY: `json` is a valid NUL-terminated C string that outlives the call.
    // The callee only reads it, and returns one of three documented ints.
    match unsafe { arca_credstore_replace(json.as_ptr()) } {
        1 => Published::Ok,
        0 => Published::AutoFillDisabled,
        _ => Published::Failed,
    }
}

/// Drop everything Arca has published.
#[cfg(target_os = "macos")]
pub fn clear() -> Published {
    extern "C" {
        fn arca_credstore_clear() -> i32;
    }
    // SAFETY: no arguments, no borrowed state; returns 0 or 1.
    if unsafe { arca_credstore_clear() } == 1 {
        Published::Ok
    } else {
        Published::Failed
    }
}

/// No system AutoFill store outside macOS; the browser extension is the path
/// there, and it needs no registration.
#[cfg(not(target_os = "macos"))]
pub fn replace(_identities: &[Identity]) -> Published {
    Published::Ok
}

#[cfg(not(target_os = "macos"))]
pub fn clear() -> Published {
    Published::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        // NSData parses standard base64 with padding; getting the tail wrong
        // yields a credential id the relying party will not recognise, which
        // surfaces as "that passkey does not exist" rather than as a bug here.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    fn json_survives_the_characters_real_vaults_contain() {
        // Titles and usernames are user text. An unescaped quote would make the
        // whole document unparseable, and the shim would publish NOTHING —
        // every suggestion silently gone because one entry had a quote in it.
        let json = to_json(&[Identity::Password {
            domain: "exa\"mple.com".into(),
            user: "a\\b\nc".into(),
            record: "id-1".into(),
        }]);
        assert!(json.contains(r#""domain":"exa\"mple.com""#), "{json}");
        assert!(json.contains(r#""user":"a\\b\nc""#), "{json}");
    }

    #[test]
    fn passkeys_carry_their_binary_fields_as_base64() {
        let json = to_json(&[Identity::Passkey {
            rp_id: "github.com".into(),
            user: "frank".into(),
            credential_id: vec![0xf0, 0x9f],
            user_handle: vec![],
            record: "id-2".into(),
        }]);
        assert!(json.contains(r#""credential_id":"8J8=""#), "{json}");
        assert!(json.contains(r#""user_handle":"""#), "{json}");
    }
}
