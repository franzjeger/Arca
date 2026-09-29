//! What crosses the socket: newline-delimited JSON, one message per line,
//! tagged by `type`. The app reads [`Request`]s and writes [`Response`]s; a
//! client does the reverse. One definition, so the two sides cannot drift.

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// The first message on a connection. See [`crate::auth`].
    Hello {
        /// Protocols 1 and 2 sent the token itself. Protocol 3 never does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        /// Protocol the client speaks. Absent means a client written before
        /// versioning existed, which by definition speaks version 1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<u32>,
        /// Client-chosen random challenge, which the app's proof covers.
        /// Required from protocol 3; absent from v1 clients.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
    /// Protocol 3: the client's proof over both nonces, answering `Challenge`.
    Auth {
        proof: String,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Handshake accepted. Carries the protocol so a client that is not our own
    /// native host can check what it is talking to before relying on it. Still
    /// serialises with `"type":"ok"`, so clients that only test the tag — the
    /// native host does exactly that — are unaffected.
    Ok {
        protocol: u32,
        version: String,
        build: String,
        commit: String,
        pid: u32,
        /// Protocol 2's proof, `HMAC-SHA256(token, nonce)`, for a v2 client
        /// that sent a nonce. Protocol 3 proves the app in `Challenge`.
        #[serde(skip_serializing_if = "Option::is_none")]
        proof: Option<String>,
    },
    /// Protocol 3: the app's nonce and its proof over both nonces.
    Challenge {
        nonce: String,
        proof: String,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginMatch {
    pub id: String,
    /// The passkey's credential id, so the picker's choice reaches the
    /// ceremony as an `allowCredentials` entry. Empty for passwords.
    ///
    /// Not a secret — it is what the browser sends the relying party anyway.
    /// Without it, picking one of two passkeys for the same site would sign
    /// with whichever the app found first, and the choice would be theatre.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub credential_id: Vec<u8>,
    pub title: String,
    pub username: String,
    /// Credential type for the picker UI: "password" for a stored login,
    /// "passkey" for a WebAuthn credential. A passkey row is informational (it
    /// signs in via the site's own passkey ceremony, not by filling a field).
    #[serde(default = "password_kind")]
    pub kind: String,
}

fn password_kind() -> String {
    "password".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clients and apps already installed read and write exactly these
    /// shapes; a renamed field or tag breaks them silently.
    #[test]
    fn the_wire_format_does_not_move() {
        let requests = [
            (
                Request::Hello {
                    token: None,
                    protocol: Some(3),
                    nonce: Some("c".into()),
                },
                r#"{"type":"hello","protocol":3,"nonce":"c"}"#,
            ),
            (
                Request::Auth { proof: "p".into() },
                r#"{"type":"auth","proof":"p"}"#,
            ),
            (Request::Unlock, r#"{"type":"request_unlock"}"#),
            (
                Request::Match { url: "u".into() },
                r#"{"type":"match","url":"u"}"#,
            ),
            (
                Request::GeneratePassword {
                    length: None,
                    symbols: None,
                },
                r#"{"type":"generate_password"}"#,
            ),
        ];
        for (request, wire) in requests {
            assert_eq!(serde_json::to_string(&request).unwrap(), wire);
            assert_eq!(serde_json::from_str::<Request>(wire).unwrap(), request);
        }

        let responses = [
            (
                Response::Challenge {
                    nonce: "a".into(),
                    proof: "p".into(),
                },
                r#"{"type":"challenge","nonce":"a","proof":"p"}"#,
            ),
            (
                Response::Logins {
                    items: vec![LoginMatch {
                        id: "i".into(),
                        credential_id: vec![],
                        title: "t".into(),
                        username: "u".into(),
                        kind: "password".into(),
                    }],
                },
                r#"{"type":"logins","items":[{"id":"i","title":"t","username":"u","kind":"password"}]}"#,
            ),
            (Response::UnlockRequested, r#"{"type":"unlock_requested"}"#),
        ];
        for (response, wire) in responses {
            assert_eq!(serde_json::to_string(&response).unwrap(), wire);
            assert_eq!(serde_json::from_str::<Response>(wire).unwrap(), response);
        }
    }

    #[test]
    fn a_protocol_2_hello_still_parses() {
        let hello: Request =
            serde_json::from_str(r#"{"type":"hello","token":"t","protocol":2,"nonce":"n"}"#)
                .unwrap();
        assert!(matches!(hello, Request::Hello { token: Some(t), .. } if t == "t"));
    }

    #[test]
    fn a_login_without_a_kind_is_a_password() {
        let response: Response = serde_json::from_str(
            r#"{"type":"logins","items":[{"id":"i","title":"t","username":"u"}]}"#,
        )
        .unwrap();
        let Response::Logins { items } = response else {
            panic!("expected logins");
        };
        assert_eq!(items[0].kind, "password");
        assert!(serde_json::from_str::<Response>(
            r#"{"type":"logins","items":[{"id":"i","title":"t"}]}"#
        )
        .is_err());
    }
}
