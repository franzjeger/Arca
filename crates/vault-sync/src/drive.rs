//! Google Drive's hidden `appDataFolder` as a [`RemoteStore`].
//!
//! The scope is `drive.appdata`: Arca can see the private folder Drive keeps
//! for it and nothing else in the user's account. Combined with the vault
//! already being sealed before it gets here, Google holds one opaque blob it
//! cannot read and cannot browse past.
//!
//! Google is not special to this crate — it is one implementation of one
//! trait. A second backend (iCloud, WebDAV, a self-hosted bucket) is a file
//! next to this one, and the engine does not change.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use crate::oauth::{AppCredentials, OAuthClient};
use crate::{CycleError, RemoteFile, RemoteStore};

/// The OAuth client, per platform. Both live in the same Google Cloud project
/// and ask for the same scope, so every Arca client reaches the same
/// `appDataFolder` and syncs with the others.
///
/// Two clients rather than one because Google ties the redirect to the client
/// TYPE. The desktop client redirects to a loopback address, which iOS cannot
/// bind and cannot register a custom scheme against; an iOS client redirects to
/// its own reversed client id. Reusing the desktop client from the phone is
/// what produces `400 redirect_uri_mismatch`.
///
/// See [`AppCredentials`] on why an installed-app secret is not a secret.
#[cfg(not(target_os = "ios"))]
pub const CLIENT_ID: &str =
    "269591410733-ger46m91l3ne5qmcrivhg1jo698gieck.apps.googleusercontent.com";

/// Supplied at build time by `build.rs`, from the environment or from
/// `~/.arca/google-client-secret` — deliberately not a literal here, because
/// this repository is public and a credential in public git history can only
/// be rotated, never withdrawn.
///
/// Empty means this build simply has no Google credentials. That is a state,
/// not a bug: [`sync_configured`] reports it and the sign-in refuses up front.
#[cfg(not(target_os = "ios"))]
pub const CLIENT_SECRET: &str = match option_env!("ARCA_GOOGLE_CLIENT_SECRET") {
    Some(secret) => secret,
    None => "",
};

/// The iOS client's identifier, written once.
///
/// Google renders the same registration two ways, and iOS needs both: the plain
/// form as `client_id`, and the *reversed* form as the URL scheme it redirects
/// to. Spelling the number out twice is how they drift, and a redirect that
/// disagrees with the client by one character fails as `redirect_uri_mismatch`
/// on the consent page with nothing to point at. It has to match
/// `CFBundleURLSchemes` in the iOS app's Info.plist and `SyncSignIn.redirectURI`
/// as well; those two cannot be reached from Rust, but two copies is better
/// than four.
#[cfg(target_os = "ios")]
macro_rules! ios_client {
    () => {
        "269591410733-ltlkje5t7p8gajnp8vvk3gp9223nheu7"
    };
}

/// iOS client (bundle id `no.sybr.vault.ios`). Public: Google issues NO secret
/// for this type, and sending an empty one is rejected — see `form_fields`.
#[cfg(target_os = "ios")]
pub const CLIENT_ID: &str = concat!(ios_client!(), ".apps.googleusercontent.com");
#[cfg(target_os = "ios")]
pub const CLIENT_SECRET: &str = "";

/// The redirect this build's client is registered for. iOS uses the reversed
/// client id, which is the only form Google accepts for an iOS client; the
/// desktop catches a loopback address chosen at runtime, so it has none here.
#[cfg(target_os = "ios")]
pub const REDIRECT_URI: &str = concat!(
    "com.googleusercontent.apps.",
    ios_client!(),
    ":/oauth2redirect"
);

/// Whether this build's client type needs a secret at all.
///
/// An iOS client is a *public* client: Google issues none, and rejects a
/// request that sends an empty one. So "has no secret" means two opposite
/// things on the two platforms, and asking the question needs this flag.
#[cfg(not(target_os = "ios"))]
const SECRET_REQUIRED: bool = true;
#[cfg(target_os = "ios")]
const SECRET_REQUIRED: bool = false;

/// Whether this build carries the credentials it needs to reach Google.
///
/// False for a build made without the client secret in place — CI's, and
/// anyone's who clones the repository. Callers check it *before* starting a
/// sign-in, so the user gets a sentence rather than being walked to a Google
/// consent page that ends in an opaque 401 from the token endpoint.
///
/// Only the sign-in needs the guard. Everything else on this path — the
/// background refresh, every Drive call — runs only when a refresh token is
/// already stored, and the only way to store one is a sign-in that got past
/// here. An iOS build cannot be unconfigured at all: its client needs no
/// secret and its id is a literal.
pub fn sync_configured() -> bool {
    !CLIENT_ID.is_empty() && (!SECRET_REQUIRED || !CLIENT_SECRET.is_empty())
}

/// What to tell the user when it is not.
pub const UNCONFIGURED: &str =
    "This build has no Google credentials, so Drive sync is unavailable. See docs/SYNC.md.";

/// Arca's own hidden folder, and nothing else in the user's Drive.
pub const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";

/// The vault's name inside `appDataFolder`. Every client must agree on it —
/// two names is two vaults that never see each other.
pub const REMOTE_NAME: &str = "arca.vault";

pub fn arca_credentials() -> AppCredentials {
    AppCredentials {
        client_id: CLIENT_ID.into(),
        client_secret: CLIENT_SECRET.into(),
        scope: SCOPE.into(),
    }
}

/// Where the long-lived refresh token lives, which is entirely a platform
/// question: the OS secret store on desktop, the app's keychain on iOS.
///
/// Presence and content are separate operations on purpose. On macOS, reading
/// a keychain item's *data* runs its ACL and can put a prompt on screen (after
/// a code-signature change, for instance); a presence check does not. The
/// background loop asks [`exists`](RefreshTokenStore::exists) every tick, so
/// that call must never be able to interrupt the user.
pub trait RefreshTokenStore: Send + Sync {
    fn exists(&self) -> bool;
    fn read(&self) -> Result<Option<Zeroizing<String>>, String>;
}

pub struct DriveStore {
    oauth: OAuthClient,
    tokens: Arc<dyn RefreshTokenStore>,
    http: reqwest::blocking::Client,
    /// The short-lived access token and the wall clock at which we stop
    /// trusting it. In memory only — it is never written anywhere.
    access: Mutex<Option<(Zeroizing<String>, SystemTime)>>,
}

impl DriveStore {
    pub fn new(credentials: AppCredentials, tokens: Arc<dyn RefreshTokenStore>) -> Self {
        Self {
            oauth: OAuthClient::new(credentials),
            tokens,
            http: crate::http::client(),
            access: Mutex::new(None),
        }
    }

    /// Seed the cache with the access token a fresh sign-in just produced, so
    /// the first cycle after connecting does not immediately spend a refresh.
    pub fn cache_access_token(&self, token: Zeroizing<String>, expires_in: u64) {
        if let Ok(mut cached) = self.access.lock() {
            *cached = Some((token, expiry_from(expires_in)));
        }
    }

    /// The signed-in account's email, for the UI to show.
    pub fn account_email(&self) -> Option<String> {
        account_email(&self.access_token().ok()?)
    }

    /// A usable access token, refreshing through the stored refresh token when
    /// the cached one has expired.
    fn access_token(&self) -> Result<Zeroizing<String>, CycleError> {
        {
            let cached = self
                .access
                .lock()
                .map_err(|_| CycleError::Other("token cache poisoned".into()))?;
            if let Some((token, until)) = &*cached {
                if SystemTime::now() < *until {
                    return Ok(token.clone());
                }
            }
        }
        let refresh = self
            .tokens
            .read()
            .map_err(CycleError::Other)?
            .ok_or_else(|| CycleError::Other("not connected".into()))?;
        let (token, expires_in) = self.oauth.refresh(&refresh).map_err(CycleError::Other)?;
        self.cache_access_token(token.clone(), expires_in);
        Ok(token)
    }
}

/// The email address of the account an access token belongs to, for the UI to
/// show. `about.get` is one of the few endpoints the `appdata` scope reaches.
///
/// Free-standing rather than a method, because the caller who most needs it has
/// just finished a sign-in and holds an access token but has not yet built a
/// [`DriveStore`] — the refresh token is still on its way to the platform's
/// keychain. `None` on any failure: a missing label is a cosmetic problem and
/// must never be the reason a completed sign-in is reported as failed.
pub fn account_email(access_token: &str) -> Option<String> {
    let about: serde_json::Value = crate::http::client()
        .get("https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)")
        .bearer_auth(access_token)
        .send()
        .and_then(|r| r.json())
        .ok()?;
    about["user"]["emailAddress"].as_str().map(str::to_string)
}

/// Stop trusting a token a minute before the server does, so a request cannot
/// be issued with a token that expires while it is in flight.
fn expiry_from(expires_in: u64) -> SystemTime {
    SystemTime::now() + Duration::from_secs(expires_in.saturating_sub(60))
}

/// Map a Drive HTTP status onto the retry policy. Only 401 is worth refreshing
/// a credential for; everything else is reported and retried on the next tick.
fn classify(status: reqwest::StatusCode, what: &str) -> CycleError {
    if status.as_u16() == 401 {
        CycleError::Auth
    } else if status.as_u16() == 404 {
        // A peer may retire an immutable input after our listing. Re-list.
        CycleError::Conflict
    } else {
        CycleError::Other(format!("{what} HTTP {status}"))
    }
}

fn field(value: &serde_json::Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

/// A malformed response is an error, never permission to create a new vault.
fn list_page(body: &serde_json::Value) -> Result<(Vec<RemoteFile>, Option<String>), CycleError> {
    let invalid = || CycleError::Other("drive list is missing file metadata".into());
    let rows = body["files"].as_array().ok_or_else(invalid)?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(invalid)?;
        let checksum = row["md5Checksum"]
            .as_str()
            .filter(|sum| !sum.is_empty())
            .ok_or_else(invalid)?;
        files.push(RemoteFile {
            id: id.into(),
            checksum: checksum.into(),
        });
    }
    let next = match body.get("nextPageToken") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|token| !token.is_empty())
                .ok_or_else(invalid)?
                .into(),
        ),
    };
    Ok((files, next))
}

impl RemoteStore for DriveStore {
    fn is_connected(&self) -> bool {
        self.tokens.exists()
    }

    fn list(&self) -> Result<Vec<RemoteFile>, CycleError> {
        let token = self.access_token()?;
        let mut files = Vec::new();
        let mut page_token = None;
        let mut seen = std::collections::HashSet::new();
        loop {
            let mut request = self
                .http
                .get("https://www.googleapis.com/drive/v3/files")
                .query(&[
                    ("spaces", "appDataFolder"),
                    ("q", &format!("name='{REMOTE_NAME}' and trashed=false")),
                    ("orderBy", "createdTime"),
                    ("fields", "nextPageToken,files(id,md5Checksum)"),
                    ("pageSize", "1000"),
                ])
                .bearer_auth(&*token);
            if let Some(page) = &page_token {
                request = request.query(&[("pageToken", page)]);
            }
            let resp = request
                .send()
                .map_err(|e| CycleError::Other(format!("drive list failed: {e}")))?;
            if !resp.status().is_success() {
                return Err(classify(resp.status(), "drive list"));
            }
            let body: serde_json::Value = resp
                .json()
                .map_err(|e| CycleError::Other(format!("drive list unreadable: {e}")))?;
            let (page, next) = list_page(&body)?;
            files.extend(page);
            match next {
                None => return Ok(files),
                Some(next) if seen.insert(next.clone()) => page_token = Some(next),
                Some(_) => return Err(CycleError::Other("drive list repeated a page".into())),
            }
        }
    }

    fn download(&self, id: &str) -> Result<Vec<u8>, CycleError> {
        let token = self.access_token()?;
        let resp = self
            .http
            .get(format!(
                "https://www.googleapis.com/drive/v3/files/{id}?alt=media"
            ))
            .bearer_auth(&*token)
            .send()
            .map_err(|e| CycleError::Other(format!("download failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(classify(resp.status(), "download"));
        }
        if resp
            .content_length()
            .is_some_and(|len| len > vault_core::MAX_VAULT_BYTES as u64)
        {
            return Err(CycleError::Other("downloaded vault is too large".into()));
        }
        let mut body = Vec::new();
        resp.take(vault_core::MAX_VAULT_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| CycleError::Other(format!("download body failed: {e}")))?;
        if body.len() > vault_core::MAX_VAULT_BYTES {
            return Err(CycleError::Other("downloaded vault is too large".into()));
        }
        Ok(body)
    }

    fn checksum(&self, id: &str) -> Result<String, CycleError> {
        let token = self.access_token()?;
        let resp = self
            .http
            .get(format!(
                "https://www.googleapis.com/drive/v3/files/{id}?fields=md5Checksum"
            ))
            .bearer_auth(&*token)
            .send()
            .map_err(|e| CycleError::Other(format!("preflight failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(classify(resp.status(), "preflight"));
        }
        let body: serde_json::Value = resp
            .json()
            .map_err(|e| CycleError::Other(format!("preflight unreadable: {e}")))?;
        Ok(field(&body, "md5Checksum"))
    }

    fn delete(&self, id: &str) -> Result<(), CycleError> {
        let token = self.access_token()?;
        let resp = self
            .http
            .delete(format!("https://www.googleapis.com/drive/v3/files/{id}"))
            .bearer_auth(&*token)
            .send()
            .map_err(|e| CycleError::Other(format!("delete failed: {e}")))?;
        // Already gone is the outcome we wanted.
        if !resp.status().is_success() && resp.status().as_u16() != 404 {
            return Err(classify(resp.status(), "delete"));
        }
        Ok(())
    }

    fn upload(&self, existing: Option<&str>, bytes: &[u8]) -> Result<RemoteFile, CycleError> {
        let token = self.access_token()?;
        let resp = match existing {
            Some(id) => self
                .http
                .patch(format!(
                    "https://www.googleapis.com/upload/drive/v3/files/{id}?uploadType=media&fields=id,md5Checksum"
                ))
                .bearer_auth(&*token)
                .header("Content-Type", "application/octet-stream")
                .body(bytes.to_vec())
                .send(),
            None => {
                let meta = format!(r#"{{"name":"{REMOTE_NAME}","parents":["appDataFolder"]}}"#);
                let boundary = "arca-vault-boundary";
                let mut body = Vec::new();
                body.extend_from_slice(
                    format!(
                        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n"
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(bytes);
                body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());
                self.http
                    .post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,md5Checksum")
                    .bearer_auth(&*token)
                    .header(
                        "Content-Type",
                        format!("multipart/related; boundary={boundary}"),
                    )
                    .body(body)
                    .send()
            }
        }
        .map_err(|e| CycleError::Other(format!("upload failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(classify(resp.status(), "upload"));
        }
        let body: serde_json::Value = resp
            .json()
            .map_err(|e| CycleError::Other(format!("upload response unreadable: {e}")))?;
        // `fields=id,md5Checksum` matters: the engine records this checksum as
        // integrated, so it has to describe what the server actually stored.
        Ok(RemoteFile {
            id: field(&body, "id"),
            checksum: field(&body, "md5Checksum"),
        })
    }

    fn invalidate_auth(&self) {
        if let Ok(mut cached) = self.access.lock() {
            *cached = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn listing_retains_the_next_page_and_rejects_missing_metadata() {
        let (files, next) = list_page(&serde_json::json!({
            "files": [{"id": "one", "md5Checksum": "checksum"}],
            "nextPageToken": "next-page"
        }))
        .unwrap();
        assert_eq!(files[0].id, "one");
        assert_eq!(next.as_deref(), Some("next-page"));
        assert_eq!(
            list_page(&serde_json::json!({"files": []})).unwrap(),
            (vec![], None)
        );
        assert!(list_page(&serde_json::json!({})).is_err());
        assert!(list_page(&serde_json::json!({"files": [{"id": "one"}]})).is_err());
    }

    #[derive(Default)]
    struct FakeTokens {
        present: AtomicBool,
        reads: AtomicUsize,
    }

    impl RefreshTokenStore for FakeTokens {
        fn exists(&self) -> bool {
            self.present.load(Ordering::SeqCst)
        }
        fn read(&self) -> Result<Option<Zeroizing<String>>, String> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .present
                .load(Ordering::SeqCst)
                .then(|| Zeroizing::new("refresh-token".into())))
        }
    }

    fn store(tokens: Arc<FakeTokens>) -> DriveStore {
        DriveStore::new(arca_credentials(), tokens)
    }

    /// Deliberately NOT "a secret is present": CI builds without one, and that
    /// build has to stay green. What must hold is that `sync_configured` tells
    /// the truth about whatever this build got, so the sign-in guard is never
    /// deciding on a stale assumption.
    #[test]
    fn configured_reports_what_this_build_actually_has() {
        let credentials = arca_credentials();
        assert!(
            !credentials.client_id.is_empty(),
            "the client id is a literal"
        );

        if SECRET_REQUIRED {
            assert_eq!(sync_configured(), !credentials.client_secret.is_empty());
        } else {
            // A public client. An empty secret is correct here, and `oauth`
            // must omit the field entirely rather than send it blank.
            assert!(credentials.client_secret.is_empty());
            assert!(sync_configured());
        }
    }

    /// The tick-rate call must answer from presence alone. Reading the token
    /// data can raise a keychain prompt on macOS, and the background loop asks
    /// this every 30 seconds forever.
    #[test]
    fn the_connected_check_never_reads_the_token() {
        let tokens = Arc::new(FakeTokens::default());
        let drive = store(tokens.clone());

        assert!(!drive.is_connected());
        tokens.present.store(true, Ordering::SeqCst);
        assert!(drive.is_connected());

        assert_eq!(
            tokens.reads.load(Ordering::SeqCst),
            0,
            "is_connected must not touch the token's data"
        );
    }

    #[test]
    fn a_cached_token_is_reused_and_invalidation_drops_it() {
        let tokens = Arc::new(FakeTokens::default());
        let drive = store(tokens.clone());
        drive.cache_access_token(Zeroizing::new("access".into()), 3600);

        assert_eq!(&*drive.access_token().unwrap(), "access");
        assert_eq!(
            tokens.reads.load(Ordering::SeqCst),
            0,
            "a live token needs no refresh"
        );

        drive.invalidate_auth();
        // Nothing stored and no network in the test: the point is that it now
        // has to go looking rather than hand back the token we dropped.
        assert!(drive.access_token().is_err());
        assert_eq!(tokens.reads.load(Ordering::SeqCst), 1);
    }

    /// An expired token must not be handed out. Every request made with one
    /// costs a round trip and comes back 401.
    #[test]
    fn an_expired_token_is_not_reused() {
        let tokens = Arc::new(FakeTokens::default());
        let drive = store(tokens.clone());
        // Server lifetime under the 60s safety margin: already past expiry.
        drive.cache_access_token(Zeroizing::new("stale".into()), 0);

        assert!(drive.access_token().is_err());
        assert_eq!(tokens.reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn only_a_401_is_treated_as_an_auth_failure() {
        assert!(matches!(
            classify(reqwest::StatusCode::UNAUTHORIZED, "upload"),
            CycleError::Auth
        ));
        assert!(matches!(
            classify(reqwest::StatusCode::NOT_FOUND, "download"),
            CycleError::Conflict
        ));
        for status in [
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(
                matches!(classify(status, "upload"), CycleError::Other(_)),
                "{status} must not trigger a credential refresh"
            );
        }
    }

    /// Drive omits `md5Checksum` for some files. An absent checksum has to read
    /// as empty rather than panic, and the engine compares it as a value like
    /// any other.
    #[test]
    fn a_missing_field_reads_as_empty() {
        let body = serde_json::json!({ "id": "abc" });
        assert_eq!(field(&body, "id"), "abc");
        assert_eq!(field(&body, "md5Checksum"), "");
    }
}
