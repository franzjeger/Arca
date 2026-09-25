//! OAuth 2.0 for installed apps: PKCE, the code exchange, and token refresh.
//!
//! What is here is the part every platform shares — deriving a PKCE challenge
//! and POSTing to the token endpoint are the same on a Mac and on a phone.
//!
//! What is deliberately NOT here is how the authorization *code* is obtained.
//! The desktop opens a browser and catches the redirect on a loopback port;
//! iOS uses `ASWebAuthenticationSession` with a custom URL scheme and cannot
//! bind a listening socket at all. The two have nothing in common beyond the
//! URL, so each caller builds [`OAuthClient::authorization_url`], runs its own
//! flow, and hands the code back to [`OAuthClient::exchange_code`].

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The app's OAuth client registration.
///
/// For an installed app the "secret" is not confidential — it ships inside
/// every copy of the binary, and Google's own documentation says so. PKCE is
/// what actually binds an authorization code to the process that asked for it.
#[derive(Debug, Clone)]
pub struct AppCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub scope: String,
}

/// A PKCE verifier and its S256 challenge (RFC 7636).
///
/// The verifier never leaves the device until the code exchange, so a local
/// port sniffer (or another app claiming the same URL scheme) that intercepts
/// the redirect cannot redeem the code it stole.
pub struct Pkce {
    verifier: Zeroizing<String>,
    challenge: String,
}

impl Pkce {
    /// 32 random bytes → 43 base64url characters, inside RFC 7636's 43–128.
    pub fn generate() -> Result<Self, String> {
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(raw.as_mut_slice()).map_err(|_| "rng failure".to_string())?;
        let verifier = Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(raw.as_slice()));
        let challenge = challenge_for(&verifier);
        Ok(Self {
            verifier,
            challenge,
        })
    }

    /// The value to put in `code_challenge`. Safe to log; the verifier is not.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

/// `BASE64URL(SHA256(ASCII(verifier)))`, unpadded — RFC 7636 §4.2.
fn challenge_for(verifier: &str) -> String {
    data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()))
}

/// The result of a successful code exchange.
pub struct Tokens {
    /// The long-lived credential. The caller stores this in whatever secret
    /// store the platform has; this crate never persists anything.
    pub refresh_token: Zeroizing<String>,
    pub access_token: Zeroizing<String>,
    /// Lifetime of `access_token` in seconds, as reported by the server.
    pub expires_in: u64,
}

/// The token endpoint, and the URL builder for the authorization request.
pub struct OAuthClient {
    credentials: AppCredentials,
    http: reqwest::blocking::Client,
}

impl OAuthClient {
    pub fn new(credentials: AppCredentials) -> Self {
        Self {
            credentials,
            http: crate::http::client(),
        }
    }

    /// Where to send the user to approve access.
    ///
    /// `access_type=offline` + `prompt=consent` is what makes Google return a
    /// refresh token: without them a re-authorization returns only an access
    /// token, and the background loop has nothing to renew with.
    pub fn authorization_url(&self, redirect_uri: &str, pkce: &Pkce) -> String {
        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&code_challenge={}&code_challenge_method=S256",
            percent_encode(&self.credentials.client_id),
            percent_encode(redirect_uri),
            percent_encode(&self.credentials.scope),
            percent_encode(pkce.challenge()),
        )
    }

    /// Redeem an authorization code. `redirect_uri` must be byte-identical to
    /// the one in [`authorization_url`](Self::authorization_url) — the server
    /// compares them and rejects a mismatch.
    /// Form fields plus `client_secret` only when there is one.
    ///
    /// A public client (iOS) has no secret, and Google rejects the request when
    /// an empty one is sent rather than ignoring it. PKCE is what binds the code
    /// to this process either way.
    fn with_client_auth<'a>(&'a self, base: Vec<(&'a str, &'a str)>) -> Vec<(&'a str, &'a str)> {
        let mut fields = base;
        fields.insert(0, ("client_id", self.credentials.client_id.as_str()));
        if !self.credentials.client_secret.is_empty() {
            fields.insert(
                1,
                ("client_secret", self.credentials.client_secret.as_str()),
            );
        }
        fields
    }

    pub fn exchange_code(
        &self,
        code: &str,
        pkce: &Pkce,
        redirect_uri: &str,
    ) -> Result<Tokens, String> {
        let resp: serde_json::Value = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&self.with_client_auth(vec![
                ("code", code),
                ("code_verifier", pkce.verifier.as_str()),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
            ]))
            .send()
            .map_err(|e| format!("token exchange failed: {e}"))?
            .json()
            .map_err(|e| format!("token response unreadable: {e}"))?;

        // Empty counts as absent. A present-but-empty token would otherwise be
        // stored as the credential and fail on every later refresh, with the
        // sign-in itself reported as having worked.
        let refresh_token = resp["refresh_token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or("no refresh token in response")?;
        let access_token = resp["access_token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or("no access token")?;
        Ok(Tokens {
            refresh_token: Zeroizing::new(refresh_token.to_string()),
            access_token: Zeroizing::new(access_token.to_string()),
            expires_in: resp["expires_in"].as_u64().unwrap_or(3600),
        })
    }

    /// Trade a refresh token for a fresh access token, returning it and its
    /// lifetime in seconds.
    pub fn refresh(&self, refresh_token: &str) -> Result<(Zeroizing<String>, u64), String> {
        let resp: serde_json::Value = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&self.with_client_auth(vec![
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ]))
            .send()
            .map_err(|e| format!("token refresh failed: {e}"))?
            .json()
            .map_err(|e| format!("refresh response unreadable: {e}"))?;

        let access = resp["access_token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or("refresh rejected (reconnect Google in Settings)")?;
        Ok((
            Zeroizing::new(access.to_string()),
            resp["expires_in"].as_u64().unwrap_or(3600),
        ))
    }
}

/// Percent-encode everything outside RFC 3986's unreserved set.
///
/// Deliberately stricter than a query-string encoder: `+`, `/` and `=` all
/// appear in base64url-ish values and all mean something else in a URL, so
/// encoding only "special" characters is how a challenge silently arrives
/// mangled and the exchange fails with an unhelpful `invalid_grant`.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from RFC 7636 Appendix B. If this drifts, every
    /// sign-in fails at the exchange with `invalid_grant` and nothing local
    /// says why.
    #[test]
    fn the_challenge_matches_the_rfc_7636_test_vector() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_generated_verifier_is_within_the_permitted_length() {
        let pkce = Pkce::generate().unwrap();
        assert_eq!(pkce.verifier.len(), 43, "43..=128 per RFC 7636 §4.1");
        assert_eq!(pkce.challenge(), challenge_for(&pkce.verifier));
    }

    #[test]
    fn generating_twice_gives_different_verifiers() {
        let a = Pkce::generate().unwrap();
        let b = Pkce::generate().unwrap();
        assert_ne!(a.verifier.as_str(), b.verifier.as_str());
    }

    #[test]
    fn the_unreserved_set_survives_encoding_and_everything_else_does_not() {
        assert_eq!(percent_encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(percent_encode("a/b+c=d"), "a%2Fb%2Bc%3Dd");
        assert_eq!(
            percent_encode("http://127.0.0.1:52341"),
            "http%3A%2F%2F127.0.0.1%3A52341"
        );
    }

    #[test]
    fn the_authorization_url_carries_the_challenge_and_asks_for_a_refresh_token() {
        let client = OAuthClient::new(AppCredentials {
            client_id: "id.apps.googleusercontent.com".into(),
            client_secret: "unused-for-the-url".into(),
            scope: "https://www.googleapis.com/auth/drive.appdata".into(),
        });
        let pkce = Pkce::generate().unwrap();
        let url = client.authorization_url("http://127.0.0.1:52341", &pkce);

        assert!(url.contains(&format!(
            "code_challenge={}",
            percent_encode(pkce.challenge())
        )));
        assert!(url.contains("code_challenge_method=S256"));
        // Without both of these Google returns no refresh token, and sync works
        // exactly until the first access token expires.
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A52341"));
        assert!(
            !url.contains("client_secret"),
            "the secret belongs in the token POST, never in a browser URL"
        );
    }

    // A public client (iOS) has no secret, and Google rejects a request that
    // sends an empty one — so "omit it" is a correctness requirement, not
    // tidiness. Easy to undo by inlining the form fields again, hence the test.
    #[test]
    fn client_secret_is_sent_only_when_there_is_one() {
        let with = OAuthClient::new(AppCredentials {
            client_id: "id".into(),
            client_secret: "shhh".into(),
            scope: "s".into(),
        });
        let fields = with.with_client_auth(vec![("grant_type", "refresh_token")]);
        assert!(fields
            .iter()
            .any(|(k, v)| *k == "client_secret" && *v == "shhh"));
        assert!(fields.iter().any(|(k, _)| *k == "client_id"));

        let without = OAuthClient::new(AppCredentials {
            client_id: "id".into(),
            client_secret: String::new(),
            scope: "s".into(),
        });
        let fields = without.with_client_auth(vec![("grant_type", "refresh_token")]);
        assert!(
            !fields.iter().any(|(k, _)| *k == "client_secret"),
            "an empty secret must be omitted entirely, not sent as \"\""
        );
        assert!(fields.iter().any(|(k, _)| *k == "client_id"));
    }
}
