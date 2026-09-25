//! WebAuthn Level 3 Related Origin Requests.
//!
//! A relying party may serve `https://<rpId>/.well-known/webauthn` listing
//! other origins its credentials are valid on. Microsoft does exactly this:
//! passkeys are registered under `login.microsoft.com`, while every sign-in
//! actually lands on `login.microsoftonline.com`. Without this, such a passkey
//! is invisible and unusable — which is how Arca behaved, while Apple Passwords
//! signed in fine, because Apple reads the file.
//!
//! WHAT KEEPS THIS SAFE
//!
//! The list is only ever fetched from the rpId's OWN origin over HTTPS, so TLS
//! is the authentication: only whoever controls `login.microsoft.com` can say
//! what `login.microsoft.com` credentials are good for. Nothing here widens
//! matching on its own; it only honours what the RP itself published.
//!
//! And the spec's cap is implemented rather than waved at: at most five
//! DISTINCT registrable-domain labels are accepted from one list. That is what
//! stops an RP (or a subverted one) from turning a single rpId into a passport
//! for hundreds of unrelated sites. The `psl` crate supplies real public-suffix
//! data, so `login.microsoftonline.com` yields the label `microsoftonline`
//! rather than a guess based on counting dots.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hosts accepted for one rpId, with the moment they were fetched.
type Cached = (Instant, Vec<String>);

fn cache() -> &'static Mutex<HashMap<String, Cached>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Cached>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How long a fetched list is trusted. Long enough that a browsing session
/// costs one request; short enough that removing an origin takes effect the
/// same day.
const TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// A failed or absent file is cached too, briefly. Most relying parties serve
/// no such file, and a passkey list must not mean a network round-trip per
/// password field on every page.
const NEGATIVE_TTL: Duration = Duration::from_secs(5 * 60);

/// The spec's limit on distinct registrable-domain labels in one list.
const MAX_LABELS: usize = 5;

/// Total origins read from one document, before labelling. A guard against a
/// pathological response, not a security boundary — `MAX_LABELS` is that.
const MAX_ORIGINS: usize = 64;

const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Whether `host` is an origin the relying party `rp_id` has published as its
/// own. Network on first use per rpId; cached after.
///
/// Callers must NOT hold the app-state lock: this makes an HTTPS request.
pub fn is_related(rp_id: &str, host: &str) -> bool {
    let rp = rp_id.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if rp.is_empty() || host.is_empty() {
        return false;
    }

    if let Some((fetched, hosts)) = cache().lock().ok().and_then(|c| c.get(&rp).cloned()) {
        let ttl = if hosts.is_empty() { NEGATIVE_TTL } else { TTL };
        if fetched.elapsed() < ttl {
            return hosts.iter().any(|h| h == &host);
        }
    }

    let hosts = fetch(&rp);
    if let Ok(mut c) = cache().lock() {
        c.insert(rp, (Instant::now(), hosts.clone()));
    }
    hosts.iter().any(|h| h == &host)
}

/// Fetch and vet `https://<rp_id>/.well-known/webauthn`. Any failure is an
/// empty list — a relying party that publishes nothing simply has no related
/// origins, which is the overwhelmingly common case and not an error.
fn fetch(rp_id: &str) -> Vec<String> {
    let url = format!("https://{rp_id}/.well-known/webauthn");
    let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        // No redirect following: a redirect off the rpId's origin would let
        // some other host answer for it, which is exactly the authentication
        // this relies on.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return Vec::new();
    };
    let Ok(response) = client.get(&url).send() else {
        return Vec::new();
    };
    if !response.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = response.text() else {
        return Vec::new();
    };
    accept(&body)
}

/// The pure half: turn a well-known document into the hosts we will honour.
///
/// Separated from the request so the rules — https only, label cap, ordering —
/// are testable without a network.
fn accept(body: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(origins) = doc.get("origins").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut labels: Vec<String> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();

    for entry in origins.iter().take(MAX_ORIGINS) {
        let Some(raw) = entry.as_str() else { continue };
        // Parsed rather than string-matched: "https://evil.com@good.com" and
        // friends are exactly what a hand-rolled prefix check gets wrong.
        let Ok(parsed) = url::Url::parse(raw.trim()) else {
            continue;
        };
        if parsed.scheme() != "https" {
            continue;
        }
        let Some(host) = parsed.host_str().map(|h| h.to_ascii_lowercase()) else {
            continue;
        };

        // The label is the registrable domain minus its public suffix:
        // login.microsoftonline.com -> microsoftonline.com -> "microsoftonline".
        let Some(registrable) = psl::domain_str(&host) else {
            continue;
        };
        let Some(label) = registrable.split('.').next().map(|s| s.to_string()) else {
            continue;
        };

        if !labels.iter().any(|l| l == &label) {
            // In document order, and the entries past the cap are DROPPED
            // rather than the whole list rejected — the spec's intent is a
            // ceiling on breadth, not a trap for a long file.
            if labels.len() == MAX_LABELS {
                continue;
            }
            labels.push(label);
        }
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_real_microsoft_document() {
        // The actual file, verbatim — the case this whole module exists for.
        let hosts =
            accept(r#"{"origins":["https://login.live.com","https://login.microsoftonline.com"]}"#);
        assert!(hosts.iter().any(|h| h == "login.microsoftonline.com"));
        assert!(hosts.iter().any(|h| h == "login.live.com"));
    }

    #[test]
    fn refuses_anything_not_https() {
        // A cleartext origin would let anyone on the path claim the credential.
        let hosts = accept(r#"{"origins":["http://evil.test","https://ok.test"]}"#);
        assert_eq!(hosts, vec!["ok.test"]);
    }

    #[test]
    fn parses_origins_rather_than_matching_strings() {
        // "https://good.test@evil.test" has HOST evil.test. A prefix check on
        // the text would read it as good.test and hand over the credential.
        let hosts = accept(r#"{"origins":["https://good.test@evil.test"]}"#);
        assert_eq!(hosts, vec!["evil.test"], "the host is what counts");
    }

    #[test]
    fn caps_distinct_registrable_labels_at_five() {
        // Six organisations; the sixth is dropped. This is the spec's guard
        // against one rpId becoming a passport for unrelated sites.
        let doc = r#"{"origins":[
            "https://a.one.com","https://b.one.com",
            "https://two.com","https://three.com",
            "https://four.com","https://five.com",
            "https://six.com"]}"#;
        let hosts = accept(doc);
        assert!(
            hosts.contains(&"b.one.com".to_string()),
            "same label is free"
        );
        assert!(hosts.contains(&"five.com".to_string()));
        assert!(
            !hosts.contains(&"six.com".to_string()),
            "the sixth distinct label must be refused"
        );
    }

    #[test]
    fn junk_is_an_empty_list_not_a_panic() {
        for body in [
            "",
            "not json",
            "{}",
            r#"{"origins":"nope"}"#,
            r#"{"origins":[1,2]}"#,
        ] {
            assert!(accept(body).is_empty(), "{body:?}");
        }
    }
}
