//! The host a stored URL belongs to — the anti-phishing match key.
//!
//! This is one function because it used to be three, and they disagreed. The
//! desktop bridge, the AutoFill FFI and the duplicate finder each grew their own
//! copy, each was hardened against something the others were not, and every one
//! of them was wrong in a way the other two were not:
//!
//! * the bridge ended the authority at `/` only, so an `@` anywhere in a query
//!   or fragment read as userinfo — a stored `https://bank.example#@evil.com`
//!   keyed the credential to `evil.com`, and autofill then offered it there;
//! * the FFI stripped `www.` before lowercasing, so `WWW.GitHub.com` came out as
//!   `www.github.com`, and lowercased ASCII-only, so `MÜNCHEN.DE` came out as
//!   `mÜnchen.de` — both fail closed, but autofill silently stops matching;
//! * the duplicate finder did not do the browser's backslash normalization, so a
//!   crafted URL grouped under the wrong site.
//!
//! Any of those is a bug. Three copies drifting apart is the bug that produces
//! them, so there is now exactly one, and the comparison lives in its tests.
//!
//! Nothing here parses URLs properly on purpose: a full parser would accept
//! things a browser rejects and vice versa, and what matters is agreeing with
//! **the browser**, because the browser decides which site the user actually
//! visited.

/// Bare host of a URL, normalized for matching and display.
///
/// Scheme, path, query, fragment, userinfo and port are stripped; a leading
/// `www.` and a trailing `.` are removed; the result is lowercased. IPv6
/// literals keep their brackets (`[fd00::a1]`), which is the form a URL
/// authority uses and the form shown in the UI. Returns an empty string when
/// there is no host — callers treat that as "never matches".
///
/// The result is the anti-phishing match key, so it MUST agree with how a
/// browser resolves the host of the same string.
pub fn host_of(url: &str) -> String {
    normalize_host(&raw_host_of(url))
}

/// Bare host of a URL for **WebAuthn**, where `www.` is part of the name.
///
/// Identical to [`host_of`] — same browser normalization, same authority and
/// userinfo rules, same lowercasing, port and trailing-dot stripping — except
/// that a leading `www.` SURVIVES.
///
/// Password matching strips it because `www.example.com` and `example.com` are
/// the same login to a human. WebAuthn is not that: the rpId is a name the
/// relying party and the browser agree on byte for byte, and a page that omits
/// `rp.id` gets its full hostname as the default — `www.example.com`. Folding
/// that to `example.com` made the rpId look like a *different* domain than the
/// origin, so the ceremony was refused with `origin_mismatch`, and any passkey
/// already stored under a `www.` rpId could never be asserted again.
pub fn webauthn_host_of(url: &str) -> String {
    normalize_case_and_dot(&raw_host_of(url))
}

/// The host substring of `url`, before the `www.` question is asked.
///
/// Shared so the WebAuthn extractor cannot drift from [`host_of`] about where a
/// host begins and ends — the drift this module exists to prevent. Everything
/// hostile lives in here (userinfo, an `@` in a fragment, backslashes, IPv6
/// literals); the callers differ only in how they normalize the result.
fn raw_host_of(url: &str) -> String {
    let normalized = browser_normalized(url);
    let trimmed = normalized.trim();

    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);

    // Userinfo is everything before the LAST `@`, per RFC 3986.
    let authority = authority_of(after_scheme);
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);

    split_port(host).0.to_string()
}

/// The parts of a URL that decide whether a stored credential may be offered on
/// a page — host, scheme and explicit port.
///
/// [`host_of`] alone was the whole match key, and a host is not an origin. A
/// credential saved at `https://bank.example` was offered on
/// `http://bank.example` — the shape of an evil-twin Wi-Fi, a captive portal or
/// spoofed DNS, where the password then leaves the browser in cleartext. It
/// also merged `https://nas.local:5000` with `https://nas.local:8443`, and
/// every `localhost:<port>` a developer runs.
///
/// Ports are recorded only when the URL states one. A stored bare hostname
/// (`github.com`) has no opinion about either scheme or port, which is how
/// entries typed by hand keep matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub host: String,
    /// Lowercased scheme when the URL had one.
    pub scheme: Option<String>,
    /// Port only when the URL stated one explicitly.
    pub port: Option<u16>,
}

impl Origin {
    /// The port this origin implies when it states none.
    fn default_port(&self) -> Option<u16> {
        match self.scheme.as_deref() {
            Some("https") => Some(443),
            Some("http") => Some(80),
            _ => None,
        }
    }

    /// Whether a credential stored at `self` may be filled on `requested`.
    ///
    /// Same host, never a downgrade from `https` to `http`, and the same port
    /// once either side names one. Upgrading `http` to `https` is allowed: it
    /// is strictly safer, and a vault full of entries saved before a site moved
    /// to TLS should keep working.
    pub fn may_fill(&self, requested: &Origin) -> bool {
        if self.host.is_empty() || requested.host.is_empty() || self.host != requested.host {
            return false;
        }
        if self.scheme.as_deref() == Some("https") && requested.scheme.as_deref() == Some("http") {
            return false;
        }
        match (self.port, requested.port) {
            (Some(a), Some(b)) => a == b,
            (Some(a), None) => Some(a) == requested.default_port(),
            (None, Some(b)) => self.default_port() == Some(b),
            (None, None) => true,
        }
    }
}

/// Host, scheme and explicit port of a URL, normalized exactly as [`host_of`]
/// normalizes the host — the two must never disagree about which site a string
/// names.
pub fn origin_of(url: &str) -> Origin {
    let normalized = browser_normalized(url);
    let trimmed = normalized.trim();

    let (scheme, after_scheme) = match trimmed.split_once("://") {
        // A scheme is ASCII letters/digits/`+`/`-`/`.`; anything else means the
        // `://` came from somewhere other than a scheme delimiter.
        Some((s, rest))
            if !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            (Some(s.to_ascii_lowercase()), rest)
        }
        _ => (None, trimmed),
    };

    let authority = authority_of(after_scheme);
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let (host_part, port_part) = split_port(host_port);

    Origin {
        host: normalize_host(host_part),
        scheme,
        port: port_part.and_then(|p| p.parse::<u16>().ok()),
    }
}

/// Browsers strip ASCII tab/CR/LF from a URL and treat backslashes as forward
/// slashes before parsing. Do the same first, or a stored
/// `https://good.com\@evil.com` — which a browser navigates to good.com — is
/// read here as host `evil.com`.
fn browser_normalized(url: &str) -> String {
    url.chars()
        .filter(|&c| c != '\t' && c != '\n' && c != '\r')
        .map(|c| if c == '\\' { '/' } else { c })
        .collect()
}

/// The authority ends at the first `/`, `?` or `#`. Splitting on `/` alone
/// leaves a query or fragment attached, and then a `rsplit_once('@')` reads an
/// `@` inside it as userinfo — handing an attacker the host.
fn authority_of(after_scheme: &str) -> &str {
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
}

/// Split `host:port`, bracket-aware: an IPv6 literal (`[fd00::a1]:8080`) must
/// not be truncated at the first colon inside the address.
fn split_port(host_port: &str) -> (&str, Option<&str>) {
    if host_port.starts_with('[') {
        return match host_port.find(']') {
            Some(end) => match host_port[end + 1..].strip_prefix(':') {
                Some(port) => (&host_port[..=end], Some(port)),
                None => (&host_port[..=end], None),
            },
            None => (host_port, None), // malformed literal; keep it, it just won't match
        };
    }
    match host_port.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    }
}

/// Lowercase BEFORE stripping `www.`, or an uppercase `WWW.` survives. Full
/// Unicode lowercase so IDN hosts compare equal. A trailing dot is the
/// fully-qualified form: `github.com.` is `github.com`.
fn normalize_host(host: &str) -> String {
    let host = normalize_case_and_dot(host);
    host.strip_prefix("www.").unwrap_or(&host).to_string()
}

/// Everything [`normalize_host`] does except the `www.` strip. Full Unicode
/// lowercase (not ASCII-only) so IDN hosts compare equal, and a trailing dot
/// dropped because `github.com.` is the fully-qualified form of `github.com`.
fn normalize_case_and_dot(host: &str) -> String {
    host.trim().trim_end_matches('.').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{host_of, origin_of, webauthn_host_of};

    /// A passkey's rpId is a name, not a match key: a page that omits `rp.id`
    /// gets its full hostname as the default, so on `https://www.example.com`
    /// the rpId IS `www.example.com`. Folding it to `example.com` the way
    /// password matching does made the two look like different domains, and the
    /// ceremony was refused as an origin mismatch.
    #[test]
    fn the_webauthn_host_keeps_www() {
        assert_eq!(
            webauthn_host_of("https://www.example.com/login"),
            "www.example.com"
        );
        assert_eq!(host_of("https://www.example.com/login"), "example.com");

        // Everything else normalizes exactly as `host_of` does — the two differ
        // in one rule and no other.
        for url in [
            "https://sub.github.com/x",
            "https://bank.example#@evil.com",
            r"https://good.com\@evil.com",
            "http://user@accounts.google.com:443/",
            "https://[fd00::a1]:8443/z",
            "https://MÜNCHEN.DE",
            "https://Good.COM./x",
            "bareword",
            "",
            "https://",
        ] {
            assert_eq!(webauthn_host_of(url), host_of(url), "disagreed on {url:?}");
        }
        // ...including the case and trailing-dot rules on a `www.` host itself.
        assert_eq!(
            webauthn_host_of("https://WWW.Example.COM./x"),
            "www.example.com"
        );
    }

    /// `origin_of` and `host_of` must never disagree about which site a string
    /// names: one is the anti-phishing key the other refines.
    #[test]
    fn origin_host_agrees_with_host_of() {
        for url in [
            "https://www.github.com/login",
            "https://bank.example#@evil.com",
            r"https://good.com\@evil.com",
            "http://user@accounts.google.com:443/",
            "https://[fd00::a1]:8443/z",
            "https://MÜNCHEN.DE",
            "https://Good.COM./x",
            "bareword",
            "",
            "https://",
        ] {
            assert_eq!(origin_of(url).host, host_of(url), "disagreed on {url:?}");
        }
    }

    #[test]
    fn origin_reads_scheme_and_explicit_port() {
        let o = origin_of("https://nas.local:5000/admin");
        assert_eq!(o.scheme.as_deref(), Some("https"));
        assert_eq!(o.port, Some(5000));

        // No port stated is not "port 0" — it is "no opinion".
        assert_eq!(origin_of("https://bank.example").port, None);
        // A bare hostname has no scheme either, so it matches either one.
        assert_eq!(origin_of("github.com").scheme, None);
        // Bracket-aware: the colons inside an IPv6 literal are not a port.
        assert_eq!(origin_of("https://[fd00::a1]/x").port, None);
        assert_eq!(origin_of("https://[fd00::a1]:8443/x").port, Some(8443));
        assert_eq!(
            origin_of("HTTPS://Example.com").scheme.as_deref(),
            Some("https")
        );
    }

    /// The finding this type exists for: a password saved over TLS must not be
    /// handed to a page served in the clear.
    #[test]
    fn https_credentials_are_never_offered_over_http() {
        let stored = origin_of("https://bank.example/login");
        assert!(!stored.may_fill(&origin_of("http://bank.example/login")));
        assert!(stored.may_fill(&origin_of("https://bank.example/login")));

        // Upgrading is safe, and keeps entries saved before a site moved to TLS.
        let legacy = origin_of("http://forum.example/login");
        assert!(legacy.may_fill(&origin_of("https://forum.example/login")));
        assert!(legacy.may_fill(&origin_of("http://forum.example/login")));

        // A hand-typed bare hostname has no scheme, so it still matches.
        assert!(origin_of("bank.example").may_fill(&origin_of("https://bank.example")));
        assert!(origin_of("bank.example").may_fill(&origin_of("http://bank.example")));
    }

    #[test]
    fn distinct_ports_are_distinct_sites() {
        // Two services behind one hostname — the developer's localhost case and
        // the NAS case — are not the same origin.
        assert!(!origin_of("https://nas.local:5000").may_fill(&origin_of("https://nas.local:8443")));
        assert!(!origin_of("http://localhost:3000").may_fill(&origin_of("http://localhost:8080")));
        assert!(origin_of("http://localhost:3000").may_fill(&origin_of("http://localhost:3000")));

        // An explicit default port is the same origin as an implicit one.
        assert!(origin_of("https://x.example").may_fill(&origin_of("https://x.example:443")));
        assert!(origin_of("https://x.example:443").may_fill(&origin_of("https://x.example")));
        // A non-default port is not.
        assert!(!origin_of("https://x.example:8443").may_fill(&origin_of("https://x.example")));
        assert!(!origin_of("https://x.example").may_fill(&origin_of("https://x.example:8443")));
    }

    #[test]
    fn a_different_host_never_matches_whatever_the_scheme() {
        assert!(!origin_of("https://bank.example").may_fill(&origin_of("https://evil.example")));
        assert!(!origin_of("").may_fill(&origin_of("https://bank.example")));
        assert!(!origin_of("https://bank.example").may_fill(&origin_of("")));
    }

    #[test]
    fn extracts_the_matchable_host() {
        assert_eq!(host_of("https://www.github.com/login"), "github.com");
        assert_eq!(host_of("https://www.github.com/login?x=1"), "github.com");
        assert_eq!(host_of("http://example.com:8080/x"), "example.com");
        assert_eq!(
            host_of("https://user:pass@sub.example.com/y"),
            "sub.example.com"
        );
        assert_eq!(
            host_of("http://user@accounts.google.com:443/"),
            "accounts.google.com"
        );
        assert_eq!(host_of("bareword"), "bareword");
        assert_eq!(host_of(""), "");
        assert_eq!(host_of("https://"), "");
    }

    #[test]
    fn case_and_trailing_dot_normalize() {
        // Lowercasing has to happen before `www.` is stripped, or the uppercase
        // form survives and the host never matches its lowercase twin.
        assert_eq!(host_of("https://WWW.GitHub.com/login"), "github.com");
        assert_eq!(host_of("https://Good.COM./x"), "good.com");
        // Full Unicode lowercase, not ASCII-only, so IDN hosts compare equal.
        assert_eq!(host_of("https://MÜNCHEN.DE"), "münchen.de");
    }

    #[test]
    fn ipv6_literals_keep_their_brackets() {
        // Bracket-aware port stripping: the colons inside the address must
        // survive, and the brackets are the form a URL authority uses.
        assert_eq!(host_of("https://[fd00::a1]/admin"), "[fd00::a1]");
        assert_eq!(host_of("https://[::1]:8080/x"), "[::1]");
        assert_eq!(host_of("https://[fd00::1]:8443/z"), "[fd00::1]");
    }

    /// The regression that motivated merging the three copies. Each case is a
    /// stored URL a browser resolves to `bank.example`; reading any other host
    /// out of one means offering that credential on someone else's site.
    #[test]
    fn an_at_sign_after_the_authority_is_not_userinfo() {
        // A query string containing an email address is entirely ordinary, and
        // the old bridge copy read this as host `gmail.com`.
        assert_eq!(
            host_of("https://bank.example?email=me@gmail.com"),
            "bank.example"
        );
        // A fragment is never sent to the server, so the site cannot strip it.
        assert_eq!(host_of("https://bank.example#@evil.com"), "bank.example");
        assert_eq!(
            host_of("https://bank.example/login?ref=@evil.com"),
            "bank.example"
        );
        // Real userinfo still works — it is before the authority's end.
        assert_eq!(host_of("https://me@bank.example/login"), "bank.example");
    }

    #[test]
    fn matches_browser_normalization() {
        // Backslash is a path separator to a browser, so the host is good.com,
        // NOT evil.com — otherwise a good.com credential could be offered on
        // evil.com.
        assert_eq!(host_of(r"https://good.com\@evil.com"), "good.com");
        assert_eq!(host_of(r"https://good.com\login"), "good.com");
        // Browsers strip ASCII tab/CR/LF anywhere in a URL before parsing.
        assert_eq!(host_of("https://good.com\t/login"), "good.com");
        assert_eq!(host_of("https://good.com\n"), "good.com");
        assert_eq!(host_of("https://good\t.com/"), "good.com");
    }
}
