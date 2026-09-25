//! Time-based one-time passwords (RFC 6238 / RFC 4226).
//!
//! SHA-1, 6 digits, 30-second period — the de-facto default that authenticator
//! apps emit. The current time is passed in (unix seconds) so the function is
//! pure and testable against the RFC vectors.
//!
//! TODO(phase-2): support configurable digits/period and SHA-256/512 once we
//! parse `otpauth://` URIs on import.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

const PERIOD_SECS: u64 = 30;
const DIGITS: u32 = 6;

/// A generated TOTP plus the timing needed to render a countdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    /// Zero-padded numeric code, e.g. `"287082"`.
    pub code: String,
    /// Step length in seconds (30).
    pub period: u64,
    /// Seconds remaining until this code rolls over (1..=period).
    pub remaining: u64,
}

/// Compute the current TOTP for a Base32 secret at `unix_seconds`.
pub fn current_totp(base32_secret: &str, unix_seconds: u64) -> Result<TotpCode> {
    let secret = decode_base32_secret(base32_secret)?;
    let counter = unix_seconds / PERIOD_SECS;
    let code = hotp(&secret, counter, DIGITS)?;
    let remaining = PERIOD_SECS - (unix_seconds % PERIOD_SECS);
    Ok(TotpCode {
        code,
        period: PERIOD_SECS,
        remaining,
    })
}

/// Parsed `otpauth://totp/...` URI (the format authenticator-app QR codes
/// encode). Only the secret is needed to compute codes; the label/issuer are
/// surfaced for callers that want to suggest a title.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpAuth {
    /// Base32 shared secret (validated to decode).
    pub secret: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

/// Parse an `otpauth://totp/...` URI and extract its Base32 secret.
///
/// Errors if the URI is not a TOTP otpauth URI, lacks a (valid Base32) secret,
/// or specifies parameters this build can't compute — non-SHA-1 algorithm,
/// digit count other than 6, or a period other than 30s — rather than silently
/// producing wrong codes. (Extending those is the SHA-256/512 TODO above.)
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpAuth> {
    const PREFIX: &str = "otpauth://totp/";
    let uri = uri.trim();
    if !uri.to_ascii_lowercase().starts_with(PREFIX) {
        return Err(Error::InvalidTotpSecret);
    }
    let rest = &uri[PREFIX.len()..];
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));

    let mut secret = None;
    let mut issuer = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(v),
            "issuer" => issuer = Some(v),
            "algorithm" => algorithm = Some(v),
            "digits" => digits = Some(v),
            "period" => period = Some(v),
            _ => {}
        }
    }

    let secret = secret
        .filter(|s| !s.is_empty())
        .ok_or(Error::InvalidTotpSecret)?;
    // Validate it actually decodes as Base32 before we store it.
    decode_base32_secret(&secret)?;

    if algorithm
        .as_deref()
        .is_some_and(|a| !a.eq_ignore_ascii_case("SHA1"))
    {
        return Err(Error::InvalidArgument(
            "unsupported TOTP algorithm (only SHA-1 is supported)",
        ));
    }
    if digits.as_deref().is_some_and(|d| d != "6") {
        return Err(Error::InvalidArgument(
            "unsupported TOTP digit count (only 6 is supported)",
        ));
    }
    if period.as_deref().is_some_and(|p| p != "30") {
        return Err(Error::InvalidArgument(
            "unsupported TOTP period (only 30 seconds is supported)",
        ));
    }

    // Label is "Issuer:Account" or just "Account".
    let label = percent_decode(label);
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), Some(a.trim().to_string())),
        None if label.trim().is_empty() => (None, None),
        None => (None, Some(label.trim().to_string())),
    };

    Ok(OtpAuth {
        secret,
        issuer: issuer.filter(|s| !s.is_empty()).or(label_issuer),
        account,
    })
}

/// Minimal RFC 3986 percent-decoding (`%XX`). Leaves other bytes untouched.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Normalize and Base32-decode a TOTP shared secret. Tolerates lowercase,
/// spaces, and `=` padding (as copied from various providers).
fn decode_base32_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .flat_map(char::to_uppercase)
        .collect();
    let bytes = data_encoding::BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| Error::InvalidTotpSecret)?;
    Ok(Zeroizing::new(bytes))
}

/// RFC 4226 HOTP with dynamic truncation.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| Error::InvalidTotpSecret)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);

    let modulus = 10u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        bin % modulus,
        width = digits as usize
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test seed: ASCII "12345678901234567890".
    const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors_truncated_to_6_digits() {
        // RFC 6238 lists 8-digit values; the low 6 digits must match.
        // T=59  -> 94287082 -> "287082"
        assert_eq!(current_totp(RFC_SECRET_B32, 59).unwrap().code, "287082");
        // T=1111111109 -> 07081804 -> "081804"
        assert_eq!(
            current_totp(RFC_SECRET_B32, 1_111_111_109).unwrap().code,
            "081804"
        );
    }

    #[test]
    fn remaining_counts_down_within_period() {
        assert_eq!(current_totp(RFC_SECRET_B32, 0).unwrap().remaining, 30);
        assert_eq!(current_totp(RFC_SECRET_B32, 1).unwrap().remaining, 29);
        assert_eq!(current_totp(RFC_SECRET_B32, 29).unwrap().remaining, 1);
        assert_eq!(current_totp(RFC_SECRET_B32, 30).unwrap().remaining, 30);
    }

    #[test]
    fn tolerates_lowercase_spaces_and_padding() {
        let messy = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(current_totp(messy, 59).unwrap().code, "287082");
    }

    #[test]
    fn rejects_invalid_base32() {
        assert!(matches!(
            current_totp("not valid base32 !!!", 0),
            Err(Error::InvalidTotpSecret)
        ));
    }

    #[test]
    fn parses_otpauth_uri_and_extracts_usable_secret() {
        let uri = format!(
            "otpauth://totp/GitHub:alice%40example.test?secret={RFC_SECRET_B32}&issuer=GitHub"
        );
        let parsed = parse_otpauth_uri(&uri).unwrap();
        assert_eq!(parsed.secret, RFC_SECRET_B32);
        assert_eq!(parsed.issuer.as_deref(), Some("GitHub"));
        assert_eq!(parsed.account.as_deref(), Some("alice@example.test")); // percent-decoded
                                                                           // The extracted secret computes the RFC vector.
        assert_eq!(current_totp(&parsed.secret, 59).unwrap().code, "287082");
    }

    #[test]
    fn otpauth_defaults_are_accepted() {
        let uri =
            format!("otpauth://totp/x?secret={RFC_SECRET_B32}&algorithm=SHA1&digits=6&period=30");
        assert!(parse_otpauth_uri(&uri).is_ok());
    }

    #[test]
    fn otpauth_rejects_non_totp_and_missing_secret() {
        assert!(matches!(
            parse_otpauth_uri("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=0"),
            Err(Error::InvalidTotpSecret)
        ));
        assert!(matches!(
            parse_otpauth_uri("otpauth://totp/x?issuer=Acme"),
            Err(Error::InvalidTotpSecret)
        ));
        assert!(matches!(
            parse_otpauth_uri("https://example.com"),
            Err(Error::InvalidTotpSecret)
        ));
    }

    #[test]
    fn otpauth_rejects_unsupported_parameters() {
        for q in ["algorithm=SHA256", "digits=8", "period=60"] {
            let uri = format!("otpauth://totp/x?secret={RFC_SECRET_B32}&{q}");
            assert!(
                matches!(parse_otpauth_uri(&uri), Err(Error::InvalidArgument(_))),
                "expected {q} to be rejected"
            );
        }
    }
}
