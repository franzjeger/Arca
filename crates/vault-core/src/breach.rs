//! Password breach check via k-anonymity (the HaveIBeenPwned range API).
//!
//! This module is I/O-free: it computes the SHA-1 range **prefix**/**suffix**
//! and parses a range response. The actual HTTP GET happens in the app layer.
//!
//! PRIVACY: only the 5-character hash prefix is ever sent to the API — never
//! the password, and never its full hash. The API replies with every hash
//! suffix sharing that prefix; the match happens locally. The service cannot
//! tell which password (or even which suffix) was being checked.

use sha1::{Digest, Sha1};

/// Split the password's SHA-1 (uppercase hex) into the 5-char range prefix
/// (sent to the API) and the remaining suffix (matched locally).
pub fn prefix_suffix(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let mut hex = String::with_capacity(40);
    for b in digest {
        hex.push_str(&format!("{b:02X}"));
    }
    let (p, s) = hex.split_at(5);
    (p.to_string(), s.to_string())
}

/// Given a range response body (lines of `SUFFIX:COUNT`), return how many times
/// `suffix` appears in known breaches, or `None` if it isn't listed (not
/// breached). A malformed line is skipped, never fatal. Case-insensitive.
pub fn count_in_range(suffix: &str, body: &str) -> Option<u64> {
    for line in body.lines() {
        let Some((s, count)) = line.trim().split_once(':') else {
            continue;
        };
        if s.eq_ignore_ascii_case(suffix) {
            return count.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_suffix_matches_known_hash() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (p, s) = prefix_suffix("password");
        assert_eq!(p, "5BAA6");
        assert_eq!(s, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn count_in_range_finds_and_misses() {
        let body = "003D68EB55068C33ACE09247EE4C639306B:3\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:52372427\r\n\
                    011053FD0102E94D6AE2F8B83D76FAF94F6:1";
        // Present (case-insensitive) -> its count.
        assert_eq!(
            count_in_range("1e4c9b93f3f0682250b6cf8331b7ee68fd8", body),
            Some(52_372_427)
        );
        // Absent -> None.
        assert_eq!(
            count_in_range("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", body),
            None
        );
    }
}
