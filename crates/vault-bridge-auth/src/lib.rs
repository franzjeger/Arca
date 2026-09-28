//! The handshake of the desktop app's loopback bridge, in one place for the app
//! and both of its clients: the browser's native-messaging host and `arca`.
//!
//! Protocol 3. The token never crosses the socket:
//!
//! ```text
//! client -> app   hello     { protocol: 3, nonce: C }
//! app -> client   challenge { nonce: A, proof: app_proof(token, C, A) }
//! client -> app   auth      { proof: client_proof(token, C, A) }
//! app -> client   ok        { protocol, version, ... }
//! ```
//!
//! The client checks the app's proof before it writes anything else. Arca's
//! port is free the moment it exits, and in protocol 2 the client's first
//! message carried the token, so whoever bound the port next could compute
//! the "app" proof from it and be sent the next submitted password.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The bridge protocol the app and its clients speak.
pub const PROTOCOL: u32 = 3;

const NONCE_BYTES: usize = 16;

/// A fresh 128-bit challenge from the OS CSPRNG, as lowercase hex.
pub fn nonce() -> Option<String> {
    let mut bytes = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut bytes).ok()?;
    Some(hex(&bytes))
}

/// Whether `s` has the shape [`nonce`] produces. Checked before a nonce is
/// used, so the two can be joined without a separator being ambiguous.
pub fn is_nonce(s: &str) -> bool {
    s.len() == 2 * NONCE_BYTES && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// What the app sends to prove it holds `token` on this connection.
pub fn app_proof(token: &str, client_nonce: &str, app_nonce: &str) -> String {
    proof(b"arca/bridge/3/app\0", token, client_nonce, app_nonce)
}

/// What the client sends to prove it holds `token` on this connection. A
/// different label from [`app_proof`], so the app can never be used to answer
/// its own challenge.
pub fn client_proof(token: &str, client_nonce: &str, app_nonce: &str) -> String {
    proof(b"arca/bridge/3/client\0", token, client_nonce, app_nonce)
}

/// Protocol 2's app proof, `HMAC-SHA256(token, nonce)`. Only the app computes
/// it, to answer clients built before protocol 3.
pub fn v2_proof(token: &str, nonce: &str) -> String {
    hex(&mac(token).chain_update(nonce).finalize().into_bytes())
}

/// Constant-time equality for tokens and proofs.
pub fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn proof(label: &[u8], token: &str, client_nonce: &str, app_nonce: &str) -> String {
    let mac = mac(token)
        .chain_update(label)
        .chain_update(client_nonce)
        .chain_update(app_nonce);
    hex(&mac.finalize().into_bytes())
}

fn mac(token: &str) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC accepts any key length")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_fresh_and_well_formed() {
        let (a, b) = (nonce().unwrap(), nonce().unwrap());
        assert!(is_nonce(&a) && is_nonce(&b));
        assert_ne!(a, b);
        assert!(!is_nonce(""));
        assert!(!is_nonce(&a.to_uppercase()));
        assert!(!is_nonce(&format!("{a}0")));
    }

    #[test]
    fn each_proof_binds_the_token_both_nonces_and_its_side() {
        let (c, a) = (nonce().unwrap(), nonce().unwrap());
        let app = app_proof("token", &c, &a);
        assert!(same(&app, &app_proof("token", &c, &a)));
        assert!(!same(&app, &app_proof("other", &c, &a)));
        assert!(!same(&app, &app_proof("token", &a, &c)));
        assert!(!same(&app, &client_proof("token", &c, &a)));
        assert!(!same(&app, &v2_proof("token", &c)));
    }

    #[test]
    fn v2_proof_is_unchanged() {
        // Clients built before protocol 3 check exactly this value.
        assert_eq!(
            v2_proof("arca-test-token", "0123456789abcdef"),
            "e7b61fca20478c27d56236c0e24e1fc97e29d2a3ed757d7a61d0cee09b66c1fc"
        );
    }
}
