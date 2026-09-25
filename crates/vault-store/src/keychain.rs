//! OS keychain integration for quick/biometric unlock.
//!
//! We store a random 256-bit **device key** in the platform secret store
//! (macOS Keychain, Windows Credential Manager, Linux Secret Service). The
//! device key wraps a copy of the vault key inside the vault header, so the
//! app can unlock without re-deriving from the master password.
//!
//! On macOS this module stores a plain generic password in the login keychain
//! (app-level biometrics). Modern protected enrollments migrate to the
//! hardened data-protection keychain with `SecAccessControl` via `vault-sharedkey`
//! and `protected_unlock` (see `docs/KEYCHAIN-HARDENING.md`).
//!
//! SECURITY: the master password is **never** stored here. The device key is
//! the OS-protected unlock token; deleting the keychain entry disables quick
//! unlock entirely.

use vault_core::SymmetricKey;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Base64 (no padding) of a 32-byte key is 43 chars; sanity bound on reads.
const ENCODED_KEY_LEN: usize = 43;

/// Decode a base64 device-key string into a [`SymmetricKey`].
fn decode_key(encoded: &str) -> Result<SymmetricKey> {
    if encoded.len() != ENCODED_KEY_LEN {
        return Err(Error::Keychain);
    }
    let raw = Zeroizing::new(
        data_encoding::BASE64_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| Error::Keychain)?,
    );
    let arr: [u8; vault_core::KEY_LEN] = raw.as_slice().try_into().map_err(|_| Error::Keychain)?;
    Ok(SymmetricKey::from_bytes(arr))
}

// ---- macOS / iOS: security-framework, plain login-keychain item ------------
//
// The device key is stored as a PLAIN generic password (no per-item access
// control, no named access group), exactly like the Google refresh token in
// `secrets.rs`. This keeps it in the file-based login keychain, where access is
// governed by the app's code-signing identity — reliably readable across dev
// re-signs.
//
// An earlier design used `USER_PRESENCE` + the shared access group so the item
// carried its own Touch ID gate and the AutoFill extension could read it. That
// forces the item into the *data-protection* keychain, where a
// provisioning-profile mismatch makes the DATA unreadable even though the
// metadata search still finds it — so Touch ID fired, the read failed, and the
// app fell back to the master password on every unlock. Touch ID is now
// enforced at the app layer (`biometric::authenticate` in the `quick_unlock`
// command) on all platforms instead. When the sandboxed AutoFill extension
// ships (needs a real provisioning profile anyway), the shared-group variant
// can be reintroduced behind that entitlement.
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod backend {
    use super::*;
    use security_framework::item::{ItemClass, ItemSearchOptions};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    /// `errSecItemNotFound` — a missing item, not a failure.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    pub fn set(service: &str, account: &str, key: &SymmetricKey) -> Result<()> {
        // Replace any existing entry (add rejects a duplicate).
        let _ = delete(service, account);
        let encoded = Zeroizing::new(data_encoding::BASE64_NOPAD.encode(key.as_bytes()));
        set_generic_password(service, account, encoded.as_bytes()).map_err(|_| Error::Keychain)
    }

    pub fn get(service: &str, account: &str) -> Result<Option<SymmetricKey>> {
        // Plain read from the login keychain (no biometric prompt here; Touch ID
        // is gated at the app layer before this is called).
        match get_generic_password(service, account) {
            Ok(bytes) => {
                let encoded =
                    Zeroizing::new(String::from_utf8(bytes).map_err(|_| Error::Keychain)?);
                Ok(Some(decode_key(&encoded)?))
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(_) => Err(Error::Keychain),
        }
    }

    pub fn delete(service: &str, account: &str) -> Result<()> {
        match delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(_) => Err(Error::Keychain),
        }
    }

    /// Presence check that does NOT read the data, so it never triggers the
    /// biometric prompt (used for "is quick-unlock available?").
    pub fn exists(service: &str, account: &str) -> bool {
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .search()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    }
}

// ---- Windows / Linux: keyring native backends -----------------------------
#[cfg(any(target_os = "windows", target_os = "linux"))]
mod backend {
    use super::*;

    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(service, account).map_err(|_| Error::Keychain)
    }

    pub fn set(service: &str, account: &str, key: &SymmetricKey) -> Result<()> {
        let encoded = Zeroizing::new(data_encoding::BASE64_NOPAD.encode(key.as_bytes()));
        entry(service, account)?
            .set_password(&encoded)
            .map_err(|_| Error::Keychain)
    }

    pub fn get(service: &str, account: &str) -> Result<Option<SymmetricKey>> {
        match entry(service, account)?.get_password() {
            Ok(encoded) => {
                let encoded = Zeroizing::new(encoded);
                Ok(Some(decode_key(&encoded)?))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Error::Keychain),
        }
    }

    pub fn delete(service: &str, account: &str) -> Result<()> {
        match entry(service, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::Keychain),
        }
    }

    pub fn exists(service: &str, account: &str) -> bool {
        matches!(get(service, account), Ok(Some(_)))
    }
}

// ---- Fallback: quick-unlock unavailable -----------------------------------
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux"
)))]
mod backend {
    use super::*;

    pub fn set(_: &str, _: &str, _: &SymmetricKey) -> Result<()> {
        Err(Error::KeychainUnsupported)
    }
    pub fn get(_: &str, _: &str) -> Result<Option<SymmetricKey>> {
        Ok(None)
    }
    pub fn delete(_: &str, _: &str) -> Result<()> {
        Ok(())
    }
    pub fn exists(_: &str, _: &str) -> bool {
        false
    }
}

pub(crate) use backend::{delete, exists, get, set};
