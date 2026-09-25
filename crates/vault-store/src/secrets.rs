//! Generic small-secret storage in the OS secret store (macOS Keychain,
//! Windows Credential Manager, Linux Secret Service).
//!
//! Used for non-vault secrets like the Google Drive OAuth refresh token.
//! Unlike the quick-unlock device key (see [`crate::keychain`]) these are
//! stored WITHOUT a biometric access control: the background sync loop must
//! read them silently, and they only ever grant access to ciphertext.
//!
//! SECURITY: never store the master password or any vault key here.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod backend {
    use super::*;
    use security_framework::item::{ItemClass, ItemSearchOptions};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    /// Presence check WITHOUT reading the data. Reading a keychain item's data
    /// runs its ACL (and can prompt the user if the app's code signature has
    /// changed since the item was written); a metadata search does not. Use
    /// this for "is X configured?" polling.
    pub fn exists(service: &str, account: &str) -> bool {
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .search()
            .map(|r| !r.is_empty())
            .unwrap_or(false)
    }

    pub fn set(service: &str, account: &str, value: &str) -> Result<()> {
        set_generic_password(service, account, value.as_bytes()).map_err(|_| Error::Keychain)
    }

    pub fn get(service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        match get_generic_password(service, account) {
            Ok(bytes) => {
                let s = String::from_utf8(bytes).map_err(|_| Error::Keychain)?;
                Ok(Some(Zeroizing::new(s)))
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
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
mod backend {
    use super::*;

    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(service, account).map_err(|_| Error::Keychain)
    }

    pub fn set(service: &str, account: &str, value: &str) -> Result<()> {
        entry(service, account)?
            .set_password(value)
            .map_err(|_| Error::Keychain)
    }

    pub fn get(service: &str, account: &str) -> Result<Option<Zeroizing<String>>> {
        match entry(service, account)?.get_password() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
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

    /// Windows/Linux secret stores don't ACL-prompt on reads; a get IS the
    /// presence check.
    pub fn exists(service: &str, account: &str) -> bool {
        matches!(get(service, account), Ok(Some(_)))
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
    target_os = "linux"
)))]
mod backend {
    use super::*;

    pub fn set(_: &str, _: &str, _: &str) -> Result<()> {
        Err(Error::KeychainUnsupported)
    }
    pub fn get(_: &str, _: &str) -> Result<Option<Zeroizing<String>>> {
        Ok(None)
    }
    pub fn delete(_: &str, _: &str) -> Result<()> {
        Ok(())
    }
    pub fn exists(_: &str, _: &str) -> bool {
        false
    }
}

pub use backend::{delete, exists, get, set};
