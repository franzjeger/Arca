//! Mirror Arca's device key into the keychain group the macOS AutoFill
//! extension reads.
//!
//! The app's own device key lives as a plain item in the file-based login
//! keychain, for reasons `vault-store`'s keychain module explains at length. A
//! sandboxed extension cannot read that keychain, so the same key is also
//! written to the data-protection keychain under the shared access group.
//!
//! Two copies of one secret, with one rule: this copy is the extension's
//! problem alone. Every call here returns a status the caller is expected to
//! log and continue past, because a broken credential provider must never stop
//! the app from unlocking.
//!
//! The Objective-C shim is in `src/sharedkey.m`.

#![cfg_attr(not(target_os = "macos"), allow(unused))]

use std::fmt;

/// What happened to the mirrored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mirrored {
    /// Written; the extension can open the vault after a biometric.
    Ok,
    /// The keychain refused, with this `OSStatus`. AutoFill will fail with
    /// `noDeviceKey`; nothing else is affected.
    Failed(i32),
    /// Not macOS — there is no shared keychain group to mirror into.
    NotApplicable,
}

impl fmt::Display for Mirrored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mirrored::Ok => write!(f, "device key shared with AutoFill"),
            // -34018 is the one worth recognising on sight: it means the
            // process has no keychain-access-group entitlement, i.e. it was
            // signed without the profile rather than anything being wrong with
            // the key.
            Mirrored::Failed(-34018) => {
                write!(
                    f,
                    "no keychain access group (app signed without the profile)"
                )
            }
            Mirrored::Failed(status) => write!(f, "keychain refused the device key ({status})"),
            Mirrored::NotApplicable => write!(f, "no shared keychain on this platform"),
        }
    }
}

/// Write `key` into the shared group, replacing any previous copy.
///
/// `key` must be the RAW device key. The extension hands these bytes straight
/// to `vault_ffi_vault_open_device`; the base64 the login-keychain copy uses
/// would decrypt nothing.
#[cfg(target_os = "macos")]
pub fn store(key: &[u8]) -> Mirrored {
    extern "C" {
        fn arca_sharedkey_store(key: *const u8, len: std::os::raw::c_ulong) -> i32;
    }
    // SAFETY: `key` is a valid slice that outlives the call; the callee only
    // reads `len` bytes from it and returns an OSStatus.
    match unsafe { arca_sharedkey_store(key.as_ptr(), key.len() as std::os::raw::c_ulong) } {
        0 => Mirrored::Ok,
        status => Mirrored::Failed(status),
    }
}

/// Delete the item written by the one build that gave the extension's key the
/// same service+account as the app's own login-keychain key.
///
/// That collision made the app's `keychain::get` resolve to an
/// access-controlled item it was not built to read: Touch ID fired repeatedly
/// and the unlock fell back to the master password every time. Called at
/// startup so a machine that ran that build heals itself.
#[cfg(target_os = "macos")]
pub fn purge_legacy() -> Mirrored {
    extern "C" {
        fn arca_sharedkey_purge_legacy() -> i32;
    }
    // SAFETY: no arguments, no borrowed state; returns an OSStatus.
    match unsafe { arca_sharedkey_purge_legacy() } {
        0 => Mirrored::Ok,
        status => Mirrored::Failed(status),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn purge_legacy() -> Mirrored {
    Mirrored::NotApplicable
}

/// Remove the shared copy. Missing is success.
#[cfg(target_os = "macos")]
pub fn clear() -> Mirrored {
    extern "C" {
        fn arca_sharedkey_clear() -> i32;
    }
    // SAFETY: no arguments, no borrowed state; returns an OSStatus.
    match unsafe { arca_sharedkey_clear() } {
        0 => Mirrored::Ok,
        status => Mirrored::Failed(status),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn store(_key: &[u8]) -> Mirrored {
    Mirrored::NotApplicable
}

#[cfg(not(target_os = "macos"))]
pub fn clear() -> Mirrored {
    Mirrored::NotApplicable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entitlement_failure_is_named_rather_than_numbered() {
        // -34018 sends people looking for a corrupt keychain when the actual
        // cause is a build signed without the provisioning profile. It cost an
        // evening once already; the message says so now.
        assert!(Mirrored::Failed(-34018).to_string().contains("profile"));
        assert!(Mirrored::Failed(-25300).to_string().contains("-25300"));
    }
}

/// Explicit desktop data-protection keychain operations. No login-keychain fallback.
#[cfg(target_os = "macos")]
pub mod protected {
    use std::ffi::CString;
    use zeroize::Zeroizing;

    unsafe extern "C" {
        fn arca_protected_create(account: *const std::ffi::c_char, key: *const u8) -> i32;
        fn arca_protected_read(
            account: *const std::ffi::c_char,
            key: *mut u8,
            interactive: i32,
        ) -> i32;
        fn arca_protected_exists(account: *const std::ffi::c_char) -> i32;
        fn arca_protected_delete(account: *const std::ffi::c_char) -> i32;
    }
    fn account(value: &str) -> Result<CString, i32> {
        if !value.starts_with("desktop-protected-") {
            return Err(-50);
        }
        CString::new(value).map_err(|_| -50)
    }
    fn result(status: i32) -> Result<(), i32> {
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }
    pub fn create(name: &str, key: &[u8; 32]) -> Result<(), i32> {
        let name = account(name)?;
        // SAFETY: both pointers remain valid during this synchronous call; the key is 32 bytes.
        result(unsafe { arca_protected_create(name.as_ptr(), key.as_ptr()) })
    }
    pub fn read(name: &str) -> Result<Zeroizing<[u8; 32]>, i32> {
        let name = account(name)?;
        let mut key = Zeroizing::new([0u8; 32]);
        // SAFETY: the output has exactly the 32 writable bytes required by the shim.
        result(unsafe { arca_protected_read(name.as_ptr(), key.as_mut_ptr(), 1) })?;
        Ok(key)
    }
    pub fn exists(name: &str) -> Result<bool, i32> {
        let name = account(name)?;
        // SAFETY: the null-terminated account outlives the synchronous call.
        match unsafe { arca_protected_exists(name.as_ptr()) } {
            0 => Ok(true),
            -25300 => Ok(false),
            status => Err(status),
        }
    }
    pub fn delete(name: &str) -> Result<(), i32> {
        let name = account(name)?;
        // SAFETY: the null-terminated account outlives the synchronous call.
        result(unsafe { arca_protected_delete(name.as_ptr()) })
    }
}
