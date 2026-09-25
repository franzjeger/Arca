//! Secret key material wrappers.
//!
//! These newtypes zeroize their bytes on drop and refuse to print their
//! contents via `Debug`. Equality, where needed, is constant-time.

use core::fmt;

use subtle::ConstantTimeEq;
use vault_secmem::SecretBytes;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Length of every symmetric key used in the crate (256-bit).
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key. Its bytes live in locked memory (mlock/VirtualLock
/// where the OS allows, so they can't be paged to swap) and are zeroized on
/// drop.
///
/// There is intentionally no `Serialize`/`Display`/non-redacting `Debug`
/// implementation: a raw key must never be persisted or logged. Keys are only
/// ever stored *wrapped* (see [`crate::header::WrappedKey`]).
#[derive(Clone)]
pub struct SymmetricKey(SecretBytes);

impl SymmetricKey {
    /// Wrap raw key bytes, copying them into locked memory and wiping the
    /// caller's array.
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let key = Self(SecretBytes::from_slice(&bytes));
        bytes.zeroize();
        key
    }

    /// Generate a fresh random key from the OS CSPRNG, straight into locked
    /// memory.
    pub fn generate() -> Result<Self> {
        let mut buf = SecretBytes::zeroed(KEY_LEN);
        getrandom::getrandom(buf.as_mut_slice()).map_err(|_| Error::Random)?;
        Ok(Self(buf))
    }

    /// Borrow the raw bytes. Callers must not copy these into long-lived,
    /// non-zeroizing buffers.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0
            .as_slice()
            .try_into()
            .expect("SymmetricKey always holds KEY_LEN bytes")
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never reveal key material.
        f.write_str("SymmetricKey(<redacted>)")
    }
}

impl ConstantTimeEq for SymmetricKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

impl PartialEq for SymmetricKey {
    /// Constant-time equality so callers cannot accidentally introduce a
    /// timing side-channel by comparing keys with `==`.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SymmetricKey {}
