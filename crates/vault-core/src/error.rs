//! Error type for `vault-core`.
//!
//! SECURITY: error messages here MUST NOT contain plaintext secrets, key
//! material, or the master password. They describe *what kind* of operation
//! failed, never *with what data*. Callers may log these freely.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The vault is locked; unlock it before performing this operation.
    #[error("vault is locked")]
    Locked,

    /// Authentication failed while unwrapping a key (wrong master password,
    /// wrong device key, or tampered ciphertext). Deliberately indistinct so
    /// it leaks nothing about *why* it failed.
    #[error("decryption failed: invalid credentials or corrupt/tampered data")]
    Decryption,

    /// Key derivation (Argon2id) failed, e.g. invalid parameters.
    #[error("key derivation failed")]
    KeyDerivation,

    /// The on-disk container is not a recognized vault.
    #[error("unrecognized or unsupported vault format")]
    Format,

    /// The vault was written by a NEWER build than this one. Distinct from
    /// [`Error::Format`] so sync layers refuse (rather than "repair"/overwrite)
    /// a legitimate newer-version peer file. The fix is updating the app.
    #[error("vault written by a newer version of the app")]
    UnsupportedVersion,

    /// (De)serialization of the vault structure failed.
    #[error("vault (de)serialization failed")]
    Serialization,

    /// No item with the given id exists.
    #[error("item not found")]
    NotFound,

    /// The operating system RNG failed to produce randomness.
    #[error("secure random generation failed")]
    Random,

    /// A TOTP secret could not be decoded (invalid Base32).
    #[error("invalid TOTP secret encoding")]
    InvalidTotpSecret,

    /// Invalid arguments supplied by the caller (e.g. password length 0).
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// A passkey operation failed (bad key material, or the item is not a
    /// passkey). Deliberately indistinct — carries no key material.
    #[error("passkey operation failed")]
    Passkey,

    /// An SSH key operation failed (bad key material, or the item is not an
    /// SSH key). Deliberately indistinct — carries no key material.
    #[error("ssh key operation failed")]
    Ssh,
}
