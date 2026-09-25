//! Errors for the persistence layer. As in `vault-core`, messages never carry
//! secret material.

use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying vault-core failure (crypto, format, locked, ...).
    #[error(transparent)]
    Core(#[from] vault_core::Error),

    /// Filesystem error while reading or atomically writing the vault file.
    #[error("vault file I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The OS keychain/secret-store operation failed.
    #[error("OS keychain operation failed")]
    Keychain,

    /// This platform has no supported secret store for quick-unlock.
    #[error("quick-unlock is not supported on this platform")]
    KeychainUnsupported,

    /// Quick-unlock was requested but no device key is stored.
    #[error("quick-unlock is not enabled")]
    QuickUnlockNotEnabled,

    /// A restore named a file that is not one of this vault's snapshots, or it
    /// could not be read. Restoring overwrites the live vault, so anything we
    /// cannot positively identify as our own snapshot is refused.
    #[error("not a snapshot of this vault")]
    SnapshotNotFound,
}
