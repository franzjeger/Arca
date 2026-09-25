//! Versioned vault header.
//!
//! The header is stored in cleartext (it contains no secrets — only public
//! KDF parameters and *wrapped* keys) and is what lets the on-disk format
//! evolve over time. Bump [`VaultHeader::FORMAT_VERSION`] and handle older
//! values in [`crate::vault::Vault::from_bytes`] when the layout changes.

use serde::{Deserialize, Serialize};

use crate::crypto::{self, AeadBlob};
use crate::error::{Error, Result};

/// KDF algorithm identifier. Stored numerically so the enum can grow without
/// breaking serialized vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KdfAlgorithm {
    Argon2id = 1,
    // TODO(phase-2+): add e.g. scrypt/balloon if ever needed; never remove a
    // variant, only deprecate, so old vaults stay readable.
}

/// Public, per-vault key-derivation parameters. Safe to store in cleartext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    /// Argon2id memory cost, in KiB.
    pub m_cost_kib: u32,
    /// Argon2id iteration (time) cost.
    pub t_cost: u32,
    /// Argon2id parallelism (lanes).
    pub p_cost: u32,
    /// Per-vault random salt.
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Default Argon2id cost parameters per the project spec:
    /// m = 64 MiB, t = 3, p = 4.
    pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
    pub const DEFAULT_T_COST: u32 = 3;
    pub const DEFAULT_P_COST: u32 = 4;
    pub const SALT_LEN: usize = 32;
    /// Highest Argon2 memory cost accepted from a vault header (256 MiB).
    pub const MAX_M_COST_KIB: u32 = 256 * 1024;
    /// Highest Argon2 iteration count accepted from a vault header.
    pub const MAX_T_COST: u32 = 10;
    /// Highest Argon2 lane count accepted from a vault header.
    pub const MAX_P_COST: u32 = 16;

    /// Build default parameters with a fresh random salt.
    pub fn new_default() -> Result<Self> {
        let mut salt = vec![0u8; Self::SALT_LEN];
        crypto::fill_random(&mut salt)?;
        Ok(Self {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: Self::DEFAULT_M_COST_KIB,
            t_cost: Self::DEFAULT_T_COST,
            p_cost: Self::DEFAULT_P_COST,
            salt,
        })
    }

    /// Validate public KDF parameters before they reach Argon2.
    ///
    /// Vault headers can come from removable media or a sync peer. Bounding
    /// these values keeps a forged header from turning unlock into an
    /// attacker-controlled memory/CPU exhaustion operation.
    pub fn validate(&self) -> Result<()> {
        let minimum_memory = self.p_cost.saturating_mul(8);
        if self.salt.len() != Self::SALT_LEN
            || self.t_cost == 0
            || self.t_cost > Self::MAX_T_COST
            || self.p_cost == 0
            || self.p_cost > Self::MAX_P_COST
            || self.m_cost_kib < minimum_memory
            || self.m_cost_kib > Self::MAX_M_COST_KIB
        {
            return Err(Error::InvalidArgument("invalid KDF parameters"));
        }
        Ok(())
    }

    /// Stable byte encoding of the parameters, used as AEAD AAD when wrapping
    /// the vault key. Binding the wrap to these bytes means an attacker cannot
    /// substitute weaker KDF parameters and have the wrap still authenticate.
    pub(crate) fn aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(13 + self.salt.len());
        v.push(self.algorithm as u8);
        v.extend_from_slice(&self.m_cost_kib.to_le_bytes());
        v.extend_from_slice(&self.t_cost.to_le_bytes());
        v.extend_from_slice(&self.p_cost.to_le_bytes());
        v.extend_from_slice(&self.salt);
        v
    }
}

/// The cleartext vault header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultHeader {
    /// On-disk format version; see [`VaultHeader::FORMAT_VERSION`].
    pub format_version: u16,
    /// KDF parameters used to derive the master key.
    pub kdf: KdfParams,
    /// The vault key, wrapped under the master-password-derived key.
    pub master_wrapped_vault_key: AeadBlob,
    /// The vault key, wrapped under an OS-keychain-held device key, enabling
    /// quick/biometric unlock. `None` until the user opts in. The device key
    /// itself lives only in the OS keychain (see `vault-store`).
    pub device_wrapped_vault_key: Option<AeadBlob>,
    /// Monotonic master-rewrap epoch: bumped on every master-password change
    /// (or future KDF hardening). Sync merges adopt the header with the HIGHER
    /// epoch, so a rotation done on one device propagates instead of being
    /// reverted by a peer's stale header. Legacy (v2) files load as epoch 0.
    pub rewrap_epoch: u64,
}

impl VaultHeader {
    /// Check a password against an already authenticated header. This checks
    /// the key wrap only; loading an untrusted file still requires Vault::unlock.
    pub fn check_master_password(&self, password: &str) -> bool {
        crypto::derive_master_key(password, &self.kdf)
            .and_then(|key| {
                crypto::unwrap_key(&key, &self.master_wrapped_vault_key, &self.kdf.aad())
            })
            .is_ok()
    }
    /// Current on-disk format version understood by this build.
    ///
    /// v1 (never released with real data): item payloads encoded with bincode.
    /// v2: item payloads encoded with self-describing, name-tagged CBOR so the
    ///     `VaultItem` schema can evolve safely.
    /// v3: header gains `rewrap_epoch` (new `SYBRVLT2` container magic — the
    ///     outer bincode framing is positional, so the header change needs its
    ///     own container version; v2 files are still read transparently).
    /// v4: item payloads carry encrypted revision ancestry; `SYBRVLT4` prevents
    ///     older clients from silently accepting and then stripping it.
    /// v5: the complete container carries a vault-key authentication tag.
    pub const FORMAT_VERSION: u16 = 5;

    /// Validate that this build can read the header.
    pub(crate) fn check_supported(&self) -> Result<()> {
        if self.format_version == 0 {
            return Err(Error::Format);
        }
        if self.format_version > Self::FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        // A malformed untrusted header is a format error; do not start Argon2
        // with its attacker-selected resource costs.
        self.kdf.validate().map_err(|_| Error::Format)?;
        Ok(())
    }
}

/// The v2 header layout exactly as `SYBRVLT1` containers serialized it
/// (bincode is positional: the legacy struct must match field-for-field).
#[derive(Deserialize)]
pub(crate) struct LegacyHeaderV2 {
    pub format_version: u16,
    pub kdf: KdfParams,
    pub master_wrapped_vault_key: AeadBlob,
    pub device_wrapped_vault_key: Option<AeadBlob>,
}

impl From<LegacyHeaderV2> for VaultHeader {
    fn from(h: LegacyHeaderV2) -> Self {
        Self {
            format_version: h.format_version,
            kdf: h.kdf,
            master_wrapped_vault_key: h.master_wrapped_vault_key,
            device_wrapped_vault_key: h.device_wrapped_vault_key,
            rewrap_epoch: 0,
        }
    }
}
