//! The [`Vault`]: a locked/unlocked state machine over an encrypted item set.
//!
//! On-disk layout produced by [`Vault::to_bytes`]:
//! ```text
//! "SYBRVLT5"            (8-byte magic; V4, V3, V2 and V1 remain readable)
//! bincode(VaultBody {   (cleartext header + per-item ciphertext)
//!     header,
//!     items: [ { id, AeadBlob }, ... ],
//!     purges: [ { id, at }, ... ],
//! })
//! HMAC-SHA256(vault_key, context || bincode(body))
//! ```
//! The header is cleartext (public KDF params + wrapped keys); every item is
//! sealed individually with the vault key, with the item id bound as AAD.
//!
//! `purges` is cleartext but authenticated by the container tag: it records a
//! hard delete, so a peer that still has the item cannot push it back. See
//! [`crate::sync::Purge`].

use crate::VaultItem;
use bincode::Options;
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, AeadBlob};
use crate::error::{Error, Result};
use crate::header::{KdfParams, VaultHeader};
use crate::item::{Item, ItemSummary};
use crate::secret::SymmetricKey;
use crate::sync::Purge;

/// Container magics. V1 framed the v2 header (no rewrap epoch); V2 added the
/// rewrap epoch; V3 adds the purge list; V4 gates encrypted per-item revision
/// ancestry so older clients cannot silently strip conflict metadata. V5 adds
/// whole-container authentication. Legacy files upgrade on an unlocked save.
const MAGIC_V1: &[u8; 8] = b"SYBRVLT1";
const MAGIC_V2: &[u8; 8] = b"SYBRVLT2";
const MAGIC_V3: &[u8; 8] = b"SYBRVLT3";
const MAGIC_V4: &[u8; 8] = b"SYBRVLT4";
const MAGIC: &[u8; 8] = b"SYBRVLT5";
const AUTH_CONTEXT: &[u8] = b"arca/vault-container/SYBRVLT5\0";
const AUTH_LEN: usize = 32;

/// Long enough for months of edits while keeping malicious synced payloads
/// from growing without bound. Losing very old ancestry can create a harmless
/// extra conflict copy; it cannot discard an item.
pub(crate) const MAX_REVISION_ANCESTORS: usize = 64;

/// Maximum serialized vault size accepted or emitted by the core (128 MiB).
/// This is deliberately generous for a password database while bounding
/// allocations driven by an untrusted local or synced file.
pub const MAX_VAULT_BYTES: usize = 128 * 1024 * 1024;

/// Fixed AAD context for the device-key (quick-unlock) wrap.
const DEVICE_UNLOCK_AAD: &[u8] = b"sybr-vault/device-unlock/v1";

/// A single encrypted item as stored on disk: cleartext id + sealed payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedItem {
    id: Uuid,
    blob: AeadBlob,
}

/// The serialized body following the magic bytes.
#[derive(Serialize, Deserialize)]
struct VaultBody {
    header: VaultHeader,
    items: Vec<EncryptedItem>,
    purges: Vec<Purge>,
}

/// Body layout of `SYBRVLT2` containers: the current header, no purge list.
#[derive(Deserialize)]
struct BodyWithoutPurges {
    header: VaultHeader,
    items: Vec<EncryptedItem>,
}

/// Body layout of legacy `SYBRVLT1` containers (v2 header, positionally exact).
#[derive(Deserialize)]
struct LegacyBodyV2 {
    header: crate::header::LegacyHeaderV2,
    items: Vec<EncryptedItem>,
}

/// In-memory vault state. When unlocked, decrypted items and the vault key are
/// held in memory and zeroized on transition back to locked / on drop.
#[derive(Clone)]
enum VaultState {
    Locked {
        items: Vec<EncryptedItem>,
    },
    Unlocked {
        vault_key: SymmetricKey,
        items: Vec<Item>,
    },
}

fn deserialize_body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit((MAX_VAULT_BYTES - MAGIC.len()) as u64)
        .deserialize(bytes)
        .map_err(|_| Error::Serialization)
}

/// A password vault. Create a new one with [`Vault::create`], or load an
/// existing (locked) one with [`Vault::from_bytes`] then [`Vault::unlock`].
#[derive(Clone)]
pub struct Vault {
    /// Process-local unlock generation. Never serialized or synced.
    session_id: Uuid,
    header: VaultHeader,
    /// Hard deletes, so emptying the Trash survives a merge. Outside
    /// [`VaultState`] because it is not secret and must persist while locked.
    purges: Vec<Purge>,
    /// Authenticates the complete locked body, including empty vaults, purges
    /// and password rotations. Unlocked bodies are signed when serialized.
    authentication: Option<[u8; AUTH_LEN]>,
    state: VaultState,
}

impl Vault {
    // ----- lifecycle ------------------------------------------------------

    /// Create a brand-new, unlocked vault protected by `master_password`.
    pub fn create(master_password: &str, params: KdfParams) -> Result<Self> {
        let master_key = crypto::derive_master_key(master_password, &params)?;
        let vault_key = SymmetricKey::generate()?;
        let master_wrapped_vault_key = crypto::wrap_key(&master_key, &vault_key, &params.aad())?;

        let header = VaultHeader {
            format_version: VaultHeader::FORMAT_VERSION,
            kdf: params,
            master_wrapped_vault_key,
            device_wrapped_vault_key: None,
            rewrap_epoch: 0,
        };

        Ok(Self {
            session_id: Uuid::new_v4(),
            header,
            purges: Vec::new(),
            authentication: None,
            state: VaultState::Unlocked {
                vault_key,
                items: Vec::new(),
            },
        })
    }

    /// Parse a locked vault from its serialized bytes. Does not require the
    /// master password; the result is locked until [`Vault::unlock`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() || bytes.len() > MAX_VAULT_BYTES {
            return Err(Error::Format);
        }
        let mut authentication = None;
        let (header, items, purges) = match &bytes[..MAGIC.len()] {
            m if m == MAGIC => {
                if bytes.len() < MAGIC.len() + AUTH_LEN {
                    return Err(Error::Decryption);
                }
                let split = bytes.len() - AUTH_LEN;
                let body: VaultBody = bincode::DefaultOptions::new()
                    .with_fixint_encoding()
                    .reject_trailing_bytes()
                    .with_limit(MAX_VAULT_BYTES as u64)
                    .deserialize(&bytes[MAGIC.len()..split])
                    .map_err(|_| Error::Decryption)?;
                authentication = Some(bytes[split..].try_into().map_err(|_| Error::Decryption)?);
                (body.header, body.items, body.purges)
            }
            m if m == MAGIC_V4 || m == MAGIC_V3 => {
                let body: VaultBody = deserialize_body(&bytes[MAGIC.len()..])?;
                (body.header, body.items, body.purges)
            }
            m if m == MAGIC_V2 => {
                // Written before hard deletes left a record. An empty purge
                // list is the truth about such a file, not a fallback.
                let body: BodyWithoutPurges = deserialize_body(&bytes[MAGIC.len()..])?;
                (body.header, body.items, Vec::new())
            }
            m if m == MAGIC_V1 => {
                // Legacy container: v2 header without the rewrap epoch.
                let body: LegacyBodyV2 = deserialize_body(&bytes[MAGIC.len()..])?;
                (body.header.into(), body.items, Vec::new())
            }
            // A container we do not know. Whether it is *ours* matters enormously:
            // callers treat `Format` as a torn upload and replace the file with
            // their own copy, which for a vault written by a NEWER Arca would
            // destroy every change it holds. Every container we have ever
            // written starts `SYBRVLT`, so that prefix means "newer than me",
            // not "garbage" — and refusing costs a sync error, while guessing
            // wrong costs data.
            m if m.starts_with(b"SYBRVLT") => return Err(Error::UnsupportedVersion),
            _ => return Err(Error::Format),
        };
        header.check_supported()?;
        // Changing only the magic must not strip the integrity requirement.
        if authentication.is_none() && header.format_version >= 5 {
            return Err(Error::Decryption);
        }
        Ok(Self {
            session_id: Uuid::nil(),
            header,
            purges,
            authentication,
            state: VaultState::Locked { items },
        })
    }

    /// Serialize the vault to bytes for persistence. Always emits ciphertext;
    /// when unlocked, items are re-sealed with fresh nonces.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let items = match &self.state {
            VaultState::Locked { items } => items.clone(),
            VaultState::Unlocked { vault_key, items } => encrypt_items(vault_key, items)?,
        };
        let mut header = self.header.clone();
        let authenticated = self.is_unlocked() || self.authentication.is_some();
        if authenticated {
            header.format_version = VaultHeader::FORMAT_VERSION;
        }
        let body = VaultBody {
            header,
            items,
            purges: self.purges.clone(),
        };
        let mut out = Vec::with_capacity(MAGIC.len() + 64);
        // A locked legacy copy cannot be authenticated without its key. Keep
        // it readable; the first unlocked save upgrades it.
        out.extend_from_slice(if authenticated { MAGIC } else { MAGIC_V4 });
        let encoded = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit((MAX_VAULT_BYTES - MAGIC.len() - AUTH_LEN) as u64)
            .serialize(&body)
            .map_err(|_| Error::Serialization)?;
        out.extend_from_slice(&encoded);
        match &self.state {
            VaultState::Unlocked { vault_key, .. } => {
                out.extend_from_slice(&authenticate_body(vault_key, &encoded));
            }
            VaultState::Locked { .. } => {
                if let Some(tag) = self.authentication {
                    out.extend_from_slice(&tag);
                }
            }
        }
        Ok(out)
    }

    // ----- locking --------------------------------------------------------

    /// Unlock with the master password. Decrypts the vault key and all items.
    /// Returns [`Error::Decryption`] for a wrong password or tampered data.
    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }
        let master_key = crypto::derive_master_key(master_password, &self.header.kdf)?;
        let vault_key = crypto::unwrap_key(
            &master_key,
            &self.header.master_wrapped_vault_key,
            &self.header.kdf.aad(),
        )?;
        self.finish_unlock(vault_key)
    }

    /// Verify the master password WITHOUT changing lock state. Returns `true`
    /// when the password correctly re-derives and unwraps the vault key. Used
    /// for re-authentication (user verification) while the vault is already
    /// unlocked — e.g. approving a passkey ceremony, where a correct password is
    /// a genuine user-verification factor.
    pub fn verify_master_password(&self, master_password: &str) -> bool {
        let Ok(master_key) = crypto::derive_master_key(master_password, &self.header.kdf) else {
            return false;
        };
        let Ok(candidate) = crypto::unwrap_key(
            &master_key,
            &self.header.master_wrapped_vault_key,
            &self.header.kdf.aad(),
        ) else {
            return false;
        };
        match &self.state {
            VaultState::Unlocked { vault_key, .. } => candidate == *vault_key,
            VaultState::Locked { .. } => self.verify_authentication(&candidate).is_ok(),
        }
    }

    /// Unlock using a device key fetched from the OS keychain (quick/biometric
    /// unlock). Fails if quick-unlock was never enabled.
    pub fn unlock_with_device_key(&mut self, device_key: &SymmetricKey) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }
        let wrapped = self
            .header
            .device_wrapped_vault_key
            .clone()
            .ok_or(Error::Decryption)?;
        let vault_key = crypto::unwrap_key(device_key, &wrapped, DEVICE_UNLOCK_AAD)?;
        self.finish_unlock(vault_key)
    }

    /// Common tail of the two unlock paths: decrypt items, transition state.
    fn finish_unlock(&mut self, vault_key: SymmetricKey) -> Result<()> {
        self.verify_authentication(&vault_key)?;
        let items = match &self.state {
            VaultState::Locked { items } => decrypt_items(&vault_key, items)?,
            // unreachable: callers guard on `is_unlocked()` first.
            VaultState::Unlocked { .. } => return Ok(()),
        };
        self.state = VaultState::Unlocked { vault_key, items };
        self.session_id = Uuid::new_v4();
        Ok(())
    }

    /// Lock the vault: re-seal current items and drop (zeroize) the vault key
    /// and plaintext items.
    pub fn lock(&mut self) -> Result<()> {
        if let VaultState::Unlocked { vault_key, items } = &self.state {
            // Encrypt before changing state. If serialization or randomness
            // fails, keeping the still-unlocked state is safer than silently
            // replacing the user's item set with an empty locked vault.
            let resealed = encrypt_items(vault_key, items)?;
            let mut header = self.header.clone();
            header.format_version = VaultHeader::FORMAT_VERSION;
            let body = bincode::serialize(&VaultBody {
                header: header.clone(),
                items: resealed.clone(),
                purges: self.purges.clone(),
            })
            .map_err(|_| Error::Serialization)?;
            let tag = authenticate_body(vault_key, &body);
            // Reassigning drops the old Unlocked state → key + plaintext zeroized.
            self.state = VaultState::Locked { items: resealed };
            self.header = header;
            self.authentication = Some(tag);
        }
        Ok(())
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, VaultState::Unlocked { .. })
    }

    /// Bind a pending user authorization to this particular unlocked session.
    pub fn session_id(&self) -> Option<Uuid> {
        self.is_unlocked().then_some(self.session_id)
    }

    // ----- item operations (require unlocked) -----------------------------

    /// Summaries for list rendering. Pass `include_deleted = true` for the
    /// Trash view.
    pub fn list_items(&self, include_deleted: bool) -> Result<Vec<ItemSummary>> {
        let items = self.unlocked_items()?;
        Ok(items
            .iter()
            .filter(|i| include_deleted || !i.is_deleted())
            .map(Item::summary)
            .collect())
    }

    /// Password-health audit (weak/reused) over the active login items.
    /// Requires the vault to be unlocked.
    pub fn security_report(&self) -> Result<Vec<crate::security::ItemSecurity>> {
        Ok(crate::security::audit(self.unlocked_items()?))
    }

    /// Fetch a full (decrypted) item by id. The returned clone carries
    /// plaintext secrets and zeroizes on drop.
    pub fn get_item(&self, id: Uuid) -> Result<Item> {
        self.unlocked_items()?
            .iter()
            .find(|i| i.id == id)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// Merge the items from another serialized vault file (a synced peer) into
    /// this unlocked vault, keeping the most-recently-changed version of each
    /// item (see [`crate::sync::merge`]).
    ///
    /// The peer's items are decrypted with *this* vault's key — valid because a
    /// synced vault shares one stable vault key across devices. A decryption
    /// failure therefore means the file is a *different* vault, and the merge is
    /// refused ([`Error::Decryption`]) rather than silently importing garbage.
    /// Requires this vault to be unlocked.
    pub fn merge_remote(&mut self, remote_bytes: &[u8]) -> Result<()> {
        let remote = Self::from_bytes(remote_bytes)?;
        let vault_key = self.vault_key()?;
        remote.verify_authentication(vault_key)?;
        if remote.authentication.is_none() {
            // Legacy item ciphertext can still be authenticated individually.
            // Destructive metadata cannot: only accept purge records already
            // known locally, and never adopt an unsigned password rotation.
            if remote.header.rewrap_epoch > self.header.rewrap_epoch
                || remote.purges.iter().any(|purge| {
                    !self
                        .purges
                        .iter()
                        .any(|known| known.id == purge.id && known.at >= purge.at)
                })
            {
                return Err(Error::Decryption);
            }
            // Even an empty legacy file must belong to this vault. An exact
            // master wrap proves it was copied from the same header; any new
            // rotation needs the authenticated format above.
            if remote.header.master_wrapped_vault_key.nonce
                != self.header.master_wrapped_vault_key.nonce
                || remote.header.master_wrapped_vault_key.ciphertext
                    != self.header.master_wrapped_vault_key.ciphertext
            {
                return Err(Error::Decryption);
            }
        }
        let remote_header = remote.header;
        let remote_purges = remote.purges;
        let remote_enc = match remote.state {
            VaultState::Locked { items } => items,
            // `from_bytes` always yields a locked vault.
            VaultState::Unlocked { .. } => return Err(Error::Format),
        };
        let VaultState::Unlocked { vault_key, items } = &mut self.state else {
            return Err(Error::Locked);
        };
        let remote_items = decrypt_items(vault_key, &remote_enc)?;
        // Purges first, then applied to the union: a hard delete on either side
        // has to reach items that only the other side still had.
        self.purges = crate::sync::merge_purges(core::mem::take(&mut self.purges), remote_purges);
        let local = core::mem::take(items);
        *items = crate::sync::apply_purges(
            crate::sync::merge_versioned(local, remote_items),
            &self.purges,
        );
        // Header: adopt a NEWER master rewrap (password rotation / KDF upgrade)
        // from the peer. The vault key itself never changes on rotation, so the
        // local device wrap stays valid and is kept.
        if remote_header.rewrap_epoch > self.header.rewrap_epoch {
            self.header.kdf = remote_header.kdf;
            self.header.master_wrapped_vault_key = remote_header.master_wrapped_vault_key;
            self.header.rewrap_epoch = remote_header.rewrap_epoch;
        }
        Ok(())
    }

    /// Merge duplicate active logins (same host + username): the newest wins,
    /// TOTP/notes are adopted, losers are soft-deleted. Returns how many items
    /// were merged away. Requires the vault to be unlocked.
    pub fn merge_duplicate_logins(&mut self, now_unix_millis: i64) -> Result<usize> {
        let before = self.unlocked_items()?.clone();
        let merged =
            crate::dedupe::merge_duplicate_logins(self.unlocked_items_mut()?, now_unix_millis);
        let changed: Vec<Uuid> = self
            .unlocked_items()?
            .iter()
            .filter(|item| before.iter().find(|old| old.id == item.id) != Some(*item))
            .map(|item| item.id)
            .collect();
        for id in changed {
            self.advance_revision(id)?;
        }
        Ok(merged)
    }

    /// Insert a new item or replace an existing one with the same id.
    pub fn upsert_item(&mut self, mut item: Item) -> Result<()> {
        if item.revision.is_nil() {
            item.revision = Uuid::new_v4();
            item.revision_ancestors.clear();
        }
        let id = item.id;
        let existed = {
            let items = self.unlocked_items_mut()?;
            match items.iter_mut().find(|i| i.id == id) {
                Some(existing) => {
                    item.retain_password_history(existing, true);
                    if item.sync_conflict.is_none() {
                        item.sync_conflict = existing.sync_conflict.clone();
                    }
                    // Revision state belongs to the vault's current copy, not
                    // to a DTO a caller reconstructed while editing it.
                    let revision = existing.revision;
                    let ancestors = core::mem::take(&mut existing.revision_ancestors);
                    *existing = item;
                    existing.revision = revision;
                    existing.revision_ancestors = ancestors;
                    true
                }
                None => {
                    items.push(item);
                    false
                }
            }
        };
        if existed {
            self.advance_revision(id)?;
        }
        Ok(())
    }

    /// Restore just a password; the current password becomes another history
    /// entry. Site/account, TOTP, notes and every other item remain untouched.
    pub fn restore_password(&mut self, id: Uuid, revision: Uuid, now: i64) -> Result<()> {
        let mut item = self.get_item(id)?;
        let old = item
            .password_history
            .iter()
            .find(|h| h.id == revision)
            .ok_or(Error::NotFound)?
            .password
            .clone();
        match &mut item.data {
            VaultItem::Login { password, .. } | VaultItem::Wifi { password, .. } => *password = old,
            _ => return Err(Error::InvalidArgument("This item has no password history.")),
        }
        item.modified_at = now;
        self.upsert_item(item)
    }

    /// Keep a conflict copy independently, including when its original was
    /// purged. This changes only the conflict marker and generated title suffix.
    pub fn keep_sync_conflict_copy(&mut self, copy_id: Uuid, now: i64) -> Result<()> {
        let mut copy = self.get_item(copy_id)?;
        if !copy.is_sync_conflict() {
            return Err(Error::InvalidArgument(
                "This entry is no longer an unresolved conflict.",
            ));
        }
        let title = crate::conflicts::original_copy_title(&copy);
        let mut link = copy
            .sync_conflict
            .clone()
            .unwrap_or(crate::item::SyncConflict {
                original_id: Uuid::nil(),
                original_title: title.clone(),
                resolved: false,
            });
        link.resolved = true;
        copy.sync_conflict = Some(link);
        crate::conflicts::set_title(&mut copy.data, title);
        copy.modified_at = now;
        self.upsert_item(copy)
    }

    /// Apply the exact comparison the user reviewed. Both inputs are retained
    /// in Trash when combining/replacing; choosing both simply dismisses the
    /// conflict marker. A changed input requires a fresh comparison.
    pub fn resolve_sync_conflict(
        &mut self,
        original_id: Uuid,
        copy_id: Uuid,
        revisions: (Uuid, Uuid),
        action: crate::conflicts::Resolution,
        fields: &[String],
        now: i64,
    ) -> Result<()> {
        use crate::conflicts::{self, Resolution};
        let mut original = self.get_item(original_id)?;
        let mut copy = self.get_item(copy_id)?;
        conflicts::validate_pair(&original, &copy)?;
        if (original.revision, copy.revision) != revisions {
            return Err(Error::InvalidArgument(
                "These entries changed. Refresh the comparison before resolving.",
            ));
        }
        let copy_title = conflicts::original_copy_title(&copy);
        let mut link = copy
            .sync_conflict
            .clone()
            .unwrap_or(crate::item::SyncConflict {
                original_id,
                original_title: copy_title.clone(),
                resolved: false,
            });
        link.resolved = true;
        if action == Resolution::KeepBoth {
            conflicts::set_title(&mut copy.data, copy_title);
            copy.sync_conflict = Some(link);
            copy.modified_at = now;
            return self.upsert_item(copy);
        }
        let selected = match action {
            Resolution::UseCopy => conflicts::field_keys(original.data.kind())
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            Resolution::Merge => fields.to_vec(),
            _ => Vec::new(),
        };
        // Validate all requested fields before performing any mutation.
        let merged = conflicts::merge_payload(&original, &copy, &selected)?;
        if action != Resolution::KeepOriginal {
            let mut archive = original.clone();
            archive.id = Uuid::new_v4();
            archive.revision = Uuid::new_v4();
            archive.revision_ancestors.clear();
            archive.sync_conflict = Some(crate::item::SyncConflict {
                original_id,
                original_title: archive.data.title().to_owned(),
                resolved: true,
            });
            archive.deleted_at = Some(now);
            archive.modified_at = now;
            self.upsert_item(archive)?;
            original.data = merged;
            if selected.iter().any(|key| key == "deleted") {
                original.deleted_at = copy.deleted_at.map(|_| now);
            }
        }
        original.modified_at = now;
        self.upsert_item(original)?;
        copy.sync_conflict = Some(link);
        copy.deleted_at = Some(now);
        copy.modified_at = now;
        conflicts::set_title(&mut copy.data, copy_title);
        self.upsert_item(copy)
    }

    /// Soft-delete (move to Trash). The item remains, marked `deleted_at`.
    pub fn delete_item(&mut self, id: Uuid, now_unix_millis: i64) -> Result<()> {
        let item = self
            .unlocked_items_mut()?
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(Error::NotFound)?;
        item.deleted_at = Some(now_unix_millis);
        item.modified_at = now_unix_millis;
        self.advance_revision(id)?;
        Ok(())
    }

    /// Restore a soft-deleted item back to active.
    pub fn restore_item(&mut self, id: Uuid, now_unix_millis: i64) -> Result<()> {
        let item = self
            .unlocked_items_mut()?
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(Error::NotFound)?;
        item.deleted_at = None;
        item.modified_at = now_unix_millis;
        self.advance_revision(id)?;
        Ok(())
    }

    /// Permanently remove an item (empties it from the Trash).
    ///
    /// Leaves a [`Purge`] behind. That record is the whole difference between
    /// this and dropping the item on the floor: without it, the next merge with
    /// a peer that still holds the item puts it straight back, and the one
    /// credential a user destroys on purpose is the one most likely to return.
    pub fn purge_item(&mut self, id: Uuid, now_unix_millis: i64) -> Result<()> {
        let items = self.unlocked_items_mut()?;
        let before = items.len();
        items.retain(|i| i.id != id);
        if items.len() == before {
            return Err(Error::NotFound);
        }
        self.purges.push(Purge {
            id,
            at: now_unix_millis,
        });
        Ok(())
    }

    /// Re-key the vault under a new master password (fresh salt + re-wrap).
    /// Existing quick-unlock stays valid (it is wrapped under the device key,
    /// not the master password).
    pub fn change_master_password(&mut self, new_password: &str) -> Result<()> {
        let vault_key = self.vault_key()?.clone();
        let new_params = KdfParams::new_default()?;
        let master_key = crypto::derive_master_key(new_password, &new_params)?;
        let wrapped = crypto::wrap_key(&master_key, &vault_key, &new_params.aad())?;
        self.header.kdf = new_params;
        self.header.master_wrapped_vault_key = wrapped;
        // Monotonic epoch: peers adopt the higher-epoch header on merge, so the
        // rotation propagates instead of being reverted by a stale header.
        self.header.rewrap_epoch += 1;
        Ok(())
    }

    // ----- quick-unlock (device key) --------------------------------------

    /// Add a device-key-wrapped copy of the vault key to the header, enabling
    /// quick/biometric unlock. The `device_key` must be stored by the caller
    /// in the OS keychain (see `vault-store`); it is never written to the file
    /// in cleartext.
    pub fn enable_device_unlock(&mut self, device_key: &SymmetricKey) -> Result<()> {
        let vault_key = self.vault_key()?.clone();
        let blob = crypto::wrap_key(device_key, &vault_key, DEVICE_UNLOCK_AAD)?;
        self.header.device_wrapped_vault_key = Some(blob);
        Ok(())
    }

    /// Remove quick-unlock material from the header. The caller should also
    /// delete the device key from the OS keychain.
    pub fn disable_device_unlock(&mut self) -> Result<()> {
        self.vault_key()?;
        self.header.device_wrapped_vault_key = None;
        Ok(())
    }

    pub fn has_device_unlock(&self) -> bool {
        self.header.device_wrapped_vault_key.is_some()
    }

    /// Whether `device_key` actually unwraps this header's quick-unlock slot.
    ///
    /// The OS-keychain copy of the device key and the header wrap can drift
    /// apart (an interrupted re-enable, a restored backup file, a peer's file
    /// bootstrapped onto this machine). Then Touch ID succeeds but the unwrap
    /// fails — so callers use this to detect the mismatch and re-establish
    /// quick unlock instead of silently failing. Works locked or unlocked;
    /// `false` when quick unlock was never enabled.
    pub fn device_key_matches(&self, device_key: &SymmetricKey) -> bool {
        self.header
            .device_wrapped_vault_key
            .as_ref()
            .map(|wrapped| crypto::unwrap_key(device_key, wrapped, DEVICE_UNLOCK_AAD).is_ok())
            .unwrap_or(false)
    }

    // ----- wraps stored outside the container ------------------------------

    /// Wrap the vault key under `key` for storage OUTSIDE the container — a
    /// local sidecar that never syncs. The header is untouched, so this
    /// coexists with the device-unlock slot instead of competing for it, and
    /// nothing about the on-disk format changes. `aad` names the use; the
    /// caller must pass the same value to unlock. Requires an unlocked vault.
    pub fn wrap_vault_key(&self, key: &SymmetricKey, aad: &[u8]) -> Result<crypto::AeadBlob> {
        crypto::wrap_key(key, self.vault_key()?, aad)
    }

    /// Unlock with a wrap produced by [`Vault::wrap_vault_key`].
    pub fn unlock_with_wrapped_key(
        &mut self,
        key: &SymmetricKey,
        wrapped: &crypto::AeadBlob,
        aad: &[u8],
    ) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }
        let vault_key = crypto::unwrap_key(key, wrapped, aad)?;
        self.finish_unlock(vault_key)
    }

    /// Whether `wrapped` under `key` opens THIS vault. Unlocked: the yielded
    /// key must equal the live one (constant-time). Locked: it must
    /// authenticate the container. A stale sidecar — a restored backup, a
    /// vault replaced from a peer — is detected here rather than as a failed
    /// unlock. Works locked or unlocked.
    pub fn wrapped_key_matches(
        &self,
        key: &SymmetricKey,
        wrapped: &crypto::AeadBlob,
        aad: &[u8],
    ) -> bool {
        let Ok(candidate) = crypto::unwrap_key(key, wrapped, aad) else {
            return false;
        };
        match self.vault_key() {
            Ok(live) => *live == candidate,
            Err(_) => self.verify_authentication(&candidate).is_ok(),
        }
    }

    // ----- accessors ------------------------------------------------------

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    // ----- internals ------------------------------------------------------

    fn verify_authentication(&self, key: &SymmetricKey) -> Result<()> {
        let (Some(tag), VaultState::Locked { items }) = (&self.authentication, &self.state) else {
            return Ok(());
        };
        let body = bincode::serialize(&VaultBody {
            header: self.header.clone(),
            items: items.clone(),
            purges: self.purges.clone(),
        })
        .map_err(|_| Error::Serialization)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts a 32-byte key");
        mac.update(AUTH_CONTEXT);
        mac.update(&body);
        mac.verify_slice(tag).map_err(|_| Error::Decryption)
    }

    fn vault_key(&self) -> Result<&SymmetricKey> {
        match &self.state {
            VaultState::Unlocked { vault_key, .. } => Ok(vault_key),
            VaultState::Locked { .. } => Err(Error::Locked),
        }
    }

    fn unlocked_items(&self) -> Result<&Vec<Item>> {
        match &self.state {
            VaultState::Unlocked { items, .. } => Ok(items),
            VaultState::Locked { .. } => Err(Error::Locked),
        }
    }

    fn unlocked_items_mut(&mut self) -> Result<&mut Vec<Item>> {
        match &mut self.state {
            VaultState::Unlocked { items, .. } => Ok(items),
            VaultState::Locked { .. } => Err(Error::Locked),
        }
    }

    fn advance_revision(&mut self, id: Uuid) -> Result<()> {
        let item = self
            .unlocked_items_mut()?
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or(Error::NotFound)?;
        let previous = item.revision;
        item.revision = Uuid::new_v4();
        item.revision_ancestors.insert(0, previous);
        let mut unique = Vec::with_capacity(item.revision_ancestors.len());
        for revision in core::mem::take(&mut item.revision_ancestors) {
            if revision != item.revision && !unique.contains(&revision) {
                unique.push(revision);
            }
        }
        unique.truncate(MAX_REVISION_ANCESTORS);
        item.revision_ancestors = unique;
        Ok(())
    }
}

fn authenticate_body(key: &SymmetricKey, body: &[u8]) -> [u8; AUTH_LEN] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts a 32-byte key");
    mac.update(AUTH_CONTEXT);
    mac.update(body);
    mac.finalize().into_bytes().into()
}

/// Encode an item payload (the plaintext that gets sealed) with CBOR.
///
/// CBOR is self-describing and tags enum variants by name, so the persisted
/// `VaultItem` schema can evolve — variants may be reordered or appended —
/// without misreading existing data. (The outer container in
/// [`Vault::to_bytes`] uses bincode; only this inner, encrypted payload needs
/// schema stability.) Generic so the round-trip test can exercise the exact
/// codec used on disk.
fn encode_item_payload<T: serde::Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| Error::Serialization)?;
    Ok(Zeroizing::new(buf))
}

/// Decode an item payload previously produced by [`encode_item_payload`].
fn decode_item_payload<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|_| Error::Serialization)
}

/// Seal every item under the vault key, binding each item's id as AAD.
fn encrypt_items(vault_key: &SymmetricKey, items: &[Item]) -> Result<Vec<EncryptedItem>> {
    items
        .iter()
        .map(|item| {
            validate_revision(item)?;
            let plaintext = encode_item_payload(item)?;
            let blob = crypto::seal(vault_key, &plaintext, item.id.as_bytes())?;
            Ok(EncryptedItem { id: item.id, blob })
        })
        .collect()
}

/// Open every item under the vault key, verifying the id-bound AAD.
fn decrypt_items(vault_key: &SymmetricKey, items: &[EncryptedItem]) -> Result<Vec<Item>> {
    items
        .iter()
        .map(|enc| {
            let plaintext = crypto::open(vault_key, &enc.blob, enc.id.as_bytes())?;
            let item: Item = decode_item_payload(&plaintext)?;
            // Defense in depth: the decrypted id must match the cleartext id.
            if item.id != enc.id {
                return Err(Error::Decryption);
            }
            validate_revision(&item)?;
            Ok(item)
        })
        .collect()
}

fn validate_revision(item: &Item) -> Result<()> {
    if item.revision_ancestors.len() > MAX_REVISION_ANCESTORS {
        return Err(Error::Format);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    // Proves the on-disk item-payload codec is stable against variant
    // reordering *and* a newly appended variant — the property a positional
    // codec (bincode) would violate. We round-trip through the real
    // encode/decode helpers used by `encrypt_items`/`decrypt_items`.
    #[test]
    fn item_payload_survives_variant_reorder_and_append() {
        // The layout in effect when some item was written to disk.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(tag = "type")]
        enum OldLayout {
            Login { username: String, password: String },
            SecureNote { title: String },
        }

        // A future build: `SecureNote` moved ahead of `Login` and a brand-new
        // `Passkey` variant appended. Under a positional encoding this would
        // misdecode the old bytes; under name-tagged CBOR it must not.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(tag = "type")]
        enum NewLayout {
            SecureNote { title: String },
            Passkey { title: String },
            Login { username: String, password: String },
        }

        let written = encode_item_payload(&OldLayout::Login {
            username: "frank-lia".into(),
            password: "correct horse battery staple".into(),
        })
        .unwrap();

        let read_back: NewLayout = decode_item_payload(&written).unwrap();
        assert_eq!(
            read_back,
            NewLayout::Login {
                username: "frank-lia".into(),
                password: "correct horse battery staple".into(),
            }
        );
    }

    // ---- quick-unlock drift ---------------------------------------------

    // The OS-keychain device key and the header wrap can drift apart (an
    // interrupted re-enable, a restored backup, a bootstrapped peer file). The
    // symptom was brutal: Touch ID kept succeeding while the unlock kept
    // failing, and nothing repaired it. `device_key_matches` is the detection
    // primitive the self-heal builds on — pin its semantics.
    #[test]
    fn device_key_matches_detects_drift() {
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        let k1 = SymmetricKey::generate().unwrap();
        let k2 = SymmetricKey::generate().unwrap();

        // Never enabled: nothing matches.
        assert!(!v.device_key_matches(&k1));

        v.enable_device_unlock(&k1).unwrap();
        assert!(v.device_key_matches(&k1));
        assert!(!v.device_key_matches(&k2)); // drifted keychain copy

        // Re-enable with a fresh key (the repair path): the new key matches,
        // the old one no longer does.
        v.enable_device_unlock(&k2).unwrap();
        assert!(v.device_key_matches(&k2));
        assert!(!v.device_key_matches(&k1));

        // Works on a LOCKED vault too (the lock screen checks before unlock).
        let bytes = v.to_bytes().unwrap();
        let locked = Vault::from_bytes(&bytes).unwrap();
        assert!(!locked.is_unlocked());
        assert!(locked.device_key_matches(&k2));
        assert!(!locked.device_key_matches(&k1));
    }

    // ---- merge_remote (sync) --------------------------------------------

    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: crate::header::KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7u8; KdfParams::SALT_LEN],
        }
    }

    fn login_item(id_byte: u8, title: &str, modified_at: i64) -> Item {
        Item {
            id: Uuid::from_bytes([id_byte; 16]),
            created_at: 0,
            modified_at,
            deleted_at: None,
            revision: Uuid::nil(),
            revision_ancestors: Vec::new(),
            password_history: Vec::new(),
            sync_conflict: None,
            data: crate::item::VaultItem::Login {
                title: title.into(),
                username: "u".into(),
                password: "p".into(),
                url: "https://x.com".into(),
                totp_secret: None,
                notes: String::new(),
            },
        }
    }

    #[test]
    fn verify_master_password_checks_without_unlock_shortcut() {
        // A freshly created vault is unlocked; verification must still re-check
        // the password (unlike `unlock`, which short-circuits when unlocked).
        let v = Vault::create("correct-horse", cheap_params()).unwrap();
        assert!(v.is_unlocked());
        assert!(v.verify_master_password("correct-horse"));
        assert!(!v.verify_master_password("wrong"));
        assert!(!v.verify_master_password(""));
    }

    #[test]
    fn failed_lock_keeps_the_unlocked_items_intact() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        vault
            .upsert_item(Item::new(
                crate::item::VaultItem::Unknown(crate::item::UnknownItem {
                    kind: "FutureSecret".into(),
                    raw: vec![0xff], // deliberately invalid CBOR
                }),
                1,
            ))
            .unwrap();

        assert!(matches!(vault.lock(), Err(Error::Serialization)));
        assert!(vault.is_unlocked());
        assert_eq!(vault.list_items(true).unwrap().len(), 1);
    }

    #[test]
    fn container_rejects_untrusted_kdf_costs_before_unlock() {
        let vault = Vault::create("pw", cheap_params()).unwrap();
        let bytes = vault.to_bytes().unwrap();
        let mut body: VaultBody = deserialize_body(&bytes[MAGIC.len()..]).unwrap();
        body.header.kdf.m_cost_kib = KdfParams::MAX_M_COST_KIB + 1;

        let mut forged = MAGIC.to_vec();
        forged.extend_from_slice(&bincode::serialize(&body).unwrap());
        forged.extend_from_slice(&[0; AUTH_LEN]);
        assert!(matches!(Vault::from_bytes(&forged), Err(Error::Format)));
    }

    #[test]
    fn merge_remote_combines_a_peers_edits() {
        let mut a = Vault::create("pw", cheap_params()).unwrap();
        a.upsert_item(login_item(1, "X", 10)).unwrap();
        let base = a.to_bytes().unwrap();

        // Peer loads the same file, unlocks with the same password, adds Y.
        let mut b = Vault::from_bytes(&base).unwrap();
        b.unlock("pw").unwrap();
        b.upsert_item(login_item(2, "Y", 20)).unwrap();
        let remote = b.to_bytes().unwrap();

        a.merge_remote(&remote).unwrap();
        let mut ids: Vec<u8> = a
            .list_items(true)
            .unwrap()
            .iter()
            .map(|s| s.id.as_bytes()[0])
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn merge_remote_takes_the_newer_version() {
        let mut a = Vault::create("pw", cheap_params()).unwrap();
        a.upsert_item(login_item(1, "old", 10)).unwrap();
        let base = a.to_bytes().unwrap();
        let mut b = Vault::from_bytes(&base).unwrap();
        b.unlock("pw").unwrap();
        b.upsert_item(login_item(1, "new", 30)).unwrap(); // same id, newer
        let remote = b.to_bytes().unwrap();

        a.merge_remote(&remote).unwrap();
        let item = a.get_item(Uuid::from_bytes([1; 16])).unwrap();
        assert_eq!(item.data.title(), "new");
    }

    #[test]
    fn concurrent_edits_preserve_a_named_conflict_copy_once() {
        let id = Uuid::from_bytes([1; 16]);
        let mut desktop = Vault::create("pw", cheap_params()).unwrap();
        desktop.upsert_item(login_item(1, "base", 10)).unwrap();
        let base = desktop.to_bytes().unwrap();

        let mut phone = Vault::from_bytes(&base).unwrap();
        phone.unlock("pw").unwrap();

        let mut desktop_edit = desktop.get_item(id).unwrap();
        desktop_edit.modified_at = 20;
        if let crate::item::VaultItem::Login { title, .. } = &mut desktop_edit.data {
            *title = "desktop edit".into();
        }
        desktop.upsert_item(desktop_edit).unwrap();

        let mut phone_edit = phone.get_item(id).unwrap();
        phone_edit.modified_at = 30;
        if let crate::item::VaultItem::Login { title, .. } = &mut phone_edit.data {
            *title = "phone edit".into();
        }
        phone.upsert_item(phone_edit).unwrap();
        let stale_phone = phone.to_bytes().unwrap();

        desktop.merge_remote(&stale_phone).unwrap();
        let titles: Vec<String> = desktop
            .list_items(true)
            .unwrap()
            .into_iter()
            .map(|item| item.title)
            .collect();
        assert_eq!(titles.len(), 2);
        assert!(titles.iter().any(|title| title == "phone edit"));
        assert!(titles
            .iter()
            .any(|title| title == "desktop edit (sync conflict)"));

        // Pulling the exact same stale remote again must be idempotent.
        desktop.merge_remote(&stale_phone).unwrap();
        assert_eq!(desktop.list_items(true).unwrap().len(), 2);
    }

    #[test]
    fn revision_descendant_wins_even_when_its_clock_is_behind() {
        let id = Uuid::from_bytes([1; 16]);
        let mut desktop = Vault::create("pw", cheap_params()).unwrap();
        desktop.upsert_item(login_item(1, "base", 100)).unwrap();
        let mut phone = Vault::from_bytes(&desktop.to_bytes().unwrap()).unwrap();
        phone.unlock("pw").unwrap();

        let mut edit = phone.get_item(id).unwrap();
        edit.modified_at = 5; // deliberately skewed backwards
        if let crate::item::VaultItem::Login { title, .. } = &mut edit.data {
            *title = "edited with a slow clock".into();
        }
        phone.upsert_item(edit).unwrap();

        desktop.merge_remote(&phone.to_bytes().unwrap()).unwrap();
        assert_eq!(
            desktop.get_item(id).unwrap().data.title(),
            "edited with a slow clock"
        );
        assert_eq!(desktop.list_items(true).unwrap().len(), 1);
    }

    #[test]
    fn v3_container_is_read_and_rewritten_as_v5() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        vault.upsert_item(login_item(1, "legacy", 10)).unwrap();
        let current = vault.to_bytes().unwrap();
        let mut body: VaultBody = deserialize_body(&current[MAGIC.len()..]).unwrap();
        body.header.format_version = 3;
        let mut old = MAGIC_V3.to_vec();
        old.extend_from_slice(&bincode::serialize(&body).unwrap());

        let mut loaded = Vault::from_bytes(&old).unwrap();
        loaded.unlock("pw").unwrap();
        assert_eq!(loaded.list_items(true).unwrap().len(), 1);
        assert!(loaded.to_bytes().unwrap().starts_with(MAGIC));
    }

    /// The whole point, at the level a user would recognise: empty the Trash on
    /// this device, sync with a phone that never heard about it, and the
    /// credential must stay gone.
    #[test]
    fn a_purge_survives_a_merge_with_a_peer_that_still_has_the_item() {
        let id = Uuid::from_bytes([1; 16]);
        let mut desktop = Vault::create("pw", cheap_params()).unwrap();
        desktop.upsert_item(login_item(1, "leaked", 10)).unwrap();

        // The phone syncs, so it now holds the item too.
        let shared = desktop.to_bytes().unwrap();
        let mut phone = Vault::from_bytes(&shared).unwrap();
        phone.unlock("pw").unwrap();

        // The desktop deletes it for good.
        desktop.delete_item(id, 20).unwrap();
        desktop.purge_item(id, 30).unwrap();
        assert!(matches!(desktop.get_item(id), Err(Error::NotFound)));

        // Both directions: the phone's copy must not come back here, and the
        // purge must reach the phone rather than only living on this device.
        desktop.merge_remote(&phone.to_bytes().unwrap()).unwrap();
        assert!(
            matches!(desktop.get_item(id), Err(Error::NotFound)),
            "the peer's copy resurrected a purged item"
        );

        phone.merge_remote(&desktop.to_bytes().unwrap()).unwrap();
        assert!(
            matches!(phone.get_item(id), Err(Error::NotFound)),
            "the purge never propagated to the peer"
        );
    }

    /// A purge record is worth nothing if it does not survive being written and
    /// read back, which is the only form it ever travels in.
    #[test]
    fn purges_round_trip_through_the_container() {
        let id = Uuid::from_bytes([7; 16]);
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        vault.upsert_item(login_item(7, "gone", 10)).unwrap();
        vault.purge_item(id, 40).unwrap();

        let mut reloaded = Vault::from_bytes(&vault.to_bytes().unwrap()).unwrap();
        reloaded.unlock("pw").unwrap();
        assert_eq!(reloaded.purges, vec![Purge { id, at: 40 }]);

        // And still there after a lock/unlock cycle, which re-seals the items
        // but must not quietly drop what sits outside them.
        reloaded.lock().unwrap();
        assert_eq!(reloaded.purges.len(), 1);
    }

    /// Vaults written before purge records existed must still open. They simply
    /// have none, which is the truth about them, not a degraded read.
    #[test]
    fn a_v2_container_still_opens_and_starts_with_no_purges() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        vault.upsert_item(login_item(1, "kept", 10)).unwrap();

        // Rebuild the file in the old shape: same header and items, no purge
        // list, old magic.
        let items = match &vault.state {
            VaultState::Unlocked { vault_key, items } => encrypt_items(vault_key, items).unwrap(),
            VaultState::Locked { items } => items.clone(),
        };
        #[derive(Serialize)]
        struct OldBody {
            header: VaultHeader,
            items: Vec<EncryptedItem>,
        }
        let mut old = MAGIC_V2.to_vec();
        let mut header = vault.header.clone();
        header.format_version = 3;
        old.extend_from_slice(&bincode::serialize(&OldBody { header, items }).unwrap());

        let mut reloaded = Vault::from_bytes(&old).unwrap();
        reloaded.unlock("pw").unwrap();
        assert_eq!(reloaded.list_items(true).unwrap().len(), 1);
        assert!(reloaded.purges.is_empty());
    }

    /// A vault from a newer Arca must be REFUSED, never treated as garbage.
    /// Callers replace an unparseable remote with their own copy, so getting
    /// this wrong means an old client silently overwrites a newer vault and
    /// every change in it is gone.
    #[test]
    fn a_container_from_a_newer_arca_is_refused_not_mistaken_for_junk() {
        let mut future = b"SYBRVLT9".to_vec();
        future.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            Vault::from_bytes(&future),
            Err(Error::UnsupportedVersion)
        ));

        // Something that is not one of ours at all stays `Format`: replacing a
        // half-written or foreign file IS the right move, and conflating the
        // two the other way would wedge sync on a torn upload forever.
        assert!(matches!(
            Vault::from_bytes(b"NOTAVLT1________"),
            Err(Error::Format)
        ));
    }

    #[test]
    fn merge_remote_rejects_a_foreign_vault() {
        let mut a = Vault::create("pw", cheap_params()).unwrap();
        // A different vault has a different random vault key, so its items can't
        // be decrypted with ours -> the merge is refused.
        let mut other = Vault::create("pw", cheap_params()).unwrap();
        other.upsert_item(login_item(9, "Z", 5)).unwrap();
        let foreign = other.to_bytes().unwrap();
        assert!(matches!(a.merge_remote(&foreign), Err(Error::Decryption)));
    }

    #[test]
    fn merge_remote_adopts_a_newer_master_rewrap() {
        // Device A and B share a vault; A rotates the master password.
        let mut a = Vault::create("old-pw", cheap_params()).unwrap();
        a.upsert_item(login_item(1, "X", 10)).unwrap();
        let base = a.to_bytes().unwrap();
        let mut b = Vault::from_bytes(&base).unwrap();
        b.unlock("old-pw").unwrap();

        a.change_master_password("new-pw").unwrap();
        assert_eq!(a.header().rewrap_epoch, 1);
        let rotated = a.to_bytes().unwrap();

        // B merges A's file: the rotated header must be adopted, so a vault
        // serialized by B now opens with the NEW password only.
        b.merge_remote(&rotated).unwrap();
        assert_eq!(b.header().rewrap_epoch, 1);
        let from_b = b.to_bytes().unwrap();
        let mut check = Vault::from_bytes(&from_b).unwrap();
        assert!(check.unlock("old-pw").is_err());
        check.unlock("new-pw").unwrap();

        // And a STALE peer file (epoch 0) must NOT revert B's header.
        b.merge_remote(&base).unwrap();
        assert_eq!(b.header().rewrap_epoch, 1);
    }

    #[test]
    fn legacy_v1_container_still_loads() {
        // Hand-build a SYBRVLT1 container (v2 header, no rewrap epoch) and
        // confirm it round-trips through the current reader.
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(login_item(3, "Old", 5)).unwrap();
        let header = v.header().clone();
        #[derive(serde::Serialize)]
        struct OldHeader<'a> {
            format_version: u16,
            kdf: &'a KdfParams,
            master_wrapped_vault_key: &'a crate::crypto::AeadBlob,
            device_wrapped_vault_key: &'a Option<crate::crypto::AeadBlob>,
        }
        #[derive(serde::Serialize)]
        struct OldBody<'a> {
            header: OldHeader<'a>,
            items: Vec<EncryptedItem>, // empty: items aren't the point here
        }
        let old = OldBody {
            header: OldHeader {
                format_version: 2,
                kdf: &header.kdf,
                master_wrapped_vault_key: &header.master_wrapped_vault_key,
                device_wrapped_vault_key: &header.device_wrapped_vault_key,
            },
            items: vec![],
        };
        let mut bytes = b"SYBRVLT1".to_vec();
        bytes.extend_from_slice(&bincode::serialize(&old).unwrap());
        let mut loaded = Vault::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.header().rewrap_epoch, 0);
        loaded.unlock("pw").unwrap();
    }

    #[test]
    fn an_external_wrap_opens_the_vault_and_leaves_the_header_alone() {
        const AAD: &[u8] = b"test/external/v1";
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(login_item(9, "K", 1)).unwrap();
        let key = SymmetricKey::generate().unwrap();
        let wrapped = v.wrap_vault_key(&key, AAD).unwrap();
        assert!(!v.has_device_unlock(), "the header's slot is not involved");
        assert!(v.wrapped_key_matches(&key, &wrapped, AAD));

        // Round trip through bytes, like a real lock/relaunch.
        let mut reloaded = Vault::from_bytes(&v.to_bytes().unwrap()).unwrap();
        assert!(reloaded.wrapped_key_matches(&key, &wrapped, AAD));
        let other = SymmetricKey::generate().unwrap();
        assert!(!reloaded.wrapped_key_matches(&other, &wrapped, AAD));
        assert!(!reloaded.wrapped_key_matches(&key, &wrapped, b"other use"));
        assert!(reloaded
            .unlock_with_wrapped_key(&other, &wrapped, AAD)
            .is_err());
        reloaded
            .unlock_with_wrapped_key(&key, &wrapped, AAD)
            .unwrap();
        assert_eq!(reloaded.list_items(false).unwrap().len(), 1);

        // A different vault (a peer's, a restore) does not match the sidecar.
        let foreign = Vault::create("pw", cheap_params()).unwrap();
        assert!(!foreign.wrapped_key_matches(&key, &wrapped, AAD));
        let locked_foreign = Vault::from_bytes(&foreign.to_bytes().unwrap()).unwrap();
        assert!(!locked_foreign.wrapped_key_matches(&key, &wrapped, AAD));

        // A locked vault cannot mint a wrap.
        let locked = Vault::from_bytes(&v.to_bytes().unwrap()).unwrap();
        assert!(locked.wrap_vault_key(&key, AAD).is_err());
    }

    #[test]
    fn newer_format_version_is_refused_distinctly() {
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(login_item(4, "F", 1)).unwrap();
        let mut bytes = v.to_bytes().unwrap();
        // Corrupt the header's format_version (first field after the magic) to
        // a large value: must surface UnsupportedVersion, not generic Format.
        bytes[8] = 0xEE;
        bytes[9] = 0xEE;
        assert!(matches!(
            Vault::from_bytes(&bytes),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn merge_remote_requires_unlock() {
        let bytes = Vault::create("pw", cheap_params())
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut locked = Vault::from_bytes(&bytes).unwrap();
        assert!(matches!(locked.merge_remote(&bytes), Err(Error::Locked)));
    }

    #[test]
    fn unsigned_metadata_cannot_delete_items_or_replace_the_master_key() {
        let mut local = Vault::create("pw", cheap_params()).unwrap();
        local.upsert_item(login_item(1, "keep", 10)).unwrap();
        let original = local.to_bytes().unwrap();
        for tamper in 0..4 {
            let mut body: VaultBody = deserialize_body(&original[MAGIC.len()..]).unwrap();
            match tamper {
                0 => body.purges.push(Purge {
                    id: Uuid::from_bytes([1; 16]),
                    at: i64::MAX,
                }),
                1 => body.header.rewrap_epoch += 1,
                2 => body.items.clear(),
                _ => body.header.master_wrapped_vault_key.ciphertext[0] ^= 1,
            }
            let mut forged = MAGIC.to_vec();
            forged.extend(bincode::serialize(&body).unwrap());
            forged.extend_from_slice(&original[original.len() - AUTH_LEN..]);
            assert!(matches!(
                local.merge_remote(&forged),
                Err(Error::Decryption)
            ));
            assert_eq!(local.list_items(true).unwrap().len(), 1);
            assert_eq!(local.header.rewrap_epoch, 0);
            let mut reopened = Vault::from_bytes(&forged).unwrap();
            assert!(matches!(reopened.unlock("pw"), Err(Error::Decryption)));
            assert!(!reopened.is_unlocked());
        }
    }

    #[test]
    fn foreign_empty_vault_is_rejected_even_with_a_newer_header() {
        let mut local = Vault::create("pw", cheap_params()).unwrap();
        local.upsert_item(login_item(1, "keep", 10)).unwrap();
        let mut foreign = Vault::create("foreign", cheap_params()).unwrap();
        foreign.header.rewrap_epoch = 1;
        assert!(matches!(
            local.merge_remote(&foreign.to_bytes().unwrap()),
            Err(Error::Decryption)
        ));
        assert!(!local.verify_master_password("foreign"));
        local.lock().unwrap();
        local.unlock("pw").unwrap();
        assert_eq!(local.list_items(true).unwrap().len(), 1);
    }

    #[test]
    fn legacy_sync_accepts_items_but_refuses_unverified_destructive_metadata() {
        let mut local = Vault::create("pw", cheap_params()).unwrap();
        local.upsert_item(login_item(1, "keep", 10)).unwrap();
        let original = local.to_bytes().unwrap();
        let mut peer = Vault::from_bytes(&original).unwrap();
        peer.unlock("pw").unwrap();
        peer.upsert_item(login_item(2, "legacy peer edit", 20))
            .unwrap();
        let mut body: VaultBody =
            deserialize_body(&peer.to_bytes().unwrap()[MAGIC.len()..]).unwrap();
        body.header.format_version = 4;
        let legacy = |body: &VaultBody| {
            let mut out = MAGIC_V4.to_vec();
            out.extend(bincode::serialize(body).unwrap());
            out
        };
        local.merge_remote(&legacy(&body)).unwrap();
        assert_eq!(local.list_items(true).unwrap().len(), 2);
        let mut locked = Vault::from_bytes(&legacy(&body)).unwrap();
        assert!(locked.to_bytes().unwrap().starts_with(MAGIC_V4));
        locked.unlock("pw").unwrap();
        assert!(locked.to_bytes().unwrap().starts_with(MAGIC));

        body.purges.push(Purge {
            id: Uuid::from_bytes([1; 16]),
            at: i64::MAX,
        });
        assert!(matches!(
            local.merge_remote(&legacy(&body)),
            Err(Error::Decryption)
        ));
        body.purges.clear();
        body.header.rewrap_epoch = 1;
        assert!(matches!(
            local.merge_remote(&legacy(&body)),
            Err(Error::Decryption)
        ));
        assert_eq!(local.list_items(true).unwrap().len(), 2);
    }

    #[test]
    fn stripping_the_authentication_tag_is_not_a_format_downgrade() {
        let vault = Vault::create("pw", cheap_params()).unwrap();
        let mut bytes = vault.to_bytes().unwrap();
        bytes.truncate(bytes.len() - AUTH_LEN);
        bytes[..MAGIC.len()].copy_from_slice(MAGIC_V4);
        assert!(matches!(Vault::from_bytes(&bytes), Err(Error::Decryption)));
    }

    #[test]
    fn authenticated_locked_copy_round_trips_and_checks_device_unlock() {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        let key = SymmetricKey::generate().unwrap();
        vault.enable_device_unlock(&key).unwrap();
        vault.lock().unwrap();
        assert!(matches!(vault.disable_device_unlock(), Err(Error::Locked)));
        let mut loaded = Vault::from_bytes(&vault.to_bytes().unwrap()).unwrap();
        loaded.unlock_with_device_key(&key).unwrap();
        loaded.disable_device_unlock().unwrap();
        let mut loaded = Vault::from_bytes(&loaded.to_bytes().unwrap()).unwrap();
        loaded.unlock("pw").unwrap();
    }
}
