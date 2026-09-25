//! Vault data model.
//!
//! [`VaultItem`] carries the secret payload and is zeroized on drop. [`Item`]
//! wraps it with non-secret metadata (id, timestamps, soft-delete marker).
//! Timestamps are supplied by the caller (unix milliseconds) so this crate
//! stays free of clock I/O and fully deterministic under test.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The kind of a [`VaultItem`], for filtering/summaries without decrypting the
/// whole payload conceptually (used by the sidebar categories).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemKind {
    Login,
    Passkey,
    SshKey,
    Wifi,
    SecureNote,
    Bookmark,
    /// An entry written by a NEWER build than this one. See
    /// [`VaultItem::Unknown`]. Computed at runtime and never written to disk,
    /// so adding it here costs older clients nothing.
    Unknown,
}

/// The secret-bearing payload of a vault entry.
///
/// All variants and their string fields are zeroized when dropped.
///
/// `#[serde(tag = "type")]` makes the on-disk representation tagged by the
/// variant *name* (e.g. `{"type":"Login", ...}`) rather than by a positional
/// index. Combined with the self-describing CBOR encoding used for the at-rest
/// item payload (see [`crate::vault`]), the format stays stable when variants
/// are reordered or new ones are appended — a guarantee a positional codec
/// such as bincode does NOT provide.
///
/// `Debug` is implemented by hand (below) so secret fields (passwords, TOTP
/// secrets, notes, private keys) are redacted rather than printed — a derived
/// `Debug` would dump them into any log line or `{:?}` of a containing struct.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type")]
pub enum VaultItem {
    Login {
        title: String,
        username: String,
        password: String,
        url: String,
        /// Base32 TOTP secret, if the login has 2FA. `None` means no code.
        totp_secret: Option<String>,
        notes: String,
    },

    /// A WebAuthn passkey credential. The private key is a P-256 scalar held as
    /// bytes and zeroized with the rest of the payload; see [`crate::passkey`]
    /// for the authenticator operations. New fields are `#[serde(default)]` so
    /// the tagged-CBOR payload stays backward-compatible.
    Passkey {
        title: String,
        /// Relying-party id, e.g. "github.com".
        #[serde(default)]
        rp_id: String,
        /// Human-facing account name shown by the RP (e.g. "franzjeger").
        #[serde(default)]
        user_name: String,
        /// Opaque user handle chosen by the RP at registration.
        #[serde(default)]
        user_handle: Vec<u8>,
        /// Credential id presented on assertions.
        #[serde(default)]
        credential_id: Vec<u8>,
        /// SEC1 P-256 private scalar (32 bytes). Secret.
        #[serde(default)]
        private_key: Vec<u8>,
        /// Reserved. Assertions always report counter 0 (synced/backup-eligible
        /// credential; see [`crate::passkey::assert`]); kept for schema stability.
        #[serde(default)]
        sign_count: u32,
    },

    /// An SSH key served over the ssh-agent protocol. The private key is a
    /// 32-byte Ed25519 seed, zeroized with the rest of the payload; see
    /// [`crate::ssh`] for generation and signing. Signing happens inside the
    /// vault and the seed never leaves it. New fields are `#[serde(default)]`
    /// so the tagged-CBOR payload stays backward-compatible.
    SshKey {
        title: String,
        /// OpenSSH comment (conventionally `user@host`); shown by the agent.
        #[serde(default)]
        comment: String,
        /// Key algorithm on the wire, e.g. "ssh-ed25519". Stored so future
        /// algorithms can coexist; only Ed25519 is generated today.
        #[serde(default)]
        key_type: String,
        /// OpenSSH public-key blob (the agent identity + `authorized_keys` body).
        #[serde(default)]
        public_key: Vec<u8>,
        /// Ed25519 seed (32 bytes). Secret.
        #[serde(default)]
        private_key: Vec<u8>,
        /// SHA-256 fingerprint (`SHA256:…`), cached for display.
        #[serde(default)]
        fingerprint: String,
    },

    /// A saved Wi-Fi network. The passphrase is secret (zeroized with the rest
    /// of the payload). New fields are `#[serde(default)]` so the tagged-CBOR
    /// payload stays backward-compatible.
    Wifi {
        title: String,
        /// Network name.
        #[serde(default)]
        ssid: String,
        /// Passphrase. Secret. Empty for an open network.
        #[serde(default)]
        password: String,
        /// Auth token used in the join QR: "WPA" (covers WPA/WPA2/WPA3), "WEP",
        /// or "nopass" (open). Empty is treated as "WPA".
        #[serde(default)]
        security: String,
        /// Whether the SSID is hidden (not broadcast).
        #[serde(default)]
        hidden: bool,
        #[serde(default)]
        notes: String,
    },

    /// A browser bookmark.
    ///
    /// Nothing here is a password, but the SET is sensitive in a way no single
    /// entry is: a few thousand bookmarks describe where someone works, banks,
    /// and reads. So it lives in the vault with everything else rather than in
    /// a convenient plaintext file beside it.
    ///
    /// `folder` is a PATH ("Bar/Arbeid/Kunder"), not a tree. Every browser
    /// stores bookmarks as a tree, and modelling one here would mean node ids,
    /// parent pointers and reparenting rules in a store that has no other
    /// hierarchy. A path is flat, sorts naturally, survives a browser that
    /// names its roots differently, and rebuilds the tree on the way out. Empty
    /// means the bar's top level.
    Bookmark {
        title: String,
        #[serde(default)]
        url: String,
        #[serde(default)]
        folder: String,
        #[serde(default)]
        notes: String,
    },

    /// A free-form secure note: a title plus an encrypted body. The body is
    /// secret (zeroized with the payload, redacted in Debug). `body` is
    /// `#[serde(default)]` so notes written before it existed still load.
    SecureNote {
        title: String,
        #[serde(default)]
        body: String,
    },

    /// An item this build does not understand, kept byte-for-byte.
    ///
    /// WHY THIS EXISTS. The payload is CBOR tagged by variant NAME, which makes
    /// adding a kind safe for a new client reading old data. It said nothing
    /// about the other direction — and the other direction is the one that
    /// ships. A phone updates through review, a desktop updates from a script,
    /// and for days the fleet is not one build. Before this variant, a single
    /// entry of an unrecognised kind failed the decode of the WHOLE vault: not
    /// that one entry, every entry. Adding `Bookmark` did exactly that to the
    /// Linux and Windows machines.
    ///
    /// Tolerating it is only half the job. A client that read the vault, quietly
    /// dropped what it could not name, and saved would DELETE the newer
    /// entries — data loss dressed up as compatibility. So the original bytes
    /// are kept and written back untouched.
    ///
    /// `#[serde(untagged)]` makes this the fallback: serde tries the named
    /// variants first and only lands here when none of them matched.
    #[serde(untagged)]
    Unknown(UnknownItem),
}

/// The verbatim CBOR of an entry from a newer build, with its kind name.
///
/// `raw` is the entire encoded item — tag included — so re-serialising it
/// reproduces what the newer client wrote. Held as bytes rather than a parsed
/// value for one reason beyond fidelity: `Vec<u8>` zeroizes, and an unknown
/// item from a password manager must be assumed to hold secrets.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct UnknownItem {
    /// The `type` tag the newer build wrote, for display and diagnostics.
    pub kind: String,
    /// The whole item as CBOR, exactly as it arrived.
    pub raw: Vec<u8>,
}

impl std::fmt::Debug for UnknownItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bytes may hold someone's secrets; only the kind is safe to print.
        write!(
            f,
            "UnknownItem {{ kind: {:?}, raw: <{} bytes> }}",
            self.kind,
            self.raw.len()
        )
    }
}

impl<'de> Deserialize<'de> for UnknownItem {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = ciborium::value::Value::deserialize(d)?;
        let kind = value
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("type")))
            .and_then(|(_, v)| v.as_text())
            .unwrap_or_default()
            .to_string();
        let mut raw = Vec::new();
        ciborium::into_writer(&value, &mut raw).map_err(serde::de::Error::custom)?;
        Ok(UnknownItem { kind, raw })
    }
}

impl Serialize for UnknownItem {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let value: ciborium::value::Value =
            ciborium::from_reader(&self.raw[..]).map_err(serde::ser::Error::custom)?;
        value.serialize(s)
    }
}

/// Build the standard Wi-Fi join string that network QR codes encode
/// (`WIFI:T:<auth>;S:<ssid>;P:<pass>;H:<hidden>;;`). Special characters in the
/// SSID/password are backslash-escaped per the de-facto spec. Kept in the I/O-
/// free core so the actual QR rendering can happen wherever, from the secret.
pub fn wifi_qr_payload(ssid: &str, password: &str, security: &str, hidden: bool) -> String {
    fn esc(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if matches!(c, '\\' | ';' | ',' | ':' | '"') {
                out.push('\\');
            }
            out.push(c);
        }
        out
    }
    let auth = if security.eq_ignore_ascii_case("nopass") {
        "nopass"
    } else if security.eq_ignore_ascii_case("wep") {
        "WEP"
    } else {
        "WPA"
    };
    let mut out = format!("WIFI:T:{auth};S:{};", esc(ssid));
    if auth != "nopass" {
        out.push_str(&format!("P:{};", esc(password)));
    }
    if hidden {
        out.push_str("H:true;");
    }
    out.push(';');
    out
}

impl VaultItem {
    pub fn kind(&self) -> ItemKind {
        match self {
            VaultItem::Login { .. } => ItemKind::Login,
            VaultItem::Passkey { .. } => ItemKind::Passkey,
            VaultItem::SshKey { .. } => ItemKind::SshKey,
            VaultItem::Wifi { .. } => ItemKind::Wifi,
            VaultItem::SecureNote { .. } => ItemKind::SecureNote,
            VaultItem::Bookmark { .. } => ItemKind::Bookmark,
            VaultItem::Unknown(_) => ItemKind::Unknown,
        }
    }

    /// Display title for list/detail panes.
    pub fn title(&self) -> &str {
        match self {
            VaultItem::Login { title, .. }
            | VaultItem::Passkey { title, .. }
            | VaultItem::SshKey { title, .. }
            | VaultItem::Wifi { title, .. }
            | VaultItem::SecureNote { title, .. }
            | VaultItem::Bookmark { title, .. } => title,
            // Named by its kind rather than blank: the user should be able to
            // SEE that a newer device wrote something here, not wonder why an
            // entry is missing.
            VaultItem::Unknown(u) => &u.kind,
        }
    }

    /// Secondary line in the entry list (e.g. the username/email).
    pub fn subtitle(&self) -> &str {
        match self {
            VaultItem::Login { username, .. } => username,
            VaultItem::Passkey { user_name, .. } => user_name,
            // The comment (conventionally user@host) is the recognizable label.
            VaultItem::SshKey { comment, .. } => comment,
            // The network name is the recognizable label.
            VaultItem::Wifi { ssid, .. } => ssid,
            VaultItem::SecureNote { .. } => "",
            // The folder is what tells two bookmarks with the same title apart.
            VaultItem::Bookmark { folder, .. } => folder,
            // Nothing this build can read out of it.
            VaultItem::Unknown(_) => "",
        }
    }

    /// Whether a non-empty TOTP secret is present.
    pub fn has_totp(&self) -> bool {
        matches!(self, VaultItem::Login { totp_secret: Some(s), .. } if !s.is_empty())
    }

    /// The website URL, for kinds that have one (empty otherwise). Non-secret
    /// metadata, used e.g. to group entries for the same site in the list.
    pub fn url(&self) -> &str {
        match self {
            VaultItem::Login { url, .. } => url,
            // The rp_id ("github.com") acts as the passkey's site, so it groups
            // next to the matching login in the list.
            VaultItem::Passkey { rp_id, .. } => rp_id,
            // SSH keys are not tied to a web site; they group under their kind.
            VaultItem::SshKey { .. } => "",
            VaultItem::Wifi { .. } => "",
            VaultItem::SecureNote { .. } => "",
            // Deliberately the real URL: a bookmark then groups in the list
            // next to the login and passkey for the same site.
            VaultItem::Bookmark { url, .. } => url,
            VaultItem::Unknown(_) => "",
        }
    }

    /// Bookmark folder path, empty for top-level bookmarks and other kinds.
    pub fn folder(&self) -> &str {
        match self {
            VaultItem::Bookmark { folder, .. } => folder,
            _ => "",
        }
    }
}

/// Hand-written `Debug` that redacts every secret field. Non-secret metadata
/// (titles, usernames, URLs, rp ids, fingerprints) is shown to keep logs useful;
/// passwords, TOTP secrets, notes, and private keys are replaced with a marker.
impl std::fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "<redacted>";
        match self {
            VaultItem::Unknown(u) => write!(f, "{u:?}"),
            VaultItem::Login {
                title,
                username,
                url,
                ..
            } => f
                .debug_struct("Login")
                .field("title", title)
                .field("username", username)
                .field("url", url)
                .field("password", &REDACTED)
                .field("totp_secret", &REDACTED)
                .field("notes", &REDACTED)
                .finish(),
            VaultItem::Passkey {
                title,
                rp_id,
                user_name,
                credential_id,
                ..
            } => f
                .debug_struct("Passkey")
                .field("title", title)
                .field("rp_id", rp_id)
                .field("user_name", user_name)
                .field("credential_id", credential_id)
                .field("private_key", &REDACTED)
                .finish_non_exhaustive(),
            VaultItem::SshKey {
                title,
                comment,
                key_type,
                fingerprint,
                ..
            } => f
                .debug_struct("SshKey")
                .field("title", title)
                .field("comment", comment)
                .field("key_type", key_type)
                .field("fingerprint", fingerprint)
                .field("private_key", &REDACTED)
                .finish_non_exhaustive(),
            VaultItem::Wifi {
                title,
                ssid,
                security,
                hidden,
                ..
            } => f
                .debug_struct("Wifi")
                .field("title", title)
                .field("ssid", ssid)
                .field("security", security)
                .field("hidden", hidden)
                .field("password", &REDACTED)
                .field("notes", &REDACTED)
                .finish(),
            // A single bookmark is not a secret, and its title and folder are
            // what make a log line useful. The URL is redacted anyway: a
            // browsing history is exactly the kind of thing that should not
            // end up in a log because one entry looked harmless.
            VaultItem::Bookmark { title, folder, .. } => f
                .debug_struct("Bookmark")
                .field("title", title)
                .field("folder", folder)
                .field("url", &REDACTED)
                .field("notes", &REDACTED)
                .finish(),
            VaultItem::SecureNote { title, .. } => f
                .debug_struct("SecureNote")
                .field("title", title)
                .field("body", &REDACTED)
                .finish(),
        }
    }
}

/// Previous login/Wi-Fi passwords travel inside the encrypted item payload.
pub const MAX_PASSWORD_HISTORY: usize = 20;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordRevision {
    #[zeroize(skip)]
    pub id: Uuid,
    pub replaced_at: i64,
    pub password: String,
}

impl std::fmt::Debug for PasswordRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordRevision")
            .field("id", &self.id)
            .field("replaced_at", &self.replaced_at)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// A stored vault entry: secret payload plus non-secret metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConflict {
    pub original_id: Uuid,
    pub original_title: String,
    #[serde(default)]
    pub resolved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    /// Creation time, unix milliseconds.
    pub created_at: i64,
    /// Last-modified time, unix milliseconds.
    pub modified_at: i64,
    /// Soft-delete marker. `Some(ts)` means the item is in the Trash and shows
    /// under the "Deleted" sidebar category; `None` means active.
    pub deleted_at: Option<i64>,
    /// Opaque per-item revision id used to distinguish a later edit from a
    /// true concurrent edit during sync. Encrypted with the item payload.
    #[serde(default)]
    pub revision: Uuid,
    /// Recent predecessor revisions, newest first. Encrypted; bounded by the
    /// vault before writing or accepting a synced item.
    #[serde(default)]
    pub revision_ancestors: Vec<Uuid>,
    #[serde(default)]
    pub password_history: Vec<PasswordRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_conflict: Option<SyncConflict>,
    pub data: VaultItem,
}

impl Item {
    /// Create a new active item with a fresh random UUID.
    pub fn new(data: VaultItem, now_unix_millis: i64) -> Self {
        Self {
            id: Uuid::new_v4(),
            created_at: now_unix_millis,
            modified_at: now_unix_millis,
            deleted_at: None,
            revision: Uuid::new_v4(),
            revision_ancestors: Vec::new(),
            password_history: Vec::new(),
            sync_conflict: None,
            data,
        }
    }

    pub fn password(&self) -> Option<&str> {
        match &self.data {
            VaultItem::Login { password, .. } | VaultItem::Wifi { password, .. } => Some(password),
            _ => None,
        }
    }

    /// Preserve history even when a caller rebuilt the item from a DTO or a
    /// peer running an older V5 build omitted the optional field.
    pub(crate) fn retain_password_history(&mut self, previous: &Item, local_edit: bool) {
        if local_edit {
            // Use the vault's copy, not caller-supplied history. New changes
            // precede older ones even if the device clock moved backwards.
            self.password_history.clear();
        }
        if let (Some(old), Some(new)) = (previous.password(), self.password()) {
            if old != new && !old.is_empty() {
                self.password_history.push(PasswordRevision {
                    id: previous.revision,
                    replaced_at: self.modified_at,
                    password: old.to_owned(),
                });
            }
        }
        self.password_history
            .extend(previous.password_history.iter().cloned());
        let mut ids = std::collections::HashSet::new();
        self.password_history.retain(|entry| ids.insert(entry.id));
        self.password_history.truncate(MAX_PASSWORD_HISTORY);
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    pub fn is_sync_conflict(&self) -> bool {
        self.sync_conflict.as_ref().map_or_else(
            || self.data.title().ends_with(" (sync conflict)"),
            |link| !link.resolved,
        )
    }

    /// Build a lightweight, decrypted summary for list rendering.
    pub fn summary(&self) -> ItemSummary {
        ItemSummary {
            id: self.id,
            kind: self.data.kind(),
            title: self.data.title().to_owned(),
            subtitle: self.data.subtitle().to_owned(),
            url: self.data.url().to_owned(),
            folder: self.data.folder().to_owned(),
            has_totp: self.data.has_totp(),
            is_deleted: self.is_deleted(),
            modified_at: self.modified_at,
            is_sync_conflict: self.is_sync_conflict(),
            conflict_of: self.sync_conflict.as_ref().map(|link| link.original_id),
        }
    }
}

/// Lightweight, already-decrypted view of an item for list rendering.
///
/// NOTE: this contains plaintext title/subtitle (shown in the UI list anyway)
/// but never the password, TOTP secret, or notes. It is not zeroized: it is a
/// short-lived view object handed to the presentation layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemSummary {
    #[serde(default)]
    pub is_sync_conflict: bool,
    #[serde(default)]
    pub conflict_of: Option<Uuid>,
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub subtitle: String,
    /// Website URL (empty for kinds without one). Non-secret metadata.
    pub url: String,
    /// Bookmark folder path, `/`-separated. Empty for top-level bookmarks and
    /// every other item kind.
    pub folder: String,
    pub has_totp: bool,
    pub is_deleted: bool,
    pub modified_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_item_without_revision_metadata_defaults_to_nil() {
        #[derive(Serialize)]
        struct LegacyItem {
            id: Uuid,
            created_at: i64,
            modified_at: i64,
            deleted_at: Option<i64>,
            data: VaultItem,
        }
        let legacy = LegacyItem {
            id: Uuid::from_bytes([4; 16]),
            created_at: 1,
            modified_at: 2,
            deleted_at: None,
            data: VaultItem::SecureNote {
                title: "old".into(),
                body: "secret".into(),
            },
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&legacy, &mut encoded).unwrap();
        let decoded: Item = ciborium::from_reader(&encoded[..]).unwrap();
        assert_eq!(decoded.revision, Uuid::nil());
        assert!(decoded.revision_ancestors.is_empty());
    }

    #[test]
    fn debug_redacts_secrets_for_every_variant() {
        let login = VaultItem::Login {
            title: "GitHub".into(),
            username: "frank".into(),
            password: "hunter2-SECRET".into(),
            url: "https://github.com".into(),
            totp_secret: Some("JBSWY3DP-SECRET".into()),
            notes: "note-SECRET".into(),
        };
        let passkey = VaultItem::Passkey {
            title: "pk".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![1, 2, 3],
            credential_id: vec![4, 5, 6],
            private_key: b"PASSKEY-SEED-SECRET".to_vec(),
            sign_count: 0,
        };
        let ssh = VaultItem::SshKey {
            title: "laptop".into(),
            comment: "frank@host".into(),
            key_type: "ssh-ed25519".into(),
            public_key: vec![7, 8, 9],
            private_key: b"SSH-SEED-SECRET".to_vec(),
            fingerprint: "SHA256:abc".into(),
        };
        for item in [&login, &passkey, &ssh] {
            let dbg = format!("{item:?}");
            assert!(dbg.contains("<redacted>"), "no redaction marker in {dbg}");
            assert!(
                !dbg.contains("SECRET"),
                "a secret leaked into Debug output: {dbg}"
            );
        }
        // Non-secret metadata is still visible (keeps logs useful).
        assert!(format!("{login:?}").contains("frank"));
        assert!(format!("{ssh:?}").contains("SHA256:abc"));
    }
}

#[cfg(test)]
mod wifi_tests {
    use super::*;

    #[test]
    fn wifi_qr_payload_encodes_and_escapes() {
        let p = wifi_qr_payload("Home;Net", "p@ss:word", "WPA2", false);
        // Auth normalizes to WPA; ';' and ':' are backslash-escaped.
        assert_eq!(p, r"WIFI:T:WPA;S:Home\;Net;P:p@ss\:word;;");

        // Open network: no password segment.
        let open = wifi_qr_payload("Cafe", "ignored", "nopass", false);
        assert_eq!(open, "WIFI:T:nopass;S:Cafe;;");

        // Hidden network adds H:true.
        let hidden = wifi_qr_payload("Secret", "pw", "WPA", true);
        assert_eq!(hidden, "WIFI:T:WPA;S:Secret;P:pw;H:true;;");
    }
}
