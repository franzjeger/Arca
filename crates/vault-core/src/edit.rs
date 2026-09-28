//! Creating and editing items: the one place that decides what an edit means,
//! so every client applies the same rules.
//!
//! A client may leave out a field it never showed. The phone's login editor
//! has no notes box, and the secret behind a TOTP code is never handed out to
//! be sent back. So a field left out keeps its value; only an explicit clear
//! erases it.

use uuid::Uuid;

use crate::error::{Error, Result};
use crate::item::{Item, ItemKind, VaultItem};
use crate::vault::Vault;

/// What an edit does to a field a client may not have shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change<T> {
    /// Left out: the field keeps its value (empty on a new item).
    Keep,
    /// Removed.
    Clear,
    /// Set to this value.
    Set(T),
}

impl Change<String> {
    fn apply(self, current: &str) -> String {
        match self {
            Change::Keep => current.to_owned(),
            Change::Clear => String::new(),
            Change::Set(value) => value,
        }
    }
}

/// A login as an editor describes it.
#[derive(Clone, Debug)]
pub struct LoginEdit {
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: Change<String>,
    /// Base32, or an `otpauth://` URI, which is stored as its secret.
    pub totp_secret: Change<String>,
    pub notes: Change<String>,
}

/// A Wi-Fi network as an editor describes it.
#[derive(Clone, Debug)]
pub struct WifiEdit {
    /// Blank means the network's name.
    pub title: String,
    pub ssid: String,
    pub password: Change<String>,
    /// The join-QR token: "WPA", "WEP" or "nopass"; empty means WPA.
    pub security: String,
    pub hidden: bool,
    pub notes: Change<String>,
}

/// A secure note as an editor describes it.
#[derive(Clone, Debug)]
pub struct NoteEdit {
    /// Blank means "Untitled note".
    pub title: String,
    pub body: String,
}

impl Vault {
    /// Create a login (`id` is `None`) or edit one in place; returns its id.
    /// Fields the edit left out keep their value. [`Error::WrongKind`] if
    /// `id` names another kind of item.
    pub fn save_login(&mut self, id: Option<Uuid>, edit: LoginEdit, now: i64) -> Result<Uuid> {
        let totp = match edit.totp_secret {
            Change::Set(raw) => normalize_totp(&raw)?.map_or(Change::Clear, Change::Set),
            other => other,
        };
        self.save(id, ItemKind::Login, now, |previous| {
            let (password, totp_secret, notes) = match previous {
                Some(VaultItem::Login {
                    password,
                    totp_secret,
                    notes,
                    ..
                }) => (password.as_str(), totp_secret.as_deref(), notes.as_str()),
                _ => ("", None, ""),
            };
            VaultItem::Login {
                title: edit.title,
                username: edit.username,
                url: edit.url,
                password: edit.password.apply(password),
                totp_secret: match totp {
                    Change::Keep => totp_secret.map(str::to_owned),
                    Change::Clear => None,
                    Change::Set(secret) => Some(secret),
                },
                notes: edit.notes.apply(notes),
            }
        })
    }

    /// Create or edit a Wi-Fi network, as [`Vault::save_login`] does logins.
    pub fn save_wifi(&mut self, id: Option<Uuid>, edit: WifiEdit, now: i64) -> Result<Uuid> {
        self.save(id, ItemKind::Wifi, now, |previous| {
            let (password, notes) = match previous {
                Some(VaultItem::Wifi {
                    password, notes, ..
                }) => (password.as_str(), notes.as_str()),
                _ => ("", ""),
            };
            VaultItem::Wifi {
                title: if edit.title.trim().is_empty() {
                    edit.ssid.clone()
                } else {
                    edit.title
                },
                ssid: edit.ssid,
                password: edit.password.apply(password),
                security: edit.security,
                hidden: edit.hidden,
                notes: edit.notes.apply(notes),
            }
        })
    }

    /// Create or edit a secure note.
    pub fn save_note(&mut self, id: Option<Uuid>, edit: NoteEdit, now: i64) -> Result<Uuid> {
        self.save(id, ItemKind::SecureNote, now, |_| VaultItem::SecureNote {
            title: if edit.title.trim().is_empty() {
                "Untitled note".into()
            } else {
                edit.title
            },
            body: edit.body,
        })
    }

    /// The tail every save shares: find the item being edited, refuse one of
    /// another kind, build its new payload from the old one, and store it.
    fn save(
        &mut self,
        id: Option<Uuid>,
        kind: ItemKind,
        now: i64,
        build: impl FnOnce(Option<&VaultItem>) -> VaultItem,
    ) -> Result<Uuid> {
        let item = match id {
            Some(id) => {
                let mut item = self.get_item(id)?;
                if item.data.kind() != kind {
                    return Err(Error::WrongKind);
                }
                item.data = build(Some(&item.data));
                item.modified_at = now;
                item
            }
            None => Item::new(build(None), now),
        };
        let id = item.id;
        self.upsert_item(item)?;
        Ok(id)
    }
}

/// A TOTP field as stored: trimmed, an `otpauth://` URI reduced to its Base32
/// secret, and blank meaning none. A malformed URI is refused here, where the
/// user can re-scan, rather than stored to derive nonsense later.
pub fn normalize_totp(raw: &str) -> Result<Option<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.to_ascii_lowercase().starts_with("otpauth://") {
        return Ok(Some(crate::parse_otpauth_uri(raw)?.secret));
    }
    Ok(Some(raw.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{KdfAlgorithm, KdfParams};

    fn vault() -> Vault {
        let params = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7u8; KdfParams::SALT_LEN],
        };
        Vault::create("pw", params).unwrap()
    }

    fn login(password: Change<String>, totp: Change<String>, notes: Change<String>) -> LoginEdit {
        LoginEdit {
            title: "Bank".into(),
            username: "me".into(),
            url: "https://bank.example".into(),
            password,
            totp_secret: totp,
            notes,
        }
    }

    fn fields(vault: &Vault, id: Uuid) -> (String, Option<String>, String) {
        match &vault.get_item(id).unwrap().data {
            VaultItem::Login {
                password,
                totp_secret,
                notes,
                ..
            } => (password.clone(), totp_secret.clone(), notes.clone()),
            other => panic!("not a login: {other:?}"),
        }
    }

    #[test]
    fn a_field_left_out_keeps_its_value_and_only_a_clear_erases_it() {
        let mut v = vault();
        let set = |s: &str| Change::Set(s.to_string());
        let id = v
            .save_login(
                None,
                login(set("pw1"), set("JBSWY3DPEHPK3PXP"), set("codes")),
                1,
            )
            .unwrap();

        v.save_login(Some(id), login(Change::Keep, Change::Keep, Change::Keep), 2)
            .unwrap();
        assert_eq!(
            fields(&v, id),
            (
                "pw1".into(),
                Some("JBSWY3DPEHPK3PXP".into()),
                "codes".into()
            )
        );

        v.save_login(Some(id), login(set("pw2"), Change::Clear, Change::Clear), 3)
            .unwrap();
        assert_eq!(fields(&v, id), ("pw2".into(), None, String::new()));
    }

    #[test]
    fn an_otpauth_uri_is_stored_as_its_secret_and_a_bad_one_is_refused() {
        let mut v = vault();
        let uri = "otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=Bank";
        let id = v
            .save_login(
                None,
                login(Change::Keep, Change::Set(uri.into()), Change::Keep),
                1,
            )
            .unwrap();
        assert_eq!(fields(&v, id).1.as_deref(), Some("JBSWY3DPEHPK3PXP"));

        let blank = login(Change::Keep, Change::Set("  ".into()), Change::Keep);
        v.save_login(Some(id), blank, 2).unwrap();
        assert_eq!(fields(&v, id).1, None);

        let bad = login(
            Change::Keep,
            Change::Set("otpauth://totp/x?secret=NOT!B32".into()),
            Change::Keep,
        );
        assert!(v.save_login(Some(id), bad, 3).is_err());
    }

    #[test]
    fn an_edit_cannot_change_an_items_kind() {
        let mut v = vault();
        let note = v
            .save_note(
                None,
                NoteEdit {
                    title: " ".into(),
                    body: "b".into(),
                },
                1,
            )
            .unwrap();
        assert_eq!(v.get_item(note).unwrap().data.title(), "Untitled note");
        let edit = login(Change::Keep, Change::Keep, Change::Keep);
        assert!(matches!(
            v.save_login(Some(note), edit.clone(), 2),
            Err(Error::WrongKind)
        ));
        assert!(matches!(
            v.save_login(Some(Uuid::nil()), edit, 2),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn a_wifi_without_a_title_is_named_after_its_network() {
        let mut v = vault();
        let edit = WifiEdit {
            title: String::new(),
            ssid: "home-5g".into(),
            password: Change::Set("pw".into()),
            security: "WPA".into(),
            hidden: false,
            notes: Change::Keep,
        };
        let id = v.save_wifi(None, edit, 1).unwrap();
        assert_eq!(v.get_item(id).unwrap().data.title(), "home-5g");
    }
}
