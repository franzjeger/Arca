//! Explicit, revision-checked conflict resolution. Secrets stay in Rust.
use crate::{Error, Item, ItemKind, Result, VaultItem};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Resolution {
    KeepOriginal,
    UseCopy,
    Merge,
    KeepBoth,
}

pub fn validate_pair(original: &Item, copy: &Item) -> Result<()> {
    if original.id == copy.id
        || original.data.kind() != copy.data.kind()
        || original.data.kind() == ItemKind::Unknown
        || !copy.is_sync_conflict()
        || copy
            .sync_conflict
            .as_ref()
            .is_some_and(|link| link.original_id != original.id)
    {
        return Err(Error::InvalidArgument(
            "These entries are not a resolvable conflict pair.",
        ));
    }
    Ok(())
}

pub fn field_keys(kind: ItemKind) -> &'static [&'static str] {
    match kind {
        ItemKind::Login => &[
            "title", "username", "password", "url", "totp", "notes", "deleted",
        ],
        ItemKind::Wifi => &[
            "title", "ssid", "password", "security", "hidden", "notes", "deleted",
        ],
        ItemKind::SecureNote => &["title", "body", "deleted"],
        ItemKind::Bookmark => &["title", "url", "folder", "notes", "deleted"],
        ItemKind::Passkey | ItemKind::SshKey => &["title", "credential", "deleted"],
        ItemKind::Unknown => &[],
    }
}

pub fn set_title(data: &mut VaultItem, value: String) {
    match data {
        VaultItem::Login { title, .. }
        | VaultItem::Wifi { title, .. }
        | VaultItem::SecureNote { title, .. }
        | VaultItem::Bookmark { title, .. }
        | VaultItem::Passkey { title, .. }
        | VaultItem::SshKey { title, .. } => *title = value,
        VaultItem::Unknown(_) => {}
    }
}

pub fn original_copy_title(copy: &Item) -> String {
    let title = copy.data.title();
    if let Some(link) = &copy.sync_conflict {
        if title == format!("{} (sync conflict)", link.original_title) {
            return link.original_title.clone();
        }
    } else if let Some(title) = title.strip_suffix(" (sync conflict)") {
        return title.to_owned();
    }
    title.to_owned()
}

pub fn merge_payload(original: &Item, copy: &Item, fields: &[String]) -> Result<VaultItem> {
    validate_pair(original, copy)?;
    let keys = field_keys(original.data.kind());
    if fields.iter().any(|key| !keys.contains(&key.as_str())) {
        return Err(Error::InvalidArgument("Unknown conflict field."));
    }
    let selected = |key: &str| fields.iter().any(|field| field == key);
    let mut result = original.data.clone();
    // Cryptographic identities are indivisible: never mix one private key
    // with another public key, RP, credential id or user handle.
    if selected("credential") {
        result = copy.data.clone();
    }
    macro_rules! take {
        ($key:literal, $left:ident, $right:ident) => {
            if selected($key) {
                *$left = $right.clone();
            }
        };
    }
    match (&mut result, &copy.data) {
        (
            VaultItem::Login {
                username,
                password,
                url,
                totp_secret,
                notes,
                ..
            },
            VaultItem::Login {
                username: u,
                password: p,
                url: r,
                totp_secret: t,
                notes: n,
                ..
            },
        ) => {
            take!("username", username, u);
            take!("password", password, p);
            take!("url", url, r);
            take!("totp", totp_secret, t);
            take!("notes", notes, n);
        }
        (
            VaultItem::Wifi {
                ssid,
                password,
                security,
                hidden,
                notes,
                ..
            },
            VaultItem::Wifi {
                ssid: s,
                password: p,
                security: c,
                hidden: h,
                notes: n,
                ..
            },
        ) => {
            take!("ssid", ssid, s);
            take!("password", password, p);
            take!("security", security, c);
            if selected("hidden") {
                *hidden = *h;
            }
            take!("notes", notes, n);
        }
        (
            VaultItem::Bookmark {
                url, folder, notes, ..
            },
            VaultItem::Bookmark {
                url: u,
                folder: f,
                notes: n,
                ..
            },
        ) => {
            take!("url", url, u);
            take!("folder", folder, f);
            take!("notes", notes, n);
        }
        (VaultItem::SecureNote { body, .. }, VaultItem::SecureNote { body: b, .. }) => {
            take!("body", body, b);
        }
        _ => {}
    }
    set_title(
        &mut result,
        if selected("title") {
            original_copy_title(copy)
        } else {
            original.data.title().to_owned()
        },
    );
    Ok(result)
}

/// Text fields suitable for explicit comparison/reveal. Private keys remain
/// opaque and are compared as a complete credential instead.
pub fn text_field<'a>(item: &'a Item, field: &str) -> Option<(&'a str, bool)> {
    let plain = |s: &'a str| Some((s, false));
    let secret = |s: &'a str| Some((s, true));
    if field == "title" {
        return plain(item.data.title());
    }
    match (&item.data, field) {
        (VaultItem::Login { username, .. }, "username") => plain(username),
        (VaultItem::Login { password, .. } | VaultItem::Wifi { password, .. }, "password") => {
            secret(password)
        }
        (VaultItem::Login { url, .. } | VaultItem::Bookmark { url, .. }, "url") => plain(url),
        (VaultItem::Login { totp_secret, .. }, "totp") => {
            secret(totp_secret.as_deref().unwrap_or(""))
        }
        (
            VaultItem::Login { notes, .. }
            | VaultItem::Wifi { notes, .. }
            | VaultItem::Bookmark { notes, .. },
            "notes",
        ) => secret(notes),
        (VaultItem::Wifi { ssid, .. }, "ssid") => plain(ssid),
        (VaultItem::Wifi { security, .. }, "security") => plain(security),
        (VaultItem::Wifi { hidden, .. }, "hidden") => plain(if *hidden { "Yes" } else { "No" }),
        (VaultItem::SecureNote { body, .. }, "body") => secret(body),
        (VaultItem::Bookmark { folder, .. }, "folder") => plain(folder),
        (_, "deleted") => plain(if item.is_deleted() {
            "In Trash"
        } else {
            "Active"
        }),
        _ => None,
    }
}
