//! Find & merge duplicate logins.
//!
//! Duplicates arise from imports, save-on-submit racing an import, or syncing
//! two devices that each saved the same site. Two active logins are considered
//! duplicates when they share the same **site host** and (case-insensitive)
//! **username**.
//!
//! Merge policy (lossless where possible):
//! * Winner: the most recently modified item with a non-empty password (ties →
//!   most recently modified overall).
//! * Password/TOTP: the winner's; if the winner lacks a TOTP but a duplicate
//!   has one, it is adopted (never dropped).
//! * Notes: distinct non-empty notes from losers are appended to the winner.
//! * `created_at`: the earliest across the group (true age of the account).
//! * Losers are **soft-deleted** (moved to Trash), so nothing is destroyed and
//!   the merge propagates to synced peers as ordinary tombstones.

use crate::item::{Item, VaultItem};
use crate::url::host_of;
use std::collections::HashMap;

/// Merge duplicate active logins in place. Returns the number of items that
/// were merged away (soft-deleted into the Trash).
pub fn merge_duplicate_logins(items: &mut [Item], now_unix_millis: i64) -> usize {
    // Group indices of active logins by (host, username).
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (i, item) in items.iter().enumerate() {
        if item.is_deleted() {
            continue;
        }
        if let VaultItem::Login { username, url, .. } = &item.data {
            let user = username.trim().to_lowercase();
            let host = host_of(url);
            if host.is_empty() && user.is_empty() {
                continue; // nothing to key on; leave untouched
            }
            groups.entry((host, user)).or_default().push(i);
        }
    }

    let mut merged = 0usize;
    for (_, idxs) in groups {
        if idxs.len() < 2 {
            continue;
        }
        // Pick the winner: newest modified with a non-empty password, else
        // newest modified overall.
        let winner_idx = *idxs
            .iter()
            .max_by_key(|&&i| {
                let has_pw = matches!(
                    &items[i].data,
                    VaultItem::Login { password, .. } if !password.is_empty()
                );
                (has_pw, items[i].modified_at)
            })
            .expect("group is non-empty");

        // Collect what the losers contribute, then apply to the winner.
        let mut adopt_totp: Option<String> = None;
        let mut extra_notes: Vec<String> = Vec::new();
        let mut earliest_created = items[winner_idx].created_at;
        for &i in &idxs {
            if i == winner_idx {
                continue;
            }
            earliest_created = earliest_created.min(items[i].created_at);
            if let VaultItem::Login {
                totp_secret, notes, ..
            } = &items[i].data
            {
                if adopt_totp.is_none() {
                    if let Some(t) = totp_secret {
                        if !t.is_empty() {
                            adopt_totp = Some(t.clone());
                        }
                    }
                }
                if !notes.trim().is_empty() {
                    extra_notes.push(notes.clone());
                }
            }
            // Soft-delete the loser: recoverable, and syncs as a tombstone.
            items[i].deleted_at = Some(now_unix_millis);
            items[i].modified_at = now_unix_millis;
            merged += 1;
        }

        let winner = &mut items[winner_idx];
        winner.created_at = earliest_created;
        winner.modified_at = now_unix_millis;
        if let VaultItem::Login {
            totp_secret, notes, ..
        } = &mut winner.data
        {
            if totp_secret.as_deref().unwrap_or("").is_empty() {
                if let Some(t) = adopt_totp {
                    *totp_secret = Some(t);
                }
            }
            for extra in extra_notes {
                if !notes.contains(extra.trim()) {
                    if !notes.is_empty() {
                        notes.push('\n');
                    }
                    notes.push_str(&extra);
                }
            }
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(user: &str, url: &str, pw: &str, modified: i64) -> Item {
        Item {
            id: uuid::Uuid::new_v4(),
            created_at: modified,
            modified_at: modified,
            deleted_at: None,
            revision: uuid::Uuid::new_v4(),
            revision_ancestors: Vec::new(),
            password_history: Vec::new(),
            sync_conflict: None,
            data: VaultItem::Login {
                title: url.into(),
                username: user.into(),
                password: pw.into(),
                url: url.into(),
                totp_secret: None,
                notes: String::new(),
            },
        }
    }

    fn active_logins(items: &[Item]) -> usize {
        items.iter().filter(|i| !i.is_deleted()).count()
    }

    #[test]
    fn merges_same_host_same_user_keeps_newest_password() {
        let mut items = vec![
            login("frank", "https://github.com/login", "old-pw", 10),
            login("frank", "https://www.GitHub.com", "new-pw", 20),
        ];
        let merged = merge_duplicate_logins(&mut items, 100);
        assert_eq!(merged, 1);
        assert_eq!(active_logins(&items), 1);
        let survivor = items.iter().find(|i| !i.is_deleted()).unwrap();
        match &survivor.data {
            VaultItem::Login { password, .. } => assert_eq!(password, "new-pw"),
            _ => panic!(),
        }
        // The loser is in the Trash, not destroyed.
        assert!(items.iter().any(|i| i.is_deleted()));
    }

    #[test]
    fn different_users_or_hosts_are_not_merged() {
        let mut items = vec![
            login("frank", "https://github.com", "a", 1),
            login("other", "https://github.com", "b", 2),
            login("frank", "https://gitlab.com", "c", 3),
        ];
        assert_eq!(merge_duplicate_logins(&mut items, 100), 0);
        assert_eq!(active_logins(&items), 3);
    }

    #[test]
    fn winner_with_password_beats_newer_empty_password() {
        let mut items = vec![
            login("frank", "https://x.com", "real-pw", 10),
            login("frank", "https://x.com", "", 99),
        ];
        merge_duplicate_logins(&mut items, 100);
        let survivor = items.iter().find(|i| !i.is_deleted()).unwrap();
        match &survivor.data {
            VaultItem::Login { password, .. } => assert_eq!(password, "real-pw"),
            _ => panic!(),
        }
    }

    #[test]
    fn totp_and_notes_are_adopted_not_dropped() {
        let mut a = login("frank", "https://y.com", "pw1", 10);
        if let VaultItem::Login {
            totp_secret, notes, ..
        } = &mut a.data
        {
            *totp_secret = Some("JBSWY3DP".into());
            *notes = "recovery: 1234".into();
        }
        let b = login("frank", "https://y.com", "pw2", 20); // newer, no totp
        let mut items = vec![a, b];
        merge_duplicate_logins(&mut items, 100);
        let survivor = items.iter().find(|i| !i.is_deleted()).unwrap();
        match &survivor.data {
            VaultItem::Login {
                password,
                totp_secret,
                notes,
                ..
            } => {
                assert_eq!(password, "pw2");
                assert_eq!(totp_secret.as_deref(), Some("JBSWY3DP"));
                assert!(notes.contains("recovery: 1234"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn earliest_created_at_survives() {
        let mut items = vec![
            login("frank", "https://z.com", "a", 5),
            login("frank", "https://z.com", "b", 50),
        ];
        merge_duplicate_logins(&mut items, 100);
        let survivor = items.iter().find(|i| !i.is_deleted()).unwrap();
        assert_eq!(survivor.created_at, 5);
    }
}
