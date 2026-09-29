//! Find & merge duplicate logins.
//!
//! Duplicates arise from imports, save-on-submit racing an import, or syncing
//! two devices that each saved the same site. Finding and merging are apart:
//! [`find_duplicate_logins`] reports groups for someone to review, and
//! [`merge_logins`] merges one group into the login chosen to keep.
//!
//! Two active logins are the **same** account when they share the **site
//! host** and (case-insensitive) **username**. A login without a site has only
//! its **title** to go by, so there title and username must both match. One
//! username on different sites of one registrable domain
//! (`accounts.google.com` and `google.com`) is a **possible** match: often one
//! account, sometimes two, so only someone looking can say.
//!
//! Merge policy (lossless where possible):
//! * Kept: the login chosen. By default the most recently modified item with a
//!   non-empty password (ties → most recently modified overall).
//! * Password/TOTP: the kept login's; if it lacks a TOTP but a duplicate has
//!   one, it is adopted (never dropped).
//! * Other passwords: every different password the duplicates held, and their
//!   own history, go into the kept login's password history.
//! * Notes: distinct non-empty notes from the others are appended.
//! * `created_at`: the earliest across the group (true age of the account).
//! * The others are **soft-deleted** (moved to Trash), so nothing is destroyed
//!   and the merge propagates to synced peers as ordinary tombstones.

use crate::item::{Item, PasswordRevision, VaultItem, MAX_PASSWORD_HISTORY};
use crate::url::host_of;
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::Zeroizing;

/// How alike the logins in a group are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Likeness {
    /// One site (or, without one, one title) and one username: the same
    /// account saved more than once.
    Same,
    /// One username on different sites of one registrable domain: often one
    /// account, sometimes not.
    Possible,
}

/// Logins that look like one account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateGroup {
    pub likeness: Likeness,
    /// The login a merge keeps unless told otherwise: the newest with a
    /// password.
    pub keep: Uuid,
    /// Every login in the group, `keep` included, newest first.
    pub ids: Vec<Uuid>,
}

/// One group to merge, as someone chose it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeChoice {
    pub keep: Uuid,
    pub ids: Vec<Uuid>,
}

/// What two logins must share to be one account.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Account {
    Site {
        host: String,
        user: String,
    },
    /// Without a site, the username alone would make "Router" and "NAS", both
    /// `admin` and neither with an address, one account.
    Titled {
        title: String,
        user: String,
    },
}

/// The account an active login belongs to, or `None` when it is not one or
/// has too little to tell.
fn account_of(item: &Item) -> Option<Account> {
    let VaultItem::Login {
        title,
        username,
        url,
        ..
    } = &item.data
    else {
        return None;
    };
    if item.is_deleted() {
        return None;
    }
    let user = username.trim().to_lowercase();
    let host = host_of(url);
    if !host.is_empty() {
        return Some(Account::Site { host, user });
    }
    let title = title.trim().to_lowercase();
    if user.is_empty() || title.is_empty() {
        return None;
    }
    Some(Account::Titled { title, user })
}

/// The registrable domain of a host by the Public Suffix List, so that
/// `accounts.google.com` goes with `google.com` while `alice.github.io` and
/// `bob.github.io` stay apart. None for IP addresses, which the list would
/// pair by their last two numbers (`192.168.1.1` and `10.0.1.1` both give
/// "1.1"), and for names without a registrable part, such as `localhost`.
fn registrable_domain(host: &str) -> Option<&str> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    psl::domain_str(host)
}

/// The login a merge keeps by default: the newest with a password, then the
/// newest. The id settles a tie the same way on every device.
fn default_keep(items: &[Item], idxs: &[usize]) -> usize {
    *idxs
        .iter()
        .max_by_key(|&&i| {
            let has_password = items[i].password().is_some_and(|p| !p.is_empty());
            (has_password, items[i].modified_at, items[i].id)
        })
        .expect("group is non-empty")
}

/// Groups of active logins that look like one account, for review: the same
/// account first, then possible ones, each by the kept login's title.
///
/// A possible group lists one login per account. An account saved more than
/// once, a group of its own, stands there as the login that group keeps by
/// default.
pub fn find_duplicate_logins(items: &[Item]) -> Vec<DuplicateGroup> {
    let mut accounts: BTreeMap<Account, Vec<usize>> = BTreeMap::new();
    for (i, item) in items.iter().enumerate() {
        if let Some(account) = account_of(item) {
            accounts.entry(account).or_default().push(i);
        }
    }

    let mut found: Vec<(Likeness, usize, Vec<usize>)> = Vec::new();
    let mut by_domain: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (account, idxs) in accounts {
        let keep = default_keep(items, &idxs);
        if let Account::Site { host, user } = &account {
            if let Some(domain) = registrable_domain(host) {
                by_domain
                    .entry((domain.to_owned(), user.clone()))
                    .or_default()
                    .push(keep);
            }
        }
        if idxs.len() > 1 {
            found.push((Likeness::Same, keep, idxs));
        }
    }
    for idxs in by_domain.into_values() {
        if idxs.len() > 1 {
            found.push((Likeness::Possible, default_keep(items, &idxs), idxs));
        }
    }

    let title = |i: usize| items[i].data.title().to_lowercase();
    found.sort_by_cached_key(|(likeness, keep, _)| (*likeness, title(*keep), items[*keep].id));
    found
        .into_iter()
        .map(|(likeness, keep, mut idxs)| {
            idxs.sort_by_key(|&i| (std::cmp::Reverse(items[i].modified_at), items[i].id));
            DuplicateGroup {
                likeness,
                keep: items[keep].id,
                ids: idxs.iter().map(|&i| items[i].id).collect(),
            }
        })
        .collect()
}

/// Merge every group of the same account into the login it keeps by default,
/// without review. Returns the number of items merged away (soft-deleted into
/// the Trash).
pub fn merge_duplicate_logins(items: &mut [Item], now_unix_millis: i64) -> usize {
    find_duplicate_logins(items)
        .into_iter()
        .filter(|group| group.likeness == Likeness::Same)
        .map(|group| merge_logins(items, &group.ids, group.keep, now_unix_millis))
        .sum()
}

/// Merge the active logins among `ids` into `keep`: the others go to the
/// Trash, and their passwords, TOTP and notes as the policy above says.
/// Returns how many were merged away; none when `keep` is not an active login.
pub fn merge_logins(items: &mut [Item], ids: &[Uuid], keep: Uuid, now_unix_millis: i64) -> usize {
    let mergeable =
        |item: &Item| !item.is_deleted() && matches!(item.data, VaultItem::Login { .. });
    let Some(winner_idx) = items
        .iter()
        .position(|item| item.id == keep && mergeable(item))
    else {
        return 0;
    };
    let losers: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(i, item)| *i != winner_idx && ids.contains(&item.id) && mergeable(item))
        .map(|(i, _)| i)
        .collect();
    if losers.is_empty() {
        return 0;
    }

    // Collect what the losers contribute, then apply to the winner.
    let mut adopt_totp: Option<String> = None;
    let mut extra_notes: Vec<String> = Vec::new();
    let mut earlier_passwords: Vec<PasswordRevision> = Vec::new();
    let mut earliest_created = items[winner_idx].created_at;
    for &i in &losers {
        earliest_created = earliest_created.min(items[i].created_at);
        if let Some(password) = items[i].password().filter(|p| !p.is_empty()) {
            earlier_passwords.push(PasswordRevision {
                id: items[i].revision,
                replaced_at: items[i].modified_at,
                password: password.to_owned(),
            });
        }
        earlier_passwords.extend(items[i].password_history.iter().cloned());
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
    }

    let winner = &mut items[winner_idx];
    keep_passwords(winner, earlier_passwords);
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
    losers.len()
}

/// Put the passwords the merged-away logins held into the survivor's history.
/// A duplicate's older password can be the one that still works somewhere,
/// and in the Trash it is only found by someone who knows to look, and gone
/// once the Trash is emptied.
fn keep_passwords(winner: &mut Item, earlier: Vec<PasswordRevision>) {
    let current = Zeroizing::new(winner.password().unwrap_or_default().to_owned());
    for entry in earlier {
        let known = entry.password.is_empty()
            || entry.password == *current
            || winner
                .password_history
                .iter()
                .any(|kept| kept.id == entry.id || kept.password == entry.password);
        if !known {
            winner.password_history.push(entry);
        }
    }
    winner
        .password_history
        .sort_by_key(|entry| std::cmp::Reverse(entry.replaced_at));
    winner.password_history.truncate(MAX_PASSWORD_HISTORY);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(user: &str, url: &str, pw: &str, modified: i64) -> Item {
        titled(url, user, url, pw, modified)
    }

    fn titled(title: &str, user: &str, url: &str, pw: &str, modified: i64) -> Item {
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
                title: title.into(),
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
    fn logins_without_a_site_are_one_account_only_under_one_title() {
        let mut items = vec![
            titled("Router", "admin", "", "router-pw", 1),
            titled("NAS", "admin", "", "nas-pw", 2),
            // No username either: nothing to tell two such logins apart by.
            titled("Door code", "", "", "1234", 3),
            titled("Door code", "", "", "5678", 4),
        ];
        assert_eq!(merge_duplicate_logins(&mut items, 100), 0);
        assert_eq!(active_logins(&items), 4);

        let mut items = vec![
            titled("Router", "admin", "", "router-pw", 1),
            titled(" router ", "Admin", "", "router-pw", 2),
            titled("Router", "admin", "https://router.example", "router-pw", 3),
        ];
        // The two without an address are one account; the one with an
        // address is keyed by its site and stays apart.
        assert_eq!(merge_duplicate_logins(&mut items, 100), 1);
        assert_eq!(active_logins(&items), 2);
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
    fn the_other_passwords_stay_in_the_history_of_the_one_kept() {
        let mut older = login("frank", "https://x.com", "old-pw", 10);
        older.password_history.push(PasswordRevision {
            id: uuid::Uuid::new_v4(),
            replaced_at: 5,
            password: "oldest-pw".into(),
        });
        let same_as_kept = login("frank", "https://x.com", "new-pw", 15);
        let newer = login("frank", "https://x.com", "new-pw", 20);
        let mut items = vec![older, same_as_kept, newer];
        let mut on_other_device = items.clone();
        assert_eq!(merge_duplicate_logins(&mut items, 100), 2);

        let survivor = items.iter().find(|i| !i.is_deleted()).unwrap();
        assert_eq!(survivor.password(), Some("new-pw"));
        // Newest first; the copy of the current password adds nothing.
        let history: Vec<(&str, i64)> = survivor
            .password_history
            .iter()
            .map(|h| (h.password.as_str(), h.replaced_at))
            .collect();
        assert_eq!(history, [("old-pw", 10), ("oldest-pw", 5)]);

        // The same merge on another device keeps the same entries, so the
        // two histories agree when they sync.
        merge_duplicate_logins(&mut on_other_device, 300);
        let there = on_other_device.iter().find(|i| !i.is_deleted()).unwrap();
        assert_eq!(there.password_history, survivor.password_history);

        // Handing the same passwords over again adds nothing.
        let mut kept = survivor.clone();
        keep_passwords(&mut kept, survivor.password_history.clone());
        assert_eq!(kept.password_history, survivor.password_history);
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

    fn ids(items: &[Item], which: &[usize]) -> Vec<uuid::Uuid> {
        which.iter().map(|&i| items[i].id).collect()
    }

    #[test]
    fn finds_the_same_account_and_possible_ones_without_merging() {
        let items = vec![
            titled("Google", "me@x.no", "https://google.com", "a", 10),
            titled("Google", "ME@x.no", "https://www.google.com/", "b", 20),
            titled(
                "Google sign-in",
                "me@x.no",
                "https://accounts.google.com/",
                "c",
                30,
            ),
            // Another user of the same site, and the same user elsewhere.
            titled("Google", "other@x.no", "https://google.com", "d", 40),
            titled("GitHub", "me@x.no", "https://github.com", "e", 50),
        ];
        let groups = find_duplicate_logins(&items);
        assert_eq!(
            groups,
            [
                DuplicateGroup {
                    likeness: Likeness::Same,
                    keep: items[1].id,
                    ids: ids(&items, &[1, 0]),
                },
                // The google.com account stands here as the login it keeps.
                DuplicateGroup {
                    likeness: Likeness::Possible,
                    keep: items[2].id,
                    ids: ids(&items, &[2, 1]),
                },
            ]
        );
        assert!(items.iter().all(|i| !i.is_deleted()));
    }

    #[test]
    fn possible_matches_follow_the_public_suffix_list_and_skip_addresses() {
        let items = vec![
            // Different people's pages on one hosting domain.
            login("me", "https://alice.github.io", "a", 1),
            login("me", "https://bob.github.io", "b", 2),
            // A router and a NAS: the list pairs any IPs by "1.1".
            login("admin", "http://192.168.1.1", "c", 3),
            login("admin", "http://10.0.1.1:8080", "d", 4),
            login("admin", "https://localhost:5173", "e", 5),
            login("admin", "http://[::1]:3000/", "f", 6),
        ];
        assert_eq!(find_duplicate_logins(&items), []);
    }

    #[test]
    fn merges_one_group_into_the_login_chosen() {
        let mut items = vec![
            login("frank", "https://x.com", "older-pw", 10),
            login("frank", "https://x.com", "newer-pw", 20),
        ];
        // Keep the older one, although the newer is the default.
        let (keep, other) = (items[0].id, items[1].id);
        assert_eq!(merge_logins(&mut items, &[keep, other], keep, 100), 1);
        assert_eq!(items[0].password(), Some("older-pw"));
        assert!(items[1].is_deleted());
        let kept: Vec<&str> = items[0]
            .password_history
            .iter()
            .map(|h| h.password.as_str())
            .collect();
        assert_eq!(kept, ["newer-pw"]);
        // Nothing left to merge: the other is in the Trash.
        assert_eq!(merge_logins(&mut items, &[keep, other], keep, 200), 0);
    }
}
