//! Duplicate logins are found for someone to review, and merged exactly as
//! they were reviewed.

use uuid::Uuid;
use vault_core::dedupe::{Likeness, MergeChoice};
use vault_core::{Item, KdfParams, Vault, VaultItem};

fn vault() -> Vault {
    let mut params = KdfParams::new_default().unwrap();
    params.m_cost_kib = 256;
    params.t_cost = 1;
    Vault::create("master", params).unwrap()
}

fn login(v: &mut Vault, title: &str, url: &str, password: &str, modified: i64) -> Uuid {
    let item = Item::new(
        VaultItem::Login {
            title: title.into(),
            username: "me@example.test".into(),
            password: password.into(),
            url: url.into(),
            notes: String::new(),
            totp_secret: None,
        },
        modified,
    );
    let id = item.id;
    v.upsert_item(item).unwrap();
    id
}

fn shown(v: &Vault, ids: &[Uuid]) -> Vec<(Uuid, Uuid)> {
    ids.iter()
        .map(|id| (*id, v.get_item(*id).unwrap().revision))
        .collect()
}

fn active(v: &Vault) -> Vec<Uuid> {
    v.active_items().unwrap().map(|item| item.id).collect()
}

#[test]
fn merges_the_groups_chosen_following_logins_an_earlier_group_merged_away() {
    let mut v = vault();
    let a = login(&mut v, "Google", "https://google.com", "pw-a", 10);
    let b = login(&mut v, "Google", "https://www.google.com", "pw-b", 20);
    let c = login(
        &mut v,
        "Google sign-in",
        "https://accounts.google.com",
        "pw-c",
        30,
    );

    let groups = v.find_duplicate_logins().unwrap();
    assert_eq!(groups.len(), 2);
    let (same, possible) = (&groups[0], &groups[1]);
    assert_eq!((same.likeness, same.keep), (Likeness::Same, b));
    assert_eq!(possible.likeness, Likeness::Possible);
    assert_eq!((possible.keep, possible.ids.clone()), (c, vec![c, b]));
    // Finding changes nothing.
    assert_eq!(active(&v), [a, b, c]);

    // Keep the older google.com login rather than the default, then merge the
    // sign-in page's login with it. The possible group names b, which the
    // first merge sends to the Trash: it is followed to a.
    let choices = [
        MergeChoice {
            keep: a,
            ids: same.ids.clone(),
        },
        MergeChoice {
            keep: c,
            ids: possible.ids.clone(),
        },
    ];
    let reviewed = shown(&v, &[a, b, c]);
    assert_eq!(v.merge_logins(&choices, &reviewed, 100).unwrap(), 2);
    assert_eq!(active(&v), [c]);
    let kept = v.get_item(c).unwrap();
    let mut history: Vec<&str> = kept
        .password_history
        .iter()
        .map(|entry| entry.password.as_str())
        .collect();
    history.sort_unstable();
    assert_eq!(history, ["pw-a", "pw-b"]);
    assert!(v.find_duplicate_logins().unwrap().is_empty());
}

#[test]
fn merges_nothing_when_a_login_changed_after_it_was_shown() {
    let mut v = vault();
    let a = login(&mut v, "Site", "https://example.test", "pw-a", 10);
    let b = login(&mut v, "Site", "https://example.test/login", "pw-b", 20);
    let reviewed = shown(&v, &[a, b]);

    // Sync brings in an edit of b between looking and merging.
    let mut item = v.get_item(b).unwrap();
    if let VaultItem::Login { password, .. } = &mut item.data {
        *password = "changed-elsewhere".into();
    }
    v.upsert_item(item).unwrap();

    let choice = [MergeChoice {
        keep: a,
        ids: vec![a, b],
    }];
    assert!(matches!(
        v.merge_logins(&choice, &reviewed, 100),
        Err(vault_core::Error::Changed)
    ));
    assert_eq!(active(&v), [a, b]);
}

#[test]
fn refuses_a_group_that_is_not_what_was_shown() {
    let mut v = vault();
    let a = login(&mut v, "Site", "https://example.test", "pw-a", 10);
    let b = login(&mut v, "Site", "https://example.test", "pw-b", 20);
    let c = login(&mut v, "Other", "https://other.test", "pw-c", 30);
    let reviewed = shown(&v, &[a, b]);
    for choice in [
        // The one to keep is not in the group.
        MergeChoice {
            keep: c,
            ids: vec![a, b],
        },
        // A login that was never shown.
        MergeChoice {
            keep: a,
            ids: vec![a, c],
        },
        // Nothing to merge it with.
        MergeChoice {
            keep: a,
            ids: vec![a],
        },
    ] {
        assert!(matches!(
            v.merge_logins(&[choice], &reviewed, 100),
            Err(vault_core::Error::InvalidArgument(_))
        ));
    }
    assert_eq!(active(&v), [a, b, c]);
}
