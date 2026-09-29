//! Find & merge duplicate logins: found for someone to look over, merged the
//! way they chose.

use crate::{
    commands::{guard, persist, write_guard},
    state::{now_millis, AppState, CmdError},
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;
use uuid::Uuid;
use vault_core::dedupe::{DuplicateGroup, Likeness, MergeChoice};
use vault_core::{host_of, Vault, VaultItem};
use zeroize::Zeroizing;

/// A login in a group, as the review shows it. No secret leaves the vault:
/// `password` only says which logins in the group share one.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateLogin {
    id: Uuid,
    revision: Uuid,
    title: String,
    site: String,
    username: String,
    modified_at: i64,
    /// Logins with the same number have the same password.
    password: usize,
    has_password: bool,
    has_totp: bool,
    has_notes: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Duplicates {
    /// One username on different sites of one domain, rather than one site.
    possible: bool,
    /// The login a merge keeps unless someone picks another.
    keep: Uuid,
    /// Newest first.
    logins: Vec<DuplicateLogin>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Choice {
    keep: Uuid,
    ids: Vec<Uuid>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Shown {
    id: Uuid,
    revision: Uuid,
}

fn describe(vault: &Vault, group: DuplicateGroup) -> Result<Duplicates, CmdError> {
    let mut passwords: Vec<Zeroizing<String>> = Vec::new();
    let mut logins = Vec::with_capacity(group.ids.len());
    for id in group.ids {
        let item = vault.get_item(id)?;
        let VaultItem::Login {
            title,
            username,
            password,
            url,
            totp_secret,
            notes,
        } = &item.data
        else {
            continue;
        };
        let index = match passwords
            .iter()
            .position(|known| known.as_str() == password)
        {
            Some(index) => index,
            None => {
                passwords.push(Zeroizing::new(password.clone()));
                passwords.len() - 1
            }
        };
        logins.push(DuplicateLogin {
            id,
            revision: item.revision,
            title: title.clone(),
            site: host_of(url),
            username: username.clone(),
            modified_at: item.modified_at,
            password: index,
            has_password: !password.is_empty(),
            has_totp: totp_secret.as_deref().is_some_and(|t| !t.is_empty()),
            has_notes: !notes.trim().is_empty(),
        });
    }
    Ok(Duplicates {
        possible: group.likeness == Likeness::Possible,
        keep: group.keep,
        logins,
    })
}

/// Groups of logins that look like one account. Changes nothing.
#[tauri::command]
pub fn find_duplicates(state: State<'_, Mutex<AppState>>) -> Result<Vec<Duplicates>, CmdError> {
    find(state.inner())
}

fn find(state: &Mutex<AppState>) -> Result<Vec<Duplicates>, CmdError> {
    let state = guard(state)?;
    let vault = state.vault()?;
    vault
        .find_duplicate_logins()?
        .into_iter()
        .map(|group| describe(vault, group))
        .collect()
}

/// Merge the groups chosen, in order, as long as every login shown is as it
/// was. The others go to the Trash; returns how many.
#[tauri::command]
pub fn merge_duplicates(
    state: State<'_, Mutex<AppState>>,
    choices: Vec<Choice>,
    shown: Vec<Shown>,
) -> Result<usize, CmdError> {
    merge(state.inner(), choices, shown)
}

fn merge(
    state: &Mutex<AppState>,
    choices: Vec<Choice>,
    shown: Vec<Shown>,
) -> Result<usize, CmdError> {
    let choices: Vec<MergeChoice> = choices
        .into_iter()
        .map(|choice| MergeChoice {
            keep: choice.keep,
            ids: choice.ids,
        })
        .collect();
    let shown: Vec<(Uuid, Uuid)> = shown.iter().map(|s| (s.id, s.revision)).collect();
    let mut st = write_guard(state)?;
    let merged = st
        .vault
        .as_mut()
        .ok_or_else(CmdError::no_vault)?
        .merge_logins(&choices, &shown, now_millis())?;
    if merged > 0 {
        persist(&mut st)?;
    }
    st.touch();
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Item, KdfParams};

    fn login(title: &str, url: &str, password: &str, modified: i64) -> Item {
        Item::new(
            VaultItem::Login {
                title: title.into(),
                username: "me@example.test".into(),
                password: password.into(),
                url: url.into(),
                notes: String::new(),
                totp_secret: None,
            },
            modified,
        )
    }

    fn state_in(dir: &std::path::Path, items: &[Item]) -> Mutex<AppState> {
        let store = vault_store::VaultStore::new(dir.join("vault"), "test", "duplicates");
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        let mut params = KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        params.p_cost = 1;
        let mut vault = Vault::create("master", params).unwrap();
        for item in items {
            vault.upsert_item(item.clone()).unwrap();
        }
        Mutex::new(AppState::new(store, Some(vault), clipboard))
    }

    fn shown(groups: &[Duplicates]) -> Vec<Shown> {
        groups
            .iter()
            .flat_map(|g| &g.logins)
            .map(|l| Shown {
                id: l.id,
                revision: l.revision,
            })
            .collect()
    }

    #[test]
    fn the_review_tells_which_passwords_match_without_showing_any() {
        let dir = tempfile::tempdir().unwrap();
        let items = [
            login("Site", "https://example.test", "first-secret", 10),
            login("Site", "https://example.test/login", "first-secret", 20),
            login("Site", "https://www.example.test", "other-secret", 30),
        ];
        let groups = find(&state_in(dir.path(), &items)).unwrap();
        let json = serde_json::to_string(&groups).unwrap();
        assert!(!json.contains("secret"), "{json}");
        assert_eq!(groups.len(), 1);
        assert!(!groups[0].possible);
        assert_eq!(groups[0].keep, items[2].id);
        let passwords: Vec<usize> = groups[0].logins.iter().map(|l| l.password).collect();
        assert_eq!(passwords, [0, 1, 1]);
    }

    #[test]
    fn a_merge_that_cannot_be_saved_leaves_the_vault_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocked");
        std::fs::write(&blocker, "not a directory").unwrap();
        let items = [
            login("Site", "https://example.test", "a", 10),
            login("Site", "https://example.test", "b", 20),
        ];
        let state = state_in(&blocker, &items);
        let groups = find(&state).unwrap();
        let choice = Choice {
            keep: groups[0].keep,
            ids: groups[0].logins.iter().map(|l| l.id).collect(),
        };
        assert!(merge(&state, vec![choice], shown(&groups)).is_err());
        assert_eq!(find(&state).unwrap().len(), 1);

        let state = state_in(dir.path(), &items);
        let groups = find(&state).unwrap();
        let choice = Choice {
            keep: groups[0].keep,
            ids: groups[0].logins.iter().map(|l| l.id).collect(),
        };
        assert_eq!(merge(&state, vec![choice], shown(&groups)).unwrap(), 1);
        assert!(find(&state).unwrap().is_empty());
    }
}
