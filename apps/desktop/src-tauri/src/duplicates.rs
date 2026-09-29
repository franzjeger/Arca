//! Find & merge duplicate logins: found for someone to look over, merged the
//! way they chose.

use crate::{
    commands::{guard, persist, write_guard},
    state::{now_millis, AppState, CmdError},
};
use serde::Deserialize;
use std::sync::Mutex;
use tauri::State;
use uuid::Uuid;
use vault_core::dedupe::{DuplicateReview, MergeChoice};

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

/// Groups of logins that look like one account. Changes nothing.
#[tauri::command]
pub fn find_duplicates(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<DuplicateReview>, CmdError> {
    find(state.inner())
}

fn find(state: &Mutex<AppState>) -> Result<Vec<DuplicateReview>, CmdError> {
    let state = guard(state)?;
    Ok(state.vault()?.review_duplicate_logins()?)
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
    use vault_core::{Item, KdfParams, Vault, VaultItem};

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

    fn shown(groups: &[DuplicateReview]) -> Vec<Shown> {
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
