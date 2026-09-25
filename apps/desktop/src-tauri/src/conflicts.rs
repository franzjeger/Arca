use crate::{
    commands::{guard, persist, write_guard},
    state::{now_millis, AppState, CmdError},
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;
use uuid::Uuid;
use vault_core::{conflicts as core, Item};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparisonField {
    key: String,
    original: String,
    copy: String,
    different: bool,
    secret: bool,
    revealable: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    original_revision: Uuid,
    copy_revision: Uuid,
    fields: Vec<ComparisonField>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewedPair {
    original_id: Uuid,
    copy_id: Uuid,
    original_revision: Uuid,
    copy_revision: Uuid,
}

fn pair(state: &AppState, original: Uuid, copy: Uuid) -> Result<(Item, Item), CmdError> {
    let vault = state.vault()?;
    let original = vault.get_item(original)?;
    let copy = vault.get_item(copy)?;
    core::validate_pair(&original, &copy)?;
    Ok((original, copy))
}

fn check_review(pair: &ReviewedPair, original: &Item, copy: &Item) -> Result<(), CmdError> {
    if original.revision != pair.original_revision || copy.revision != pair.copy_revision {
        return Err(CmdError::new(
            "conflict_changed",
            "These entries changed. Refresh the comparison.",
        ));
    }
    Ok(())
}

fn compare(original: &Item, copy: &Item) -> Comparison {
    let fields = core::field_keys(original.data.kind())
        .iter()
        .map(|key| {
            if *key == "credential" {
                let mut left = original.data.clone();
                let mut right = copy.data.clone();
                core::set_title(&mut left, String::new());
                core::set_title(&mut right, String::new());
                return ComparisonField {
                    key: (*key).into(),
                    original: "Complete credential".into(),
                    copy: "Complete credential".into(),
                    different: left != right,
                    secret: true,
                    revealable: false,
                };
            }
            let (left, secret) = core::text_field(original, key).unwrap_or(("", false));
            let (right, _) = core::text_field(copy, key).unwrap_or(("", false));
            let title;
            let right = if *key == "title" {
                title = core::original_copy_title(copy);
                &title
            } else {
                right
            };
            let display = |value: &str| {
                if secret && !value.is_empty() {
                    "Hidden".to_owned()
                } else {
                    value.to_owned()
                }
            };
            ComparisonField {
                key: (*key).into(),
                original: display(left),
                copy: display(right),
                different: left != right,
                secret,
                revealable: secret,
            }
        })
        .collect();
    Comparison {
        original_revision: original.revision,
        copy_revision: copy.revision,
        fields,
    }
}

#[tauri::command]
pub fn compare_sync_conflict(
    state: State<'_, Mutex<AppState>>,
    original_id: Uuid,
    copy_id: Uuid,
) -> Result<Comparison, CmdError> {
    let state = guard(state.inner())?;
    let (original, copy) = pair(&state, original_id, copy_id)?;
    Ok(compare(&original, &copy))
}

#[tauri::command]
pub fn reveal_conflict_field(
    state: State<'_, Mutex<AppState>>,
    reviewed: ReviewedPair,
    field: String,
) -> Result<(String, String), CmdError> {
    let mut state = guard(state.inner())?;
    let (original, copy) = pair(&state, reviewed.original_id, reviewed.copy_id)?;
    check_review(&reviewed, &original, &copy)?;
    let (left, secret) = core::text_field(&original, &field)
        .ok_or_else(|| CmdError::new("invalid_field", "This field cannot be revealed."))?;
    let (right, _) = core::text_field(&copy, &field)
        .ok_or_else(|| CmdError::new("invalid_field", "This field cannot be revealed."))?;
    if !secret {
        return Err(CmdError::new(
            "invalid_field",
            "This field does not need to be revealed.",
        ));
    }
    state.touch();
    Ok((left.to_owned(), right.to_owned()))
}

fn resolve(
    state: &Mutex<AppState>,
    reviewed: ReviewedPair,
    action: core::Resolution,
    fields: &[String],
) -> Result<(), CmdError> {
    let mut state = write_guard(state)?;
    let (original, copy) = pair(&state, reviewed.original_id, reviewed.copy_id)?;
    check_review(&reviewed, &original, &copy)?;
    state
        .vault
        .as_mut()
        .ok_or_else(CmdError::no_vault)?
        .resolve_sync_conflict(
            original.id,
            copy.id,
            (reviewed.original_revision, reviewed.copy_revision),
            action,
            fields,
            now_millis(),
        )?;
    persist(&mut state)?;
    state.touch();
    Ok(())
}

#[tauri::command]
pub fn resolve_sync_conflict(
    state: State<'_, Mutex<AppState>>,
    reviewed: ReviewedPair,
    action: core::Resolution,
    fields: Vec<String>,
) -> Result<(), CmdError> {
    resolve(state.inner(), reviewed, action, &fields)
}

#[tauri::command]
pub fn keep_sync_conflict_copy(
    state: State<'_, Mutex<AppState>>,
    copy_id: Uuid,
) -> Result<(), CmdError> {
    let mut state = write_guard(state.inner())?;
    state
        .vault
        .as_mut()
        .ok_or_else(CmdError::no_vault)?
        .keep_sync_conflict_copy(copy_id, now_millis())?;
    persist(&mut state)?;
    state.touch();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{item::SyncConflict, KdfParams, Vault, VaultItem};

    #[test]
    fn preview_redacts_secrets_and_failed_persistence_restores_both_revisions() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocked");
        std::fs::write(&blocker, "not a directory").unwrap();
        let store = vault_store::VaultStore::new(blocker.join("vault"), "test", "conflict");
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        let mut params = KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        params.p_cost = 1;
        let mut vault = Vault::create("master", params).unwrap();
        let original = Item::new(
            VaultItem::SecureNote {
                title: "Note".into(),
                body: "original-secret-note".into(),
            },
            1,
        );
        let mut copy = Item::new(
            VaultItem::SecureNote {
                title: "Note (sync conflict)".into(),
                body: "copy-secret-note".into(),
            },
            2,
        );
        copy.sync_conflict = Some(SyncConflict {
            original_id: original.id,
            original_title: "Note".into(),
            resolved: false,
        });
        let preview = serde_json::to_string(&compare(&original, &copy)).unwrap();
        assert!(!preview.contains("original-secret-note"));
        assert!(!preview.contains("copy-secret-note"));
        assert!(preview.contains("Hidden"));
        vault.upsert_item(original.clone()).unwrap();
        vault.upsert_item(copy.clone()).unwrap();
        let state = Mutex::new(AppState::new(store, Some(vault), clipboard));
        let reviewed = ReviewedPair {
            original_id: original.id,
            copy_id: copy.id,
            original_revision: original.revision,
            copy_revision: copy.revision,
        };
        assert!(resolve(&state, reviewed, core::Resolution::Merge, &["body".into()]).is_err());
        let state = state.lock().unwrap();
        let vault = state.vault().unwrap();
        assert_eq!(vault.get_item(original.id).unwrap(), original);
        assert_eq!(vault.get_item(copy.id).unwrap(), copy);
        assert_eq!(vault.list_items(true).unwrap().len(), 2);
    }
}
