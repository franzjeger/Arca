//! Bookmarks: the extension's folder, kept in the vault.

use uuid::Uuid;
use vault_core::VaultItem;

use crate::state::AppState;

use super::*;

pub(super) fn import_bookmarks(ctx: &mut Ctx, items: Vec<BookmarkWire>) -> Response {
    let state = ctx.state;
    let Ok(mut st) = state.lock() else {
        return error("internal");
    };
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    // The ids, not just a count: a save that fails has to be undone item
    // by item, and nothing else in the vault may be touched.
    let mut added: Vec<Uuid> = Vec::new();
    let now = crate::state::now_millis();
    {
        let Some(vault) = st.vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        if let Ok(active) = vault.active_items() {
            for item in active {
                if let VaultItem::Bookmark { url, folder, .. } = &item.data {
                    seen.insert((url.clone(), folder.clone()));
                }
            }
        }
        for b in items {
            if b.url.is_empty() || !seen.insert((b.url.clone(), b.folder.clone())) {
                continue;
            }
            let item = vault_core::Item::new(
                VaultItem::Bookmark {
                    title: b.title,
                    url: b.url,
                    folder: b.folder,
                    notes: String::new(),
                },
                now,
            );
            let id = item.id;
            if vault.upsert_item(item).is_ok() {
                added.push(id);
            }
        }
    }
    if !added.is_empty() {
        // A bulk insert is what a rollback point is for.
        st.store.snapshot_now();
        let AppState { store, vault, .. } = &mut *st;
        if let Some(v) = vault.as_mut() {
            if store.save_synced(v).is_err() {
                // Undo the whole import. Left in memory it would be
                // deduplicated against on the next run — the extension
                // would be told those bookmarks are already filed while
                // the disk has never heard of them, and they would be
                // gone for good at the next lock.
                for id in &added {
                    let _ = v.purge_item(*id, now);
                }
                return error("internal");
            }
        }
        // Every other bridge write marks dirty; this one didn't, so an
        // import stayed local-only until some unrelated edit pushed it.
        crate::sync::mark_dirty();
    }
    Response::ImportedBookmarks { added: added.len() }
}

pub(super) fn list_bookmarks(ctx: &mut Ctx) -> Response {
    let state = ctx.state;
    let Ok(st) = state.lock() else {
        return error("internal");
    };
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return error("locked");
    };
    let mut items = Vec::new();
    if let Ok(active) = vault.active_items() {
        for item in active {
            if let VaultItem::Bookmark {
                title, url, folder, ..
            } = &item.data
            {
                items.push(BookmarkWire {
                    title: title.clone(),
                    url: url.clone(),
                    folder: folder.clone(),
                });
            }
        }
    }
    Response::Bookmarks { items }
}

pub(super) fn delete_bookmarks(ctx: &mut Ctx, url: String, folder: String) -> Response {
    let state = ctx.state;
    if url.trim().is_empty() && folder.trim().is_empty() {
        // Would match the whole collection. Refused rather than
        // interpreted generously.
        return error("need a url or a folder");
    }
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let removed = {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        let mut hits = Vec::new();
        if let Ok(active) = vault.active_items() {
            for item in active {
                if let VaultItem::Bookmark {
                    url: u, folder: f, ..
                } = &item.data
                {
                    let matches = if url.trim().is_empty() {
                        // A folder went: everything at or under it.
                        f == &folder || f.starts_with(&format!("{folder}/"))
                    } else {
                        u == &url && f == &folder
                    };
                    if matches {
                        hits.push(item.id);
                    }
                }
            }
        }
        if hits.is_empty() {
            0
        } else {
            // A bulk retraction is exactly what a rollback point is for.
            store.snapshot_now();
            let mut deleted = Vec::new();
            for id in hits {
                if vault.delete_item(id, now).is_ok() {
                    deleted.push(id);
                }
            }
            if store.save_synced(vault).is_err() {
                // Restore every one of them. The reply says nothing was
                // removed, and a bookmark that is in the Trash in memory
                // but present on disk is the worst of both: it vanishes
                // from the app now and comes back at the next unlock.
                // Only ids this call actually retracted are restored, so
                // an item already in the Trash stays there.
                for id in &deleted {
                    let _ = vault.restore_item(*id, now);
                }
                return error("internal");
            }
            deleted.len()
        }
    };
    if removed > 0 {
        crate::sync::mark_dirty();
    }
    Response::DeletedBookmarks { removed }
}
