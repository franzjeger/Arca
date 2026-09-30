//! Passwords: matching logins to a page, filling one, saving what a form
//! submitted, and generating new ones. A credential only ever leaves for the
//! page whose host it was saved for.

use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use vault_bridge::proto::LoginMatch;
use vault_core::{Item, VaultItem};

use crate::state::AppState;

use super::*;

/// Whether a credential stored at `stored_url` may be listed for, or filled on,
/// `requested_url`.
///
/// Hosts must match exactly after normalization (`www.` is stripped): trust is
/// not inherited by sibling or subdomains, especially on multi-tenant
/// suffixes. Host equality is not enough either: this also refuses an
/// `https`-to-`http` downgrade and a port change. See [`vault_core::Origin`]
/// for why.
pub(super) fn domain_matches(stored_url: &str, requested_url: &str) -> bool {
    vault_core::origin_of(stored_url).may_fill(&vault_core::origin_of(requested_url))
}

/// Find an active login matching (normalized host, lowercased username).
/// Returns `(id, current_password)` for change detection.
#[cfg(test)]
pub(super) fn find_login(
    vault: &vault_core::Vault,
    host: &str,
    username: &str,
) -> Option<(Uuid, String)> {
    let user = username.to_lowercase();
    for item in vault.active_items().ok()? {
        if let VaultItem::Login {
            url,
            username: un,
            password,
            ..
        } = &item.data
        {
            if host_of(url) == host && un.to_lowercase() == user {
                return Some((item.id, password.clone()));
            }
        }
    }
    None
}

/// Resolve which stored login a save/update should land on.
///
/// With a username we match it by fill-safe origin + username, so distinct
/// accounts and distinct services on different ports stay distinct. A
/// token-based password reset has NO username field
/// — `username` is empty there — yet it is almost always a reset OF an account
/// already in the vault. When that origin has exactly one login we target it:
/// that is the account being reset, and the update keeps its stored username and
/// only replaces the password. Two or more logins for the origin is genuinely
/// ambiguous with no username to disambiguate, so we refuse to guess (guessing
/// could overwrite the wrong account's password) and return None — the caller
/// then files a new entry the user can merge in the app. This never fires on
/// ordinary sign-in pages: those carry a username field, so `username` is
/// non-empty and the exact match applies.
/// A short, non-secret reason for a save that did not reach the disk.
///
/// The browser shows this on the page, so it carries an error *kind* and never
/// a path, a host or anything from the vault. It exists because every distinct
/// way a save can fail — a blocked write, a corrupt file on disk, a vault the
/// running key cannot merge — arrived at the user as the same bare "internal",
/// which is why the same report kept coming back with nothing to act on.
pub(super) fn save_failure_reason(e: &vault_store::Error) -> String {
    match e {
        // The common one, and the one worth naming: another process had the
        // vault file open (Windows) or the write itself failed.
        vault_store::Error::Io(io) => {
            format!("the vault file could not be written ({})", io.kind())
        }
        // A well-formed file the running vault cannot reconcile — a different
        // vault's key, typically after sync replaced the file underneath us.
        vault_store::Error::Core(_) => {
            "the vault file on disk could not be merged with this vault".into()
        }
        _ => "internal".into(),
    }
}

/// The stored logins a save for `username` on `requested_url` is about, as
/// (id, stored username, stored password).
///
/// Every login on the site with that username, not the first: two entries for
/// one account are one account. Updating only the first left the other with
/// the old password, and the next fill that picked it made the update look
/// as if it had never happened. With no username on the page (a token reset)
/// only the site's single login qualifies; with several it is ambiguous, and
/// the save is offered as a new login instead.
pub(super) fn logins_for_save(
    vault: &vault_core::Vault,
    requested_url: &str,
    username: &str,
) -> Vec<(Uuid, String, String)> {
    let Ok(items) = vault.active_items() else {
        return Vec::new();
    };
    let on_site = items.filter_map(|item| match &item.data {
        // Saving has to use the same trust boundary as filling. A host can
        // serve unrelated applications on :443, :9443, :8006, …; host-only
        // matching silently updated the wrong credential.
        VaultItem::Login {
            url,
            username: stored,
            password,
            ..
        } if domain_matches(url.as_str(), requested_url) => {
            Some((item.id, stored.clone(), password.clone()))
        }
        _ => None,
    });
    if username.is_empty() {
        let mut only: Vec<_> = on_site.take(2).collect();
        if only.len() > 1 {
            only.clear();
        }
        return only;
    }
    on_site
        .filter(|(_, stored, _)| stored.eq_ignore_ascii_case(username))
        .collect()
}

pub(super) fn list_matches(ctx: &mut Ctx, url: String) -> Response {
    let state = ctx.state;
    let st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return error("locked");
    };
    let mut items = Vec::new();
    // Passkeys whose rp_id does not match this page directly. Resolved
    // after the lock is released.
    let mut deferred: Vec<(String, LoginMatch)> = Vec::new();
    if let Ok(active) = vault.active_items() {
        for item in active {
            match &item.data {
                VaultItem::Login {
                    url: u,
                    username,
                    title,
                    ..
                } if domain_matches(u, &url) => {
                    items.push(LoginMatch {
                        id: item.id.to_string(),
                        title: title.clone(),
                        username: username.clone(),
                        kind: "password".into(),
                        credential_id: Vec::new(),
                    });
                }
                // Passkeys for this site: surfaced so the picker can
                // show the user a passkey exists. Matched by the same
                // rule the ceremony uses. Those that do not match
                // DIRECTLY are set aside — deciding them needs the
                // relying party's related-origins file, and fetching
                // it under this lock would stall every other command
                // behind a network request.
                VaultItem::Passkey {
                    rp_id,
                    user_name,
                    title,
                    credential_id,
                    ..
                } => {
                    let entry = LoginMatch {
                        id: item.id.to_string(),
                        title: title.clone(),
                        username: user_name.clone(),
                        kind: "passkey".into(),
                        credential_id: credential_id.clone(),
                    };
                    if rp_id_matches_origin(rp_id, &url) {
                        items.push(entry);
                    } else {
                        deferred.push((rp_id.clone(), entry));
                    }
                }
                // Non-matching logins/passkeys and other item kinds
                // (SSH keys, secure notes) are not autofillable here.
                _ => {}
            }
        }
    }
    drop(st);

    // Now the network part, off the lock. Only for passkeys that did not
    // match outright, and only one request per relying party per twelve
    // hours — a vault with no such passkeys does no I/O at all.
    for (rp_id, entry) in deferred {
        if rp_id_allows_origin(&rp_id, &url) {
            items.push(entry);
        }
    }
    Response::Logins { items }
}

pub(super) fn fill(ctx: &mut Ctx, id: String, url: String, picked: bool) -> Response {
    // Picked in Arca's list with the vault locked: open it for this fill,
    // behind one prompt that names the site, and go on with the same login.
    // That fingerprint is also the approval a per-fill confirmation asks for,
    // so it is not asked again below.
    let mut verified = false;
    if picked {
        match (ctx.unlock)(&format!("fill your password on {}", host_of(&url))) {
            RequestUnlock::Verified => verified = true,
            RequestUnlock::AlreadyOpen | RequestUnlock::Unattended => {}
            RequestUnlock::Declined => return error("unlock_cancelled"),
            // The window is asking for the master password; the extension
            // waits for it and sends this same fill again.
            RequestUnlock::Window => return error("unlocking"),
        }
    }
    let state = ctx.state;
    let app = ctx.app;
    let consent = &mut *ctx.consent;
    // Resolve + validate under the lock, then extract just what we need
    // and release it before any (possibly slow) user consent prompt.
    let confirm;
    let username;
    let password;
    let title;
    {
        let st = match state.lock() {
            Ok(s) => s,
            Err(_) => return error("internal"),
        };
        let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        let Ok(uuid) = Uuid::parse_str(&id) else {
            return error("not_found");
        };
        let Ok(item) = vault.get_item(uuid) else {
            return error("not_found");
        };
        // Trashed is trashed. `get_item` answers for deleted items too —
        // it is the Trash view's reader as much as autofill's — so a
        // credential the user retired stayed fillable by id for as long
        // as it sat in the bin. `Match` never offers one (it lists
        // active items), which made this reachable only by an id from an
        // earlier session or from something else on this machine, and
        // invisible to the user either way.
        if item.is_deleted() {
            return error("not_found");
        }
        let VaultItem::Login {
            url: u,
            username: un,
            password: pw,
            title: t,
            ..
        } = &item.data
        else {
            return error("not_found");
        };
        // Origin binding: never hand a credential to a non-matching host.
        if !domain_matches(u, &url) {
            return error("origin_mismatch");
        }
        confirm = st.settings.confirm_autofill;
        username = un.clone();
        password = pw.clone();
        title = t.clone();
    }

    // Optional per-fill consent: the app is the final approver.
    if confirm && !verified {
        let ctx = ConsentContext {
            site: host_of(&url),
            account: username.clone(),
            title: title.clone(),
        };
        if !consent(&ctx) {
            return error("denied");
        }
        // The prompt can outlast the vault: with lock-on-blur, glancing
        // back at the browser while Arca asks locks it, and a credential
        // must not leave after that. Re-check now that the wait is over.
        let locked = state
            .lock()
            .map(|st| !st.vault.as_ref().is_some_and(|v| v.is_unlocked()))
            .unwrap_or(true);
        if locked {
            return error("locked");
        }
    }

    if let Some(app) = app {
        let _ = app.emit("autofilled", format!("{title} ({})", host_of(&url)));
    }
    Response::Credentials { username, password }
}

pub(super) fn save_probe(
    ctx: &mut Ctx,
    url: String,
    username: String,
    password: String,
) -> Response {
    let state = ctx.state;
    if password.is_empty() {
        return Response::SaveDecision {
            action: "known".into(), // nothing worth saving
            username: None,
        };
    }
    let st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    if !st.settings.save_prompt {
        return Response::SaveDecision {
            action: "disabled".into(),
            username: None,
        };
    }
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Response::SaveDecision {
            action: "locked".into(),
            username: None,
        };
    };
    let host = host_of(&url);
    if host.is_empty() {
        return Response::SaveDecision {
            action: "disabled".into(),
            username: None,
        };
    }
    let matches = logins_for_save(vault, &url, &username);
    // "known" only when every copy of the account already has it: one stale
    // duplicate is exactly the update that went missing before.
    let stale = matches.iter().find(|(_, _, cur)| *cur != password);
    let (action, target) = match (matches.is_empty(), stale) {
        (true, _) => ("new", None),
        (false, None) => ("known", None),
        (false, Some((_, stored, _))) => ("update", Some(stored.clone())),
    };
    Response::SaveDecision {
        action: action.into(),
        username: target,
    }
}

pub(super) fn save_login(
    ctx: &mut Ctx,
    url: String,
    username: String,
    password: String,
) -> Response {
    let state = ctx.state;
    let app = ctx.app;
    if password.is_empty() {
        return error("empty");
    }
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    if !st.settings.save_prompt {
        return error("disabled");
    }
    let host = host_of(&url);
    if host.is_empty() {
        return error("invalid");
    }
    {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        let matches = logins_for_save(vault, &url, &username);
        if matches.is_empty() {
            // Brand-new login for this site.
            let item = Item::new(
                VaultItem::Login {
                    title: host.clone(),
                    username,
                    password,
                    url,
                    totp_secret: None,
                    notes: String::new(),
                },
                crate::state::now_millis(),
            );
            let new_id = item.id;
            if vault.upsert_item(item).is_err() {
                return error("internal");
            }
            if let Err(e) = store.save_synced(vault) {
                // An entry that never reached the disk must not sit in memory
                // claiming the site is already saved. Purged rather than
                // soft-deleted — it was never a vault entry, and it must not
                // surface in the Trash as something the user could restore.
                let _ = vault.purge_item(new_id, crate::state::now_millis());
                return error(save_failure_reason(&e));
            }
        } else {
            // Same site and username, new password: every copy of the
            // account that does not have it yet, updated in place. The old
            // password goes to each one's history.
            let stale: Vec<Uuid> = matches
                .into_iter()
                .filter(|(_, _, current)| *current != password)
                .map(|(id, _, _)| id)
                .collect();
            if stale.is_empty() {
                // Already stored with this password: nothing to do.
                return Response::Saved;
            }
            let mut before = Vec::with_capacity(stale.len());
            for id in stale {
                let Ok(mut item) = vault.get_item(id) else {
                    put_back(vault, before);
                    return error("internal");
                };
                before.push(item.clone());
                if let VaultItem::Login {
                    password: stored, ..
                } = &mut item.data
                {
                    stored.clone_from(&password);
                }
                item.modified_at = crate::state::now_millis();
                if vault.upsert_item(item).is_err() {
                    put_back(vault, before);
                    return error("internal");
                }
            }
            if let Err(e) = store.save_synced(vault) {
                // Put the OLD passwords back. The disk still has them, so
                // leaving the new one in memory makes the two disagree, and
                // the vault is the copy the user is shown: the next probe
                // answers "known" (no save bar, nothing to click again) and
                // the next save returns Saved, while the password that was
                // actually typed exists nowhere after the app quits. An
                // honest failure the browser can retry is worth more than a
                // lost secret.
                put_back(vault, before);
                return error(save_failure_reason(&e));
            }
        }
    }
    crate::sync::mark_dirty();
    if let Some(app) = app {
        let _ = app.emit("login-saved", host);
    }
    Response::Saved
}

/// Logins as they were before a save that went no further, newest change
/// undone first.
fn put_back(vault: &mut vault_core::Vault, items: Vec<Item>) {
    for item in items.into_iter().rev() {
        let _ = vault.upsert_item(item);
    }
}

/// A generator request over the bridge. Clamped rather than refused: a site
/// that caps passwords at 16 is a real thing, and failing the request would
/// send the user to type one themselves, the outcome generating exists to
/// avoid.
pub(super) fn generator(
    length: Option<usize>,
    symbols: Option<bool>,
    default_length: usize,
) -> vault_core::password::PasswordOptions {
    vault_core::password::PasswordOptions {
        length: length.unwrap_or(default_length).clamp(8, 64),
        symbols: symbols.unwrap_or(true),
        ..Default::default()
    }
}

pub(super) fn generate(opts: vault_core::password::PasswordOptions) -> Response {
    match vault_core::password::generate_password(&opts) {
        Ok(pw) => Response::GeneratedPassword {
            password: pw.to_string(),
        },
        Err(_) => error("internal"),
    }
}

pub(super) fn create_login(
    ctx: &mut Ctx,
    title: String,
    username: String,
    url: String,
    notes: String,
    opts: vault_core::password::PasswordOptions,
    reveal: bool,
) -> Response {
    let state = ctx.state;
    if title.trim().is_empty() {
        return error("title_required");
    }
    let Ok(password) = vault_core::password::generate_password(&opts) else {
        return error("internal");
    };
    let password = password.to_string();

    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let id = {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        let item = vault_core::Item::new(
            VaultItem::Login {
                title: title.clone(),
                username: username.clone(),
                password: password.clone(),
                url: url.clone(),
                totp_secret: None,
                notes: notes.clone(),
            },
            crate::state::now_millis(),
        );
        let id = item.id;
        if vault.upsert_item(item).is_err() {
            return error("internal");
        }
        if store.save_synced(vault).is_err() {
            // The caller is told the creation failed, so the login must
            // not exist anywhere afterwards. Left in memory it would be
            // the credential a provisioning script believes it did not
            // create — offered by autofill until the app quits, then
            // gone, with the account on the far end still expecting it.
            let _ = vault.purge_item(id, crate::state::now_millis());
            return error("internal");
        }
        id
    };
    crate::sync::mark_dirty();
    Response::CreatedLogin {
        id: id.to_string(),
        title,
        password: if reveal { Some(password) } else { None },
    }
}

pub(super) fn delete_item(ctx: &mut Ctx, id: String) -> Response {
    let state = ctx.state;
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return error("invalid_id");
    };
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let title = {
        let AppState { store, vault, .. } = &mut *st;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            return error("locked");
        };
        // Read the title BEFORE deleting, so the reply can say what
        // went even though the item is now flagged.
        let Ok(item) = vault.get_item(uuid) else {
            return error("not_found");
        };
        // Already in the Trash: `get_item` finds it, `delete_item`
        // cheerfully re-stamps it, and the reply claimed a retraction
        // that did not happen. An offboarding script that reads that as
        // "this account's credential was live and is now gone" is being
        // told something untrue. The bridge only ever sees active items
        // anyway, so from its side the item is simply not there.
        if item.is_deleted() {
            return error("not_found");
        }
        let title = item.data.title().to_string();
        if vault.delete_item(uuid, now).is_err() {
            return error("internal");
        }
        if store.save_synced(vault).is_err() {
            // Take it back out of the Trash. The disk still has it
            // active, so leaving it deleted in memory hides a credential
            // the user still has — until the next unlock re-reads the
            // file and it reappears with no explanation. Safe because
            // the item was demonstrably NOT deleted a moment ago.
            let _ = vault.restore_item(uuid, now);
            return error("internal");
        }
        title
    };
    crate::sync::mark_dirty();
    Response::Deleted { id, title }
}

pub(super) fn read_password(ctx: &mut Ctx, id: String) -> Response {
    let state = ctx.state;
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return error("invalid_id");
    };
    let st = match state.lock() {
        Ok(s) => s,
        Err(_) => return error("internal"),
    };
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return error("locked");
    };
    match vault.get_item(uuid) {
        // A trashed login is not a login you can read, for the same
        // reason `fill` refuses one: the user retired that credential,
        // and nothing in the app still offers it. `get_item` serves the
        // Trash view as well as this one, so the filter has to be here.
        Ok(item) if item.is_deleted() => error("not_found"),
        Ok(item) => match &item.data {
            VaultItem::Login { password, .. } => Response::Password {
                password: password.clone(),
            },
            _ => error("not_a_login"),
        },
        Err(_) => error("not_found"),
    }
}

/// Production consent: emit the request to the frontend, bring the window
/// forward, and block this bridge thread until the user answers (or times out,
/// which denies). Returns `true` only on an explicit Allow.
pub(super) fn request_consent(app: &AppHandle, ctx: &ConsentContext) -> bool {
    let consent_id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        let pending = app.state::<PendingConsents>();
        let Ok(mut map) = pending.0.lock() else {
            return false;
        };
        map.insert(consent_id.clone(), tx);
    }
    let _ = app.emit(
        "fill-consent-request",
        serde_json::json!({
            "id": consent_id,
            "site": ctx.site,
            "account": ctx.account,
            "title": ctx.title,
        }),
    );
    // Surface the prompt over the browser the user is filling into.
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
    let approved = rx.recv_timeout(CONSENT_TIMEOUT).unwrap_or(false);
    // Drop the sender if it's still registered (timeout path).
    if let Ok(mut map) = app.state::<PendingConsents>().0.lock() {
        map.remove(&consent_id);
    }
    approved
}

/// Deliver a user's Allow/Deny decision to the parked bridge thread.
pub fn resolve_consent(app: &AppHandle, id: &str, approved: bool) {
    if let Ok(mut map) = app.state::<PendingConsents>().0.lock() {
        if let Some(tx) = map.remove(id) {
            let _ = tx.send(approved);
        }
    }
}
