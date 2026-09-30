// A test reads as one scenario, top to bottom; splitting it hides the story.
#![allow(clippy::too_many_lines)]

use super::*;
use crate::clipboard::ClipboardManager;
use crate::commands::{do_upsert_item, LoginInput};
use crate::state::AppState;
use std::time::Instant;
use tempfile::TempDir;
use uuid::Uuid;
use vault_bridge::proto::Request;
use vault_core::VaultItem;
use vault_core::{KdfAlgorithm, KdfParams, Vault};
use vault_store::VaultStore;

/// A consent closure that always approves, for tests that are not about the
/// in-app Allow/Deny.
fn allow() -> impl FnMut(&ConsentContext) -> bool {
    |_| true
}

/// The nag has to actually END. The original design suppressed for a fixed
/// 90 seconds, which just meant a fresh Touch ID prompt every 90 seconds
/// forever — and from the user's chair that is not a cooldown at all.
#[test]
fn declining_repeatedly_eventually_silences_a_site_for_good() {
    let key = "github.com/get-nag-test";
    clear_passkey_decline(key);

    // Bounded independently of the constant under test. A loop whose length
    // IS that constant hangs instead of failing when the value is wrong,
    // which is the least useful way for a test to react to a regression.
    // That the limit fits inside this bound is checked where it is declared,
    // at compile time.
    const TRIES: u32 = 10;

    let mut announcements = 0;
    for _ in 0..TRIES {
        if record_passkey_decline(key) {
            announcements += 1;
        }
        assert!(
            passkey_suppressed(key),
            "silent immediately after a decline"
        );
    }
    assert_eq!(
        announcements, 1,
        "the permanent stop is announced exactly once, not on every later attempt"
    );

    // Past the limit the elapsed time stops mattering: no window reopens,
    // which is the whole difference from the old behaviour.
    {
        let mut map = passkey_decline_map();
        let decline = map.get_mut(key).unwrap();
        decline.at = Instant::now() - Duration::from_secs(24 * 60 * 60);
    }
    assert!(
        passkey_suppressed(key),
        "a day later it must STILL be silent, or the nag simply resumes"
    );

    // An approval is the way back: a genuine sign-in later must not be
    // swallowed by a refusal the user has no way to see.
    clear_passkey_decline(key);
    assert!(!passkey_suppressed(key));
}

/// Before the limit, silence expires — declining once must not lock a site
/// out of a real sign-in an hour later.
#[test]
fn an_early_decline_expires_instead_of_locking_the_site_out() {
    let key = "example.com/get-expiry-test";
    clear_passkey_decline(key);

    record_passkey_decline(key);
    assert!(passkey_suppressed(key));

    {
        let mut map = passkey_decline_map();
        map.get_mut(key).unwrap().at = Instant::now() - Duration::from_secs(120);
    }
    assert!(
        !passkey_suppressed(key),
        "one decline is a snooze, not a ban"
    );
    clear_passkey_decline(key);
}

fn cheap_params() -> KdfParams {
    KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![5u8; KdfParams::SALT_LEN],
    }
}

fn unlocked_state(dir: &TempDir) -> Mutex<AppState> {
    let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    let vault = Vault::create("pw", cheap_params()).unwrap();
    let (clip, _) = ClipboardManager::memory();
    Mutex::new(AppState::new(store, Some(vault), clip))
}

fn add(state: &Mutex<AppState>, title: &str, user: &str, pw: &str, url: &str) -> String {
    do_upsert_item(
        state,
        LoginInput {
            id: None,
            title: title.into(),
            username: user.into(),
            password: pw.into(),
            url: url.into(),
            totp_secret: None,
            notes: String::new(),
        },
    )
    .unwrap()
}

/// Point the state's store at a path nothing can be written to, so every
/// save fails the way a full disk, a revoked permission or a vanished
/// network volume would.
///
/// `blocked` is a FILE, and the store wants to create its lock file in a
/// directory of that name — impossible on every platform, and it fails
/// before the vault file is read or touched, so the disk still holds
/// exactly what the last successful save put there. That is the situation
/// the rollbacks exist for: the in-memory vault must not drift away from
/// it.
fn break_the_store(state: &Mutex<AppState>, dir: &TempDir) {
    let blocked = dir.path().join("blocked");
    std::fs::write(&blocked, b"not a directory").unwrap();
    state.lock().unwrap().store = VaultStore::new(blocked.join("v.vault"), "svc", "acct");
}

/// A save that fails must not leave the password in memory, and must say why.
///
/// This is the quiet way a password manager loses a password. The handler
/// reports the failure, the browser shows the save failed — and the vault in
/// memory has the new password anyway, so the next probe answers "known"
/// (no save bar, nothing to click again) and the next save answers Saved.
/// Nothing ever writes it, and quitting the app takes it with it.
///
/// The message is asserted too, loosely. Every one of these failures used to
/// arrive as a bare "internal", which is why the same report came back
/// repeatedly with nothing to act on. It must also not read as a LOCKED vault:
/// content.js matches /locked|not running|unreachable/i to decide whether to
/// send the user through an unlock before retrying, and a write error dressed
/// up as a lock sends them somewhere that cannot help.
/// The save failed, it said so in terms the user can act on, and it did not
/// masquerade as a locked vault (which would send the browser into an unlock
/// that cannot fix a write error).
fn writes_failed(message: &str) -> bool {
    let looks_locked = ["locked", "not running", "unreachable"]
        .iter()
        .any(|needle| message.to_lowercase().contains(needle));
    message.contains("could not be written") && !looks_locked
}

#[test]
fn a_save_that_never_reached_the_disk_is_rolled_back_out_of_memory() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let request =
        |req, authed: &mut Session| handle_request(req, &state, "t", authed, None, &mut allow());
    let stored_password = |host: &str, user: &str| {
        let st = state.lock().unwrap();
        find_login(st.vault.as_ref().unwrap(), host, user).map(|(_, pw)| pw)
    };

    // One login that genuinely reached the disk, to update later.
    assert_eq!(
        request(
            Request::SaveLogin {
                url: "https://github.com/login".into(),
                username: "frank".into(),
                password: "first-pw".into(),
            },
            &mut authed,
        ),
        Response::Saved
    );

    break_the_store(&state, &dir);

    // A brand-new login for a site the vault has never seen.
    assert!(matches!(
        request(
            Request::SaveLogin {
                url: "https://gitlab.com/login".into(),
                username: "frank".into(),
                password: "never-persisted".into(),
            },
            &mut authed,
        ),
        Response::Error { message } if writes_failed(&message)
    ));
    assert_eq!(
        stored_password("gitlab.com", "frank"),
        None,
        "an entry that never reached the disk must not be in the vault"
    );
    assert!(
        matches!(
            request(
                Request::SaveProbe {
                    url: "https://gitlab.com/login".into(),
                    username: "frank".into(),
                    password: "never-persisted".into(),
                },
                &mut authed,
            ),
            Response::SaveDecision { action, .. } if action == "new"
        ),
        "the save bar has to come back; 'known' is how the password is lost"
    );

    // ...and an update to the one that IS on disk.
    assert!(matches!(
        request(
            Request::SaveLogin {
                url: "https://github.com/login".into(),
                username: "frank".into(),
                password: "changed-pw".into(),
            },
            &mut authed,
        ),
        Response::Error { message } if writes_failed(&message)
    ));
    assert_eq!(
        stored_password("github.com", "frank"),
        Some("first-pw".to_string()),
        "memory must still agree with the file, or the old password is gone too"
    );
    assert!(matches!(
        request(
            Request::SaveProbe {
                url: "https://github.com/login".into(),
                username: "frank".into(),
                password: "changed-pw".into(),
            },
            &mut authed,
        ),
        Response::SaveDecision { action, .. } if action == "update"
    ));
}

/// Two entries for one account are one account. An update that reached only
/// the first left the other on the old password, and the next fill that
/// picked it made the update look as if it had never happened.
#[test]
fn an_update_reaches_every_copy_of_the_account() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let request =
        |req, authed: &mut Session| handle_request(req, &state, "t", authed, None, &mut allow());
    let site = "https://github.com/settings/password";
    let first = add(&state, "GitHub", "frank", "old-pw", "https://github.com");
    let copy = add(
        &state,
        "GitHub (2)",
        "Frank",
        "old-pw",
        "https://github.com/login",
    );
    add(
        &state,
        "GitHub",
        "someone-else",
        "theirs",
        "https://github.com",
    );
    let passwords = |user: &str| -> Vec<String> {
        let st = state.lock().unwrap();
        let mut found: Vec<String> = st
            .vault
            .as_ref()
            .unwrap()
            .active_items()
            .unwrap()
            .filter_map(|item| match &item.data {
                VaultItem::Login {
                    username, password, ..
                } if username.eq_ignore_ascii_case(user) => Some(password.clone()),
                _ => None,
            })
            .collect();
        found.sort();
        found
    };
    let probe = |password: &str, authed: &mut Session| match request(
        Request::SaveProbe {
            url: site.into(),
            username: "frank".into(),
            password: password.into(),
        },
        authed,
    ) {
        Response::SaveDecision { action, .. } => action,
        other => panic!("not a decision: {other:?}"),
    };
    let save = |password: &str, authed: &mut Session| {
        request(
            Request::SaveLogin {
                url: site.into(),
                username: "frank".into(),
                password: password.into(),
            },
            authed,
        )
    };

    assert_eq!(probe("new-pw", &mut authed), "update");
    assert_eq!(save("new-pw", &mut authed), Response::Saved);
    assert_eq!(passwords("frank"), ["new-pw", "new-pw"], "both copies");
    assert_eq!(passwords("someone-else"), ["theirs"], "not another account");
    assert_eq!(probe("new-pw", &mut authed), "known");
    {
        let st = state.lock().unwrap();
        let vault = st.vault.as_ref().unwrap();
        for id in [&first, &copy] {
            let item = vault.get_item(id.parse().unwrap()).unwrap();
            assert!(
                item.password_history.iter().any(|h| h.password == "old-pw"),
                "the old password is kept in each copy's history"
            );
        }
    }

    // One copy changed by hand since, the other still on the password
    // before: the update is still offered, and it reaches the stale copy.
    do_upsert_item(
        &state,
        LoginInput {
            id: Some(copy),
            title: "GitHub (2)".into(),
            username: "Frank".into(),
            password: "newest-pw".into(),
            url: "https://github.com/login".into(),
            totp_secret: None,
            notes: String::new(),
        },
    )
    .unwrap();
    assert_eq!(probe("newest-pw", &mut authed), "update");
    assert_eq!(save("newest-pw", &mut authed), Response::Saved);
    assert_eq!(passwords("frank"), ["newest-pw", "newest-pw"]);
}

/// The same trade for every other bridge write: a create that failed must
/// leave nothing behind, and a delete that failed must not hide an item the
/// disk still has. A vault that disagrees with its file always resolves the
/// wrong way — at the next unlock the file wins, and whatever the user saw
/// in between was a lie.
#[test]
fn a_failed_persist_leaves_creates_deletes_and_imports_undone() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let request =
        |req, authed: &mut Session| handle_request(req, &state, "t", authed, None, &mut allow());
    let active = || {
        let st = state.lock().unwrap();
        st.vault.as_ref().unwrap().list_items(false).unwrap()
    };

    // Seed a login and a bookmark that really are on disk.
    let Response::CreatedLogin { id: kept, .. } = request(
        Request::CreateLogin {
            title: "Kept".into(),
            username: "frank".into(),
            url: "https://example.com".into(),
            notes: String::new(),
            length: Some(16),
            symbols: Some(false),
            reveal: false,
        },
        &mut authed,
    ) else {
        panic!("the seed login must be created");
    };
    assert_eq!(
        request(
            Request::ImportBookmarks {
                items: vec![BookmarkWire {
                    title: "Docs".into(),
                    url: "https://example.com/docs".into(),
                    folder: "Work".into(),
                }],
            },
            &mut authed,
        ),
        Response::ImportedBookmarks { added: 1 }
    );

    break_the_store(&state, &dir);

    // CreateLogin: the caller is told it failed, so the credential must not
    // exist — least of all one autofill would offer until the app quits.
    assert!(matches!(
        request(
            Request::CreateLogin {
                title: "Ghost".into(),
                username: "frank".into(),
                url: "https://ghost.example".into(),
                notes: String::new(),
                length: Some(16),
                symbols: Some(false),
                reveal: false,
            },
            &mut authed,
        ),
        Response::Error { message } if message == "internal"
    ));
    assert!(
        !active().iter().any(|s| s.title == "Ghost"),
        "a login whose save failed must not be in the vault"
    );

    // DeleteItem: the item is still on disk, so it must still be active.
    assert!(matches!(
        request(Request::DeleteItem { id: kept.clone() }, &mut authed),
        Response::Error { message } if message == "internal"
    ));
    assert!(
        active().iter().any(|s| s.id.to_string() == kept),
        "a delete that was not persisted must not hide the item"
    );

    // DeleteBookmarks: same, in bulk.
    assert!(matches!(
        request(
            Request::DeleteBookmarks {
                url: "https://example.com/docs".into(),
                folder: "Work".into(),
            },
            &mut authed,
        ),
        Response::Error { message } if message == "internal"
    ));
    assert!(
        active().iter().any(|s| s.url == "https://example.com/docs"),
        "bookmarks the disk still has must not vanish from the app"
    );

    // ImportBookmarks: nothing added, so the next run offers them again
    // instead of deduplicating against entries that were never written.
    assert!(matches!(
        request(
            Request::ImportBookmarks {
                items: vec![BookmarkWire {
                    title: "Handbook".into(),
                    url: "https://example.com/handbook".into(),
                    folder: "Work".into(),
                }],
            },
            &mut authed,
        ),
        Response::Error { message } if message == "internal"
    ));
    assert!(
        !active()
            .iter()
            .any(|s| s.url == "https://example.com/handbook"),
        "an import that failed to persist must leave nothing to deduplicate against"
    );
}

/// A page on `www.example.com` that omits `rp.id` gets `www.example.com` as
/// the default rpId. Stripping `www.` the way password matching does turned
/// that into a mismatch against its own origin: registration and sign-in
/// were both refused, and a passkey already stored under a `www.` rpId
/// could never be used again.
#[test]
fn a_www_page_may_use_its_own_hostname_as_the_rp_id() {
    assert!(rp_id_matches_origin(
        "www.example.com",
        "https://www.example.com/login"
    ));
    // The registrable domain still works from a `www.` page — a site that
    // DOES set rp.id explicitly must keep working.
    assert!(rp_id_matches_origin(
        "example.com",
        "https://www.example.com/login"
    ));
    // The binding is not loosened: an rpId must still be the origin's host
    // or a parent of it, and never someone else's domain.
    assert!(!rp_id_matches_origin(
        "www.example.com",
        "https://example.com/login"
    ));
    assert!(!rp_id_matches_origin("www.example.com", "https://evil.com"));
    assert!(!rp_id_matches_origin(
        "www.example.com",
        "https://www.example.com.evil.com"
    ));

    // End to end: register on the www page and sign in with it.
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let credential_id = match handle_request(
        Request::PasskeyCreate {
            origin: "https://www.example.com/signup".into(),
            rp_id: "www.example.com".into(),
            user_name: "frank".into(),
            user_handle: vec![7, 7, 7],
            exclude_credentials: vec![],
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    ) {
        Response::PasskeyCredential { credential_id, .. } => credential_id,
        other => panic!("a www page must be able to register, got {other:?}"),
    };
    assert!(matches!(
        handle_request(
            Request::PasskeyGet {
                origin: "https://www.example.com/login".into(),
                rp_id: "www.example.com".into(),
                client_data_hash: vec![4u8; 32],
                allow_credentials: vec![credential_id],

                picked: false,
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        ),
        Response::PasskeyAssertion { .. }
    ));
}

/// Touch ID succeeding is not the vault opening.
///
/// The unlock handler used to discard the result of `quick_unlock` and emit
/// "vault-unlocked" regardless. With quick unlock never enabled — or its
/// device key no longer unwrapping this header — the frontend dropped its
/// lock screen over a locked vault, the extension re-requested an unlock,
/// and the user got a biometric prompt every few seconds, each one leading
/// nowhere.
#[test]
fn a_quick_unlock_that_did_not_happen_is_reported_as_failure() {
    let dir = TempDir::new().unwrap();
    let store = VaultStore::new(
        dir.path().join("v.vault"),
        // A keychain name nothing else uses, so "no device key" is a fact
        // of this test rather than of the machine it runs on.
        "arca-test-quick-unlock-absent",
        "acct",
    );
    let mut vault = Vault::create("pw", cheap_params()).unwrap();
    vault.lock().unwrap();
    let (clip, _) = ClipboardManager::memory();
    let state = Mutex::new(AppState::new(store, Some(vault), clip));

    let idle_before = {
        let mut st = state.lock().unwrap();
        st.last_activity = Instant::now() - Duration::from_secs(120);
        st.last_activity
    };

    assert!(
        !try_device_unlock(&state),
        "quick unlock is not enabled here, so it cannot have unlocked anything"
    );
    assert!(
        !state.lock().unwrap().vault.as_ref().unwrap().is_unlocked(),
        "the vault is still locked; announcing otherwise is the bug"
    );
    assert_eq!(
        state.lock().unwrap().last_activity,
        idle_before,
        "an unlock that did not happen is not the user using Arca"
    );
}

/// An item in the Trash is retired, and the app stops offering it — but
/// `get_item` serves the Trash view too, so `fill` and `read_password`
/// handed the credential out by id anyway. The picker hides it, which is
/// what makes this invisible: the user believes that password is gone.
#[test]
fn a_trashed_login_is_neither_filled_nor_read_nor_deleted_twice() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let request =
        |req, authed: &mut Session| handle_request(req, &state, "t", authed, None, &mut allow());
    let id = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");

    // While it is active, both work — the refusal below has to come from
    // the deletion and nothing else.
    assert_eq!(
        request(
            Request::Fill {
                id: id.clone(),
                url: "https://github.com/login".into(),
                picked: false,
            },
            &mut authed,
        ),
        Response::Credentials {
            username: "frank".into(),
            password: "gh-pw".into(),
        }
    );
    assert!(matches!(
        request(Request::ReadPassword { id: id.clone() }, &mut authed),
        Response::Password { password } if password == "gh-pw"
    ));

    assert!(matches!(
        request(Request::DeleteItem { id: id.clone() }, &mut authed),
        Response::Deleted { .. }
    ));

    assert!(matches!(
        request(
            Request::Fill {
                id: id.clone(),
                url: "https://github.com/login".into(),
                picked: false,
            },
            &mut authed,
        ),
        Response::Error { message } if message == "not_found"
    ));
    assert!(matches!(
        request(Request::ReadPassword { id: id.clone() }, &mut authed),
        Response::Error { message } if message == "not_found"
    ));
    // And retracting it a second time must not report a retraction that did
    // not happen — an offboarding script reads that as "it was live".
    assert!(matches!(
        request(Request::DeleteItem { id }, &mut authed),
        Response::Error { message } if message == "not_found"
    ));
}

/// The passkey prompt can outlast the vault, exactly as a fill's can: the
/// private key is read before the wait, and idle or blur lock can fire while
/// the user is looking at the dialog. Signing after that would let a locked
/// vault authenticate a sign-in.
#[test]
fn a_passkey_get_that_outlasts_the_lock_refuses_to_sign() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;

    let credential_id = match handle_request(
        Request::PasskeyCreate {
            origin: "https://github.com".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![1, 2, 3],
            exclude_credentials: vec![],
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    ) {
        Response::PasskeyCredential { credential_id, .. } => credential_id,
        other => panic!("expected a credential, got {other:?}"),
    };

    // Approve, but the vault locks while the prompt is up — which is what a
    // blur lock does the moment the user's eyes go back to the browser.
    let mut lock_then_approve = |_: &ConsentContext| {
        state
            .lock()
            .unwrap()
            .vault
            .as_mut()
            .unwrap()
            .lock()
            .unwrap();
        true
    };
    assert!(matches!(
        handle_request(
            Request::PasskeyGet {
                origin: "https://github.com/login".into(),
                rp_id: "github.com".into(),
                client_data_hash: vec![5u8; 32],
                allow_credentials: vec![credential_id],

                picked: false,
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut lock_then_approve,
        ),
        Response::Error { message } if message == "locked"
    ));
}

/// Regression: `host_of` used to end the authority at `/` only, so an `@`
/// anywhere in a query or fragment read as userinfo and everything after it
/// became the host. A stored `https://bank.example#@evil.com` therefore
/// matched `evil.com`, and autofill offered the bank credential there.
///
/// Browser-supplied URLs were never affected (`location.href` always carries
/// the path `/`), but a stored URL need not come from a browser — CSV import
/// is a documented path for a file the user may not control.
///
/// The parsing now lives in `vault-core`; this pins the property that
/// matters here, which is whether the credential is offered at all.
#[test]
fn an_at_sign_after_the_authority_never_moves_the_match() {
    for stored in [
        "https://bank.example#@evil.com",
        "https://bank.example?ref=@evil.com",
        "https://bank.example?email=me@gmail.com",
        r"https://bank.example\@evil.com",
    ] {
        assert!(
            !domain_matches(stored, "https://evil.com/"),
            "{stored} offered the credential on evil.com"
        );
        assert!(
            !domain_matches(stored, "https://gmail.com/"),
            "{stored} offered the credential on gmail.com"
        );
        assert!(
            domain_matches(stored, "https://bank.example/login"),
            "{stored} failed to match its own site"
        );
    }
    // Real userinfo is still userinfo: it sits before the authority ends.
    assert!(domain_matches(
        "https://me@bank.example/login",
        "https://bank.example/"
    ));
}

#[test]
fn host_normalization_and_domain_matching() {
    assert_eq!(host_of("https://www.github.com/login?x=1"), "github.com");
    assert_eq!(
        host_of("http://user@accounts.google.com:443/"),
        "accounts.google.com"
    );
    // Case-insensitive: lowercase happens BEFORE the "www." strip.
    assert_eq!(host_of("https://WWW.GitHub.com/login"), "github.com");
    // IDN hosts need full Unicode lowercasing to compare equal.
    assert_eq!(host_of("https://MÜNCHEN.DE"), "münchen.de");
    // Bracketed IPv6 literals keep their identity (not cut at ':').
    assert_eq!(host_of("https://[fd00::a1]/admin"), "[fd00::a1]");
    assert_eq!(host_of("https://[::1]:8080/x"), "[::1]");
    // ...so two DIFFERENT IPv6 hosts must neither group nor autofill-match.
    assert!(!domain_matches("https://[fd00::a1]", "https://[fd00::b2]"));
    // The same host on a different port is a different origin. This used to
    // match on the host alone, which merged every service behind one
    // address — the NAS on :5000 and :8443, every localhost dev server.
    assert!(!domain_matches(
        "https://[fd00::a1]",
        "https://[fd00::a1]:8443"
    ));
    assert!(domain_matches(
        "https://[fd00::a1]:8443",
        "https://[fd00::a1]:8443"
    ));
    // A credential saved over TLS is never handed to a page served in the
    // clear — the evil-twin Wi-Fi / captive-portal / spoofed-DNS case.
    assert!(!domain_matches(
        "https://bank.example",
        "http://bank.example"
    ));
    // Upgrading is safe, and a hand-typed bare hostname still matches.
    assert!(domain_matches(
        "http://forum.example",
        "https://forum.example"
    ));
    assert!(domain_matches("bank.example", "https://bank.example"));
    assert!(domain_matches(
        "https://github.com",
        "https://www.github.com/login"
    ));
    assert!(!domain_matches(
        "https://github.com",
        "https://gist.github.com"
    ));
    assert!(!domain_matches(
        "https://accounts.google.com",
        "https://google.com"
    ));
    // A public-suffix tenant must never inherit another tenant's login.
    assert!(!domain_matches(
        "https://github.io",
        "https://evil.github.io"
    ));
    // Look-alike must NOT match.
    assert!(!domain_matches(
        "https://evil-github.com",
        "https://github.com"
    ));
    assert!(!domain_matches("https://github.com", "https://github.org"));
}

/// Filling from the browser has to count as using Arca — and the automatic
/// chatter must not.
///
/// Both halves fail silently. Miss the first and the vault locks while you
/// work, which is the complaint this came from. Miss the second and one open
/// tab keeps it unlocked for ever, which looks like a generous timeout and
/// is the absence of one.
#[test]
fn browser_use_resets_the_idle_timer_but_polling_does_not() {
    let deliberate = [
        Request::Fill {
            id: "x".into(),
            url: "https://github.com".into(),
            picked: false,
        },
        Request::SaveLogin {
            url: "https://github.com".into(),
            username: "u".into(),
            password: "p".into(),
        },
        Request::GeneratePassword {
            length: None,
            symbols: None,
        },
    ];
    for req in deliberate {
        assert!(req.is_deliberate_use(), "{req:?} is the user acting");
    }

    let automatic = [
        Request::Hello {
            token: Some("t".into()),
            protocol: None,
            nonce: None,
        },
        Request::Auth { proof: "p".into() },
        Request::Match {
            url: "https://github.com".into(),
        },
        // Sent on EVERY submitted form, including ones with nothing to do
        // with Arca. The clearest case for not counting it.
        Request::SaveProbe {
            url: "https://github.com".into(),
            username: "u".into(),
            password: "p".into(),
        },
    ];
    for req in automatic {
        assert!(!req.is_deliberate_use(), "{req:?} is the extension talking");
    }
}

/// Checking whether the app is up must not be what opens the vault: with a
/// USB key inserted, `arca status` used to report "unlocked" because asking
/// had unlocked it.
#[test]
fn only_a_match_for_a_site_may_open_the_vault() {
    let status = Request::Match { url: String::new() };
    assert!(!status.wants_vault_open());
    let focus = Request::Match {
        url: "https://github.com/login".into(),
    };
    assert!(focus.wants_vault_open());
}

/// Generation must work with the vault LOCKED.
///
/// Every other bridge request reads or writes the vault and is right to
/// refuse while locked, so "check unlocked first" is the reflex here — and
/// applying it to this one would put a master password between the user and
/// the exact moment they are deciding whether to invent a password instead.
/// Nothing secret is read: the answer is bytes from the CSPRNG.
#[test]
fn generating_a_password_does_not_need_an_unlocked_vault() {
    let dir = TempDir::new().unwrap();
    let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    let (clip, _) = ClipboardManager::memory();
    // No vault at all: stricter than locked, and it still has to answer.
    let state = Mutex::new(AppState::new(store, None, clip));
    let mut authed = Session::Authed;

    let mut generate = |length: Option<usize>| {
        handle_request(
            Request::GeneratePassword {
                length,
                symbols: Some(true),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        )
    };

    let Response::GeneratedPassword { password } = generate(Some(24)) else {
        panic!("a locked vault must still generate");
    };
    assert_eq!(password.chars().count(), 24);

    // Clamped, not refused: a site that caps at 6 characters is a real
    // thing, and erroring would send the user off to type one by hand.
    let Response::GeneratedPassword { password } = generate(Some(1)) else {
        panic!("an absurd length must be clamped, not refused");
    };
    assert_eq!(password.chars().count(), 8);
    let Response::GeneratedPassword { password } = generate(Some(9999)) else {
        panic!("an absurd length must be clamped, not refused");
    };
    assert_eq!(password.chars().count(), 64);

    // Default when the caller says nothing.
    let Response::GeneratedPassword { password } = generate(None) else {
        panic!("a missing length must fall back to the default");
    };
    assert_eq!(password.chars().count(), 20);
}

#[test]
fn requires_token_before_serving() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::New;
    // Match without hello -> unauthorized.
    let r = handle_request(
        Request::Match {
            url: "https://x.com".into(),
        },
        &state,
        "secret",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(matches!(r, Response::Error { message } if message == "unauthorized"));
    // Wrong token -> unauthorized, stays unauthed.
    let r = handle_request(
        Request::Hello {
            token: Some("nope".into()),
            protocol: None,
            nonce: None,
        },
        &state,
        "secret",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(matches!(r, Response::Error { .. }));
    assert!(!authed.is_authed());
    // Correct token -> ok.
    let r = handle_request(
        Request::Hello {
            token: Some("secret".into()),
            protocol: None,
            nonce: None,
        },
        &state,
        "secret",
        &mut authed,
        None,
        &mut allow(),
    );
    assert_eq!(
        r,
        Response::Ok {
            protocol: PROTOCOL_VERSION,
            version: APP_VERSION.into(),
            build: env!("ARCA_BUILD").into(),
            commit: env!("ARCA_COMMIT").into(),
            pid: std::process::id(),
            proof: None,
        }
    );
    assert!(authed.is_authed());
}

/// A second consumer now opens this socket directly (a passkey client
/// inside an Electron app, which cannot use native messaging), so the
/// handshake has to say what it speaks and refuse what it cannot.
#[test]
fn the_handshake_negotiates_a_protocol_version() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);

    let hello = |protocol, token: &str, authed: &mut Session| {
        handle_request(
            Request::Hello {
                token: Some(token.into()),
                protocol,
                nonce: None,
            },
            &state,
            "secret",
            authed,
            None,
            &mut allow(),
        )
    };

    // Absent: the native host as it was written before versioning existed.
    let mut authed = Session::New;
    assert_eq!(
        hello(None, "secret", &mut authed),
        Response::Ok {
            protocol: PROTOCOL_VERSION,
            version: APP_VERSION.into(),
            build: env!("ARCA_BUILD").into(),
            commit: env!("ARCA_COMMIT").into(),
            pid: std::process::id(),
            proof: None,
        }
    );
    assert!(authed.is_authed());

    // Our own version, stated explicitly.
    let mut authed = Session::New;
    assert_eq!(
        hello(Some(PROTOCOL_VERSION), "secret", &mut authed),
        Response::Ok {
            protocol: PROTOCOL_VERSION,
            version: APP_VERSION.into(),
            build: env!("ARCA_BUILD").into(),
            commit: env!("ARCA_COMMIT").into(),
            pid: std::process::id(),
            proof: None,
        }
    );
    assert!(authed.is_authed());

    // A client from the future is refused rather than served responses it
    // would misread, and does not get to send anything afterwards.
    let mut authed = Session::New;
    assert_eq!(
        hello(Some(PROTOCOL_VERSION + 1), "secret", &mut authed),
        Response::Error {
            message: "unsupported_protocol".into()
        }
    );
    assert!(!authed.is_authed());

    // Zero is not a version anyone speaks.
    let mut authed = Session::New;
    assert!(matches!(
        hello(Some(0), "secret", &mut authed),
        Response::Error { .. }
    ));
    assert!(!authed.is_authed());

    // The token is checked first, so a caller that cannot authenticate
    // learns nothing about this build — not even that its version is wrong.
    let mut authed = Session::New;
    assert_eq!(
        hello(Some(PROTOCOL_VERSION + 1), "wrong", &mut authed),
        Response::Error {
            message: "unauthorized".into()
        }
    );
    assert!(!authed.is_authed());
}

#[test]
fn match_and_fill_respect_origin_and_unlock() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let gh = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
    add(&state, "Google", "frank@g", "g-pw", "https://google.com");

    let mut authed = Session::Authed;

    // Match returns only the github.com login for a github.com page.
    let r = handle_request(
        Request::Match {
            url: "https://www.github.com/login".into(),
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    match r {
        Response::Logins { items } => {
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].id, gh);
            assert_eq!(items[0].username, "frank");
        }
        other => panic!("expected logins, got {other:?}"),
    }

    // Fill on the matching origin returns the credential.
    let r = handle_request(
        Request::Fill {
            id: gh.clone(),
            url: "https://github.com/login".into(),
            picked: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    assert_eq!(
        r,
        Response::Credentials {
            username: "frank".into(),
            password: "gh-pw".into()
        }
    );

    // Fill for the github id from a DIFFERENT origin is refused.
    let r = handle_request(
        Request::Fill {
            id: gh.clone(),
            url: "https://evil.com".into(),
            picked: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(matches!(r, Response::Error { message } if message == "origin_mismatch"));

    // When locked, nothing is served.
    state
        .lock()
        .unwrap()
        .vault
        .as_mut()
        .unwrap()
        .lock()
        .unwrap();
    let r = handle_request(
        Request::Fill {
            id: gh,
            url: "https://github.com".into(),
            picked: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(matches!(r, Response::Error { message } if message == "locked"));
}

#[test]
fn match_labels_passwords_and_passkeys_by_kind() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    // A password login and a passkey, both for github.com.
    add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
    let mut authed = Session::Authed;
    let r = handle_request(
        Request::PasskeyCreate {
            origin: "https://github.com".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![1, 2, 3],
            exclude_credentials: vec![],
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(matches!(r, Response::PasskeyCredential { .. }));

    // Match on a github.com page returns both, each tagged by kind.
    let r = handle_request(
        Request::Match {
            url: "https://github.com/login".into(),
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    match r {
        Response::Logins { items } => {
            assert_eq!(items.len(), 2);
            assert!(items
                .iter()
                .any(|i| i.kind == "password" && i.username == "frank"));
            assert!(items.iter().any(|i| i.kind == "passkey"));
        }
        other => panic!("expected logins, got {other:?}"),
    }
}

#[test]
fn fill_requires_consent_when_confirm_is_enabled() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let gh = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
    state.lock().unwrap().settings.confirm_autofill = true;
    let mut authed = Session::Authed;

    // Denied consent -> no credential.
    let mut deny = |_: &ConsentContext| false;
    let r = handle_request(
        Request::Fill {
            id: gh.clone(),
            url: "https://github.com".into(),
            picked: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut deny,
    );
    assert!(matches!(r, Response::Error { message } if message == "denied"));

    // The consent prompt must carry the real site + account being approved.
    let mut seen: Option<(String, String)> = None;
    let mut capture = |ctx: &ConsentContext| {
        seen = Some((ctx.site.clone(), ctx.account.clone()));
        true
    };
    let r = handle_request(
        Request::Fill {
            id: gh,
            url: "https://github.com/login".into(),
            picked: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut capture,
    );
    assert_eq!(
        r,
        Response::Credentials {
            username: "frank".into(),
            password: "gh-pw".into()
        }
    );
    assert_eq!(seen, Some(("github.com".into(), "frank".into())));
}

#[test]
fn passkey_create_then_get_binds_to_origin_and_signs() {
    use vault_core::passkey;

    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let mut create = |origin: &str, rp: &str| {
        handle_request(
            Request::PasskeyCreate {
                origin: origin.into(),
                rp_id: rp.into(),
                user_name: "frank".into(),
                user_handle: vec![9, 9, 9],
                exclude_credentials: vec![],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        )
    };

    // A page on evil.com may not create a github.com passkey.
    assert!(matches!(
        create("https://evil.com", "github.com"),
        Response::Error { message } if message == "origin_mismatch"
    ));

    // A page on the RP (incl. a subdomain) can.
    let cred_id = match create("https://sub.github.com/x", "github.com") {
        Response::PasskeyCredential {
            credential_id,
            attestation_object,
        } => {
            assert!(!attestation_object.is_empty());
            credential_id
        }
        other => panic!("expected credential, got {other:?}"),
    };

    // get() from a matching origin returns an assertion that verifies.
    let client_data_hash = vec![3u8; 32];
    let r = handle_request(
        Request::PasskeyGet {
            origin: "https://github.com/login".into(),
            rp_id: "github.com".into(),
            client_data_hash: client_data_hash.clone(),
            allow_credentials: vec![cred_id.clone()],

            picked: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    let (auth_data, sig, ret_cred) = match r {
        Response::PasskeyAssertion {
            credential_id,
            authenticator_data,
            signature,
            user_handle,
        } => {
            assert_eq!(user_handle, vec![9, 9, 9]);
            (authenticator_data, signature, credential_id)
        }
        other => panic!("expected assertion, got {other:?}"),
    };
    assert_eq!(ret_cred, cred_id);

    // Independently verify the signature against a freshly asserted key is
    // not possible (private key is in the vault), but we can confirm the
    // assertion is well-formed: authData is 37 bytes with counter 0.
    assert_eq!(auth_data.len(), 37);
    assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
    assert!(!sig.is_empty());
    // Sanity: the same rp signs verifiably via the core (uses its own key).
    let fresh = passkey::create("github.com", true).unwrap();
    let (fa, fsig) =
        passkey::assert(&fresh.private_key, "github.com", &client_data_hash, true).unwrap();
    assert_eq!(fa.len(), 37);
    assert!(!fsig.is_empty());

    // get() from a non-RP origin is refused.
    assert!(matches!(
        handle_request(
            Request::PasskeyGet {
                origin: "https://evil.com".into(),
                rp_id: "github.com".into(),
                client_data_hash: client_data_hash.clone(),
                allow_credentials: vec![],

                picked: false,
            },
            &state, "t", &mut authed, None, &mut allow(),
        ),
        Response::Error { message } if message == "origin_mismatch"
    ));

    // Unknown credential id -> not_found.
    assert!(matches!(
        handle_request(
            Request::PasskeyGet {
                origin: "https://github.com".into(),
                rp_id: "github.com".into(),
                client_data_hash: client_data_hash.clone(),
                allow_credentials: vec![vec![1, 2, 3, 4]],

                picked: false,
            },
            &state, "t", &mut authed, None, &mut allow(),
        ),
        Response::Error { message } if message == "not_found"
    ));

    // A DENIED approval blocks the assertion (mandatory user approval).
    assert!(matches!(
        handle_request(
            Request::PasskeyGet {
                origin: "https://github.com".into(),
                rp_id: "github.com".into(),
                client_data_hash,
                allow_credentials: vec![cred_id],

                picked: false,
            },
            &state, "t", &mut authed, None, &mut |_: &ConsentContext| false,
        ),
        Response::Error { message } if message == "denied"
    ));
}

#[test]
fn rp_id_rejects_public_suffixes_and_cross_origin() {
    // A page may use its own registrable domain (incl. from a subdomain)...
    assert!(rp_id_matches_origin("github.com", "https://github.com"));
    assert!(rp_id_matches_origin(
        "github.com",
        "https://sub.github.com/x"
    ));
    assert!(rp_id_matches_origin(
        "evil.github.io",
        "https://evil.github.io"
    ));
    // ...but NOT a broader eTLD / public suffix...
    assert!(!rp_id_matches_origin("github.io", "https://evil.github.io"));
    assert!(!rp_id_matches_origin("com", "https://evil.com"));
    assert!(!rp_id_matches_origin("co.uk", "https://foo.co.uk"));
    // ...and never a different registrable domain (phishing).
    assert!(!rp_id_matches_origin("github.com", "https://evil.com"));
    assert!(!rp_id_matches_origin(
        "github.com",
        "https://github.com.evil.com"
    ));
}

#[test]
fn save_probe_and_login_add_update_and_dedupe() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let probe = |url: &str, user: &str, pw: &str, authed: &mut Session| {
        handle_request(
            Request::SaveProbe {
                url: url.into(),
                username: user.into(),
                password: pw.into(),
            },
            &state,
            "t",
            authed,
            None,
            &mut allow(),
        )
    };
    let save = |url: &str, user: &str, pw: &str, authed: &mut Session| {
        handle_request(
            Request::SaveLogin {
                url: url.into(),
                username: user.into(),
                password: pw.into(),
            },
            &state,
            "t",
            authed,
            None,
            &mut allow(),
        )
    };
    let github_count = || {
        let st = state.lock().unwrap();
        st.vault
            .as_ref()
            .unwrap()
            .list_items(false)
            .unwrap()
            .iter()
            .filter(|s| host_of(&s.url) == "github.com")
            .count()
    };

    // Unknown login -> "new"; save it.
    assert!(matches!(
        probe("https://github.com/login", "frank", "pw1", &mut authed),
        Response::SaveDecision { action, .. } if action == "new"
    ));
    assert_eq!(
        save("https://github.com/login", "frank", "pw1", &mut authed),
        Response::Saved
    );
    assert_eq!(github_count(), 1);

    // Same login (messier URL, different username case) + same pw -> "known".
    assert!(matches!(
        probe("https://www.github.com", "Frank", "pw1", &mut authed),
        Response::SaveDecision { action, .. } if action == "known"
    ));
    // Saving a duplicate is a no-op, not a second entry.
    assert_eq!(
        save("https://github.com", "frank", "pw1", &mut authed),
        Response::Saved
    );
    assert_eq!(github_count(), 1);

    // Changed password -> "update"; commit updates in place (still one item).
    assert!(matches!(
        probe("https://github.com", "frank", "pw2", &mut authed),
        Response::SaveDecision { action, .. } if action == "update"
    ));
    assert_eq!(
        save("https://github.com", "frank", "pw2", &mut authed),
        Response::Saved
    );
    assert_eq!(github_count(), 1);
    // Now pw2 is "known", pw1 would be an "update" back.
    assert!(matches!(
        probe("https://github.com", "frank", "pw2", &mut authed),
        Response::SaveDecision { action, .. } if action == "known"
    ));

    // Setting off -> "disabled"; when locked -> "locked".
    state.lock().unwrap().settings.save_prompt = false;
    assert!(matches!(
        probe("https://x.com", "u", "p", &mut authed),
        Response::SaveDecision { action, .. } if action == "disabled"
    ));
    state.lock().unwrap().settings.save_prompt = true;
    state
        .lock()
        .unwrap()
        .vault
        .as_mut()
        .unwrap()
        .lock()
        .unwrap();
    assert!(matches!(
        probe("https://x.com", "u", "p", &mut authed),
        Response::SaveDecision { action, .. } if action == "locked"
    ));
    assert!(matches!(
        save("https://x.com", "u", "p", &mut authed),
        Response::Error { message } if message == "locked"
    ));
}

// A host is not an account boundary when it serves several homelab apps on
// different ports. In particular, password-reset forms often have no
// username field; the old host-only fallback then updated the sole login
// for another port and preserved that old URL, leaving nothing fillable on
// the page whose password had actually changed.
#[test]
fn password_reset_save_never_crosses_an_origin_port() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let request =
        |req, authed: &mut Session| handle_request(req, &state, "t", authed, None, &mut allow());

    assert_eq!(
        request(
            Request::SaveLogin {
                url: "https://nas.local/".into(),
                username: "admin".into(),
                password: "port-443-password".into(),
            },
            &mut authed,
        ),
        Response::Saved,
    );
    assert!(matches!(
        request(
            Request::SaveProbe {
                url: "https://nas.local:9443/account/password".into(),
                username: String::new(),
                password: "port-9443-password".into(),
            },
            &mut authed,
        ),
        Response::SaveDecision { action, .. } if action == "new"
    ));
    assert_eq!(
        request(
            Request::SaveLogin {
                url: "https://nas.local:9443/account/password".into(),
                username: String::new(),
                password: "port-9443-password".into(),
            },
            &mut authed,
        ),
        Response::Saved,
    );

    let st = state.lock().unwrap();
    let vault = st.vault.as_ref().unwrap();
    let mut saved = vault
        .list_items(false)
        .unwrap()
        .into_iter()
        .filter_map(|summary| {
            let item = vault.get_item(summary.id).ok()?;
            match &item.data {
                VaultItem::Login { url, password, .. } if host_of(url) == "nas.local" => {
                    Some((url.clone(), password.clone()))
                }
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    saved.sort();
    assert_eq!(saved.len(), 2);
    assert!(saved.contains(&(
        "https://nas.local/".to_string(),
        "port-443-password".to_string(),
    )));
    assert!(saved.contains(&(
        "https://nas.local:9443/account/password".to_string(),
        "port-9443-password".to_string(),
    )));
}

// A token-based password reset (connect.visma.com/emailtokenverify) has no
// username field, so the browser submits an empty username. The new password
// must still land on the account being reset, not vanish or spawn a blank
// duplicate — the bug that made Arca's own generator look useless.
#[test]
fn save_with_no_username_updates_the_only_host_login() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let probe = |user: &str, pw: &str, authed: &mut Session| {
        handle_request(
            Request::SaveProbe {
                url: "https://connect.visma.com/emailtokenverify".into(),
                username: user.into(),
                password: pw.into(),
            },
            &state,
            "t",
            authed,
            None,
            &mut allow(),
        )
    };
    let save = |user: &str, pw: &str, authed: &mut Session| {
        handle_request(
            Request::SaveLogin {
                url: "https://connect.visma.com/emailtokenverify".into(),
                username: user.into(),
                password: pw.into(),
            },
            &state,
            "t",
            authed,
            None,
            &mut allow(),
        )
    };
    let host_count = || {
        let st = state.lock().unwrap();
        st.vault
            .as_ref()
            .unwrap()
            .list_items(false)
            .unwrap()
            .iter()
            .filter(|s| host_of(&s.url) == "connect.visma.com")
            .count()
    };

    // Seed the existing account with a real username (as a normal sign-in
    // would have captured it).
    assert_eq!(
        save("alice@example.test", "old-pw", &mut authed),
        Response::Saved
    );
    assert_eq!(host_count(), 1);

    // Reset flow: no username, brand-new generated password. This is the one
    // account for the host, so it is an in-place UPDATE, not a new entry.
    assert!(matches!(
        probe("", "generated-strong", &mut authed),
        Response::SaveDecision { action, .. } if action == "update"
    ));
    assert_eq!(save("", "generated-strong", &mut authed), Response::Saved);
    assert_eq!(host_count(), 1);

    // The stored username is preserved; only the password changed. Proven by
    // the exact-username lookup now returning the generated password.
    {
        let st = state.lock().unwrap();
        let vault = st.vault.as_ref().unwrap();
        assert_eq!(
            find_login(vault, "connect.visma.com", "alice@example.test").map(|(_, pw)| pw),
            Some("generated-strong".to_string()),
        );
    }

    // Two accounts for the host is ambiguous without a username: refuse to
    // guess which to overwrite, and file a new entry instead.
    assert_eq!(
        save("bob@example.test", "second-pw", &mut authed),
        Response::Saved
    );
    assert_eq!(host_count(), 2);
    assert!(matches!(
        probe("", "another-generated", &mut authed),
        Response::SaveDecision { action, .. } if action == "new"
    ));
    assert_eq!(save("", "another-generated", &mut authed), Response::Saved);
    assert_eq!(host_count(), 3);
}

// A save that overwrites an existing login must say WHICH account. With no
// username on the page (a token reset) the app picks the target itself, so
// the browser can only show it if the probe reports it back.
#[test]
fn save_probe_names_the_login_an_update_would_overwrite() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let probe = |user: &str, pw: &str, authed: &mut Session| {
        handle_request(
            Request::SaveProbe {
                url: "https://connect.visma.com/emailtokenverify".into(),
                username: user.into(),
                password: pw.into(),
            },
            &state,
            "t",
            authed,
            None,
            &mut allow(),
        )
    };
    assert_eq!(
        handle_request(
            Request::SaveLogin {
                url: "https://connect.visma.com/".into(),
                username: "alice@example.test".into(),
                password: "old-pw".into(),
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        ),
        Response::Saved
    );

    // No username on the page: the decision names the stored account.
    match probe("", "generated-strong", &mut authed) {
        Response::SaveDecision { action, username } => {
            assert_eq!(action, "update");
            assert_eq!(username.as_deref(), Some("alice@example.test"));
        }
        other => panic!("expected a save decision, got {other:?}"),
    }
    // "new" has no account to name yet.
    match probe("other@example.test", "another", &mut authed) {
        Response::SaveDecision { action, username } => {
            assert_eq!(action, "new");
            assert_eq!(username, None);
        }
        other => panic!("expected a save decision, got {other:?}"),
    }
}

// The idle timer used to be reset before the request was even validated, so
// a site retrying passkeys against an origin the user had silenced kept the
// vault open with nobody at the desk.
#[test]
fn a_refused_request_does_not_reset_the_idle_timer() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;

    // Age the vault's last-use marker, then make a request that fails.
    let before = {
        let mut st = state.lock().unwrap();
        st.last_activity = Instant::now() - Duration::from_secs(120);
        st.last_activity
    };
    let refused = handle_request(
        Request::Fill {
            id: Uuid::new_v4().to_string(),
            url: "https://example.com".into(),
            picked: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(matches!(refused, Response::Error { .. }));
    assert_eq!(
        state.lock().unwrap().last_activity,
        before,
        "a refused fill must not count as the user being present"
    );

    // A request that succeeds still does.
    let ok = handle_request(
        Request::GeneratePassword {
            length: Some(20),
            symbols: Some(true),
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(matches!(ok, Response::GeneratedPassword { .. }));
    assert!(
        state.lock().unwrap().last_activity > before,
        "a successful deliberate use must reset the idle timer"
    );
}

/// Protocol 3, the way the native host and the CLI now speak it: the app
/// proves itself over the client's nonce before the client says anything that
/// matters, and the token itself never crosses the socket in either direction.
#[test]
fn protocol_3_authenticates_both_sides_without_sending_the_token() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let token = "the-real-token";
    let mut session = Session::New;
    let send = |req: Request, session: &mut Session| {
        handle_request(req, &state, token, session, None, &mut allow())
    };

    let client_nonce = vault_bridge::auth::nonce().unwrap();
    let Response::Challenge { nonce, proof } = send(
        Request::Hello {
            token: None,
            protocol: Some(PROTOCOL_VERSION),
            nonce: Some(client_nonce.clone()),
        },
        &mut session,
    ) else {
        panic!("a tokenless hello must be answered with a challenge");
    };
    assert!(vault_bridge::auth::same(
        &proof,
        &vault_bridge::auth::app_proof(token, &client_nonce, &nonce)
    ));
    assert!(!session.is_authed());

    // Nothing is served between the challenge and the client's proof.
    let early = send(Request::ListBookmarks, &mut session);
    assert_eq!(early, unauthorized());

    let mut session = Session::Challenged {
        client_nonce: client_nonce.clone(),
        app_nonce: nonce.clone(),
    };
    let ok = send(
        Request::Auth {
            proof: vault_bridge::auth::client_proof(token, &client_nonce, &nonce),
        },
        &mut session,
    );
    assert_eq!(ok, welcome(None));
    assert!(session.is_authed());
}

#[test]
fn protocol_3_refuses_a_client_that_cannot_prove_itself() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let token = "the-real-token";
    let mut send = |req: Request, session: &mut Session| {
        handle_request(req, &state, token, session, None, &mut allow())
    };
    let challenge = |send: &mut dyn FnMut(Request, &mut Session) -> Response,
                     session: &mut Session| {
        let client_nonce = vault_bridge::auth::nonce().unwrap();
        let Response::Challenge { nonce, .. } = send(
            Request::Hello {
                token: None,
                protocol: Some(PROTOCOL_VERSION),
                nonce: Some(client_nonce.clone()),
            },
            session,
        ) else {
            panic!("expected a challenge");
        };
        (client_nonce, nonce)
    };

    // A proof made without the token.
    let mut session = Session::New;
    let (c, a) = challenge(&mut send, &mut session);
    let forged = vault_bridge::auth::client_proof("a-guessed-token", &c, &a);
    assert_eq!(
        send(Request::Auth { proof: forged }, &mut session),
        unauthorized()
    );
    assert!(!session.is_authed());

    // The app's own proof, echoed back: different label, so it never works.
    let mut session = Session::New;
    let (c, a) = challenge(&mut send, &mut session);
    let echoed = vault_bridge::auth::app_proof(token, &c, &a);
    assert_eq!(
        send(Request::Auth { proof: echoed }, &mut session),
        unauthorized()
    );

    // A proof from an earlier connection: the app's nonce is fresh each time.
    let mut session = Session::New;
    let (c, a) = challenge(&mut send, &mut session);
    let replay = vault_bridge::auth::client_proof(token, &c, &a);
    let mut session = Session::New;
    challenge(&mut send, &mut session);
    assert_eq!(
        send(Request::Auth { proof: replay }, &mut session),
        unauthorized()
    );

    // No challenge outstanding.
    let mut session = Session::New;
    let proof = vault_bridge::auth::client_proof(token, &c, &a);
    assert_eq!(send(Request::Auth { proof }, &mut session), unauthorized());

    // Without a well-formed nonce, or claiming a protocol that sent the token.
    for (protocol, nonce) in [
        (Some(PROTOCOL_VERSION), None),
        (Some(PROTOCOL_VERSION), Some("cafebabe".to_string())),
        (Some(2), vault_bridge::auth::nonce()),
        (None, vault_bridge::auth::nonce()),
    ] {
        let mut session = Session::New;
        let hello = Request::Hello {
            token: None,
            protocol,
            nonce,
        };
        assert_eq!(send(hello, &mut session), unauthorized());
        assert_eq!(session, Session::New);
    }
}

/// Clients built before protocol 3 still send the token in their hello and
/// check protocol 2's proof. Serving them adds nothing an attacker can use:
/// it takes the token to get in either way.
#[test]
fn a_protocol_2_client_is_still_served() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let hello = |token: &str, session: &mut Session| {
        handle_request(
            Request::Hello {
                token: Some(token.into()),
                protocol: Some(2),
                nonce: Some("cafebabe".into()),
            },
            &state,
            "the-real-token",
            session,
            None,
            &mut allow(),
        )
    };

    let mut session = Session::New;
    assert_eq!(
        hello("the-real-token", &mut session),
        welcome(Some(vault_bridge::auth::v2_proof(
            "the-real-token",
            "cafebabe"
        )))
    );
    assert!(session.is_authed());

    let mut session = Session::New;
    assert_eq!(hello("wrong-token", &mut session), unauthorized());
    assert!(!session.is_authed());
}

#[test]
fn bridge_created_items_receive_real_timestamps() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;

    let created = handle_request(
        Request::CreateLogin {
            title: "Generated".into(),
            username: "frank".into(),
            url: "https://example.com".into(),
            notes: String::new(),
            length: Some(16),
            symbols: Some(false),
            reveal: false,
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    let Response::CreatedLogin { id, .. } = created else {
        panic!("expected a created login, got {created:?}");
    };

    assert_eq!(
        handle_request(
            Request::ImportBookmarks {
                items: vec![BookmarkWire {
                    title: "Example".into(),
                    url: "https://example.com/docs".into(),
                    folder: "Docs".into(),
                }],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        ),
        Response::ImportedBookmarks { added: 1 }
    );

    let st = state.lock().unwrap();
    let vault = st.vault.as_ref().unwrap();
    assert!(vault.get_item(id.parse().unwrap()).unwrap().created_at > 0);
    let bookmark = vault
        .list_items(false)
        .unwrap()
        .into_iter()
        .find_map(|summary| {
            let item = vault.get_item(summary.id).ok()?;
            matches!(item.data, VaultItem::Bookmark { .. }).then_some(item.created_at)
        })
        .expect("bookmark was imported");
    assert!(bookmark > 0);
}

#[test]
fn multiple_passkey_accounts_require_choice_and_respect_allow_credentials() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let mut ids = Vec::new();
    for (name, handle) in [("first@example.test", 1), ("wanted@example.test", 2)] {
        let response = handle_request(
            Request::PasskeyCreate {
                origin: "https://accounts.example.test".into(),
                rp_id: "example.test".into(),
                user_name: name.into(),
                user_handle: vec![handle],
                exclude_credentials: vec![],
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        let Response::PasskeyCredential { credential_id, .. } = response else {
            panic!("{response:?}")
        };
        ids.push(credential_id);
    }
    let request = |allowed| Request::PasskeyGet {
        origin: "https://accounts.example.test".into(),
        rp_id: "example.test".into(),
        client_data_hash: vec![0; 32],
        allow_credentials: allowed,

        picked: false,
    };
    let mut no_prompt =
        |_: &ConsentContext| -> bool { panic!("must not sign an ambiguous account") };
    for allowed in [vec![], ids.clone()] {
        assert_eq!(
            handle_request(
                request(allowed),
                &state,
                "t",
                &mut authed,
                None,
                &mut no_prompt
            ),
            Response::Error {
                message: "account_selection_required".into()
            }
        );
    }
    for (index, id) in ids.iter().enumerate() {
        let response = handle_request(
            request(vec![id.clone()]),
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
        );
        let Response::PasskeyAssertion {
            credential_id,
            user_handle,
            ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert_eq!(&credential_id, id);
        assert_eq!(user_handle, vec![index as u8 + 1]);
    }
    assert_eq!(
        handle_request(
            request(vec![vec![99]]),
            &state,
            "t",
            &mut authed,
            None,
            &mut no_prompt
        ),
        Response::Error {
            message: "not_found".into()
        }
    );
}

/// excludeCredentials: a create listing a credential we already hold must
/// be refused with "excluded" WITHOUT consulting the user at all — that
/// answer becomes InvalidStateError in the page and stops re-registration
/// loops (the endless-Touch-ID bug).
#[test]
fn passkey_create_with_excluded_credential_is_refused_without_prompt() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;

    // Register one passkey normally.
    let resp = handle_request(
        Request::PasskeyCreate {
            origin: "https://github.com".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![1, 2, 3],
            exclude_credentials: vec![],
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    let Response::PasskeyCredential { credential_id, .. } = resp else {
        panic!("expected a credential, got {resp:?}");
    };

    // Re-register with that credential excluded: refused, and the consent
    // closure must never run (no prompt).
    let mut never = |_: &ConsentContext| -> bool {
        panic!("consent must not be requested for an excluded create")
    };
    let resp = handle_request(
        Request::PasskeyCreate {
            origin: "https://github.com".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![1, 2, 3],
            exclude_credentials: vec![credential_id],
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut never,
    );
    assert_eq!(
        resp,
        Response::Error {
            message: "excluded".into()
        }
    );
}

/// The other refusal branch: the site sent NO exclude list, but we already
/// hold a passkey for this rp_id and account. Same answer, same silence
/// towards the page — but this is the one the user gets told about, because
/// re-registering is the only way back when the RP lost its copy.
#[test]
fn passkey_create_for_a_known_account_is_refused_without_an_exclude_list() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;

    let create = |exclude: Vec<Vec<u8>>| Request::PasskeyCreate {
        origin: "https://login.microsoft.com".into(),
        rp_id: "login.microsoft.com".into(),
        user_name: "alice@example.test".into(),
        user_handle: vec![9, 8, 7],
        exclude_credentials: exclude,
    };

    let resp = handle_request(create(vec![]), &state, "t", &mut authed, None, &mut allow());
    assert!(
        matches!(resp, Response::PasskeyCredential { .. }),
        "first registration should succeed, got {resp:?}"
    );

    // Same account, empty exclude list: refused, and without a prompt.
    let mut never = |_: &ConsentContext| -> bool {
        panic!("consent must not be requested for a known-account create")
    };
    let resp = handle_request(create(vec![]), &state, "t", &mut authed, None, &mut never);
    assert_eq!(
        resp,
        Response::Error {
            message: "excluded".into()
        }
    );

    // A different account on the same site still gets to register once.
    let resp = handle_request(
        Request::PasskeyCreate {
            origin: "https://login.microsoft.com".into(),
            rp_id: "login.microsoft.com".into(),
            user_name: "other@example.test".into(),
            user_handle: vec![4, 5, 6],
            exclude_credentials: vec![],
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    );
    assert!(
        matches!(resp, Response::PasskeyCredential { .. }),
        "a distinct user handle must not be blocked, got {resp:?}"
    );
}

// ---- one prompt for a pick made while locked --------------------------------

fn lock_vault(state: &Mutex<AppState>) {
    state
        .lock()
        .unwrap()
        .vault
        .as_mut()
        .unwrap()
        .lock()
        .unwrap();
}

/// Answers a request's unlock prompt as the person at the Mac does with Touch
/// ID: an open vault asks nothing; a locked one is opened and the user is
/// verified. Records what each prompt said.
fn fingerprint<'a>(
    state: &'a Mutex<AppState>,
    prompts: &'a mut Vec<String>,
) -> impl FnMut(&str) -> RequestUnlock + 'a {
    move |reason| {
        let mut st = state.lock().unwrap();
        let vault = st.vault.as_mut().unwrap();
        if vault.is_unlocked() {
            return RequestUnlock::AlreadyOpen;
        }
        prompts.push(reason.to_string());
        vault.unlock("pw").unwrap();
        RequestUnlock::Verified
    }
}

fn is_error(r: &Response, expected: &str) -> bool {
    matches!(r, Response::Error { message } if message == expected)
}

/// The Apple Passwords shape: choose the account, one fingerprint that says
/// what for, done. It used to be: choose, "locked", unlock, choose again, and
/// with confirmation on, approve again.
#[test]
fn a_login_picked_while_locked_fills_after_one_prompt_that_names_the_site() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let gh = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
    state.lock().unwrap().settings.confirm_autofill = true;
    lock_vault(&state);
    let mut authed = Session::Authed;
    let fill = |picked| Request::Fill {
        id: gh.clone(),
        url: "https://github.com/login".into(),
        picked,
    };

    let mut prompts = Vec::new();
    let r = dispatch_with(
        fill(true),
        &state,
        "t",
        &mut authed,
        None,
        &mut |_: &ConsentContext| panic!("the fingerprint already approved this fill"),
        &mut fingerprint(&state, &mut prompts),
    );
    assert_eq!(
        r,
        Response::Credentials {
            username: "frank".into(),
            password: "gh-pw".into()
        }
    );
    assert_eq!(prompts, ["fill your password on github.com"]);

    // Open already: no prompt, and the confirmation the user turned on is
    // asked as before, since nothing else approved this fill.
    let mut asked = 0;
    let r = dispatch_with(
        fill(true),
        &state,
        "t",
        &mut authed,
        None,
        &mut |_: &ConsentContext| {
            asked += 1;
            true
        },
        &mut fingerprint(&state, &mut prompts),
    );
    assert!(matches!(r, Response::Credentials { .. }));
    assert_eq!((asked, prompts.len()), (1, 1));

    // A fill nobody picked in Arca's list never prompts: locked is locked.
    lock_vault(&state);
    let r = dispatch_with(
        fill(false),
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
        &mut |_: &str| -> RequestUnlock { panic!("an unpicked fill must not prompt") },
    );
    assert!(is_error(&r, "locked"));
}

#[test]
fn a_declined_prompt_or_the_window_leaves_the_vault_locked_and_says_which() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let gh = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
    lock_vault(&state);
    let mut authed = Session::Authed;
    for (answer, expected) in [
        (RequestUnlock::Declined, "unlock_cancelled"),
        // No Touch ID here: the window asks for the master password, and the
        // extension sends this same fill again once it is open.
        (RequestUnlock::Window, "unlocking"),
    ] {
        let r = dispatch_with(
            Request::Fill {
                id: gh.clone(),
                url: "https://github.com/login".into(),
                picked: true,
            },
            &state,
            "t",
            &mut authed,
            None,
            &mut allow(),
            &mut |_: &str| answer,
        );
        assert!(is_error(&r, expected), "{answer:?} gave {r:?}");
        assert!(!state.lock().unwrap().vault.as_ref().unwrap().is_unlocked());
    }
}

/// A sign-in with the vault locked: the one fingerprint that opens it is the
/// user verification, so the assertion carries UV without a second prompt.
/// With "ask for the master password for passkeys" on, it does not count.
#[test]
fn a_passkey_sign_in_while_locked_asks_once_unless_the_password_is_required() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = Session::Authed;
    let cred_id = match handle_request(
        Request::PasskeyCreate {
            origin: "https://github.com".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![9, 9, 9],
            exclude_credentials: vec![],
        },
        &state,
        "t",
        &mut authed,
        None,
        &mut allow(),
    ) {
        Response::PasskeyCredential { credential_id, .. } => credential_id,
        other => panic!("expected a credential, got {other:?}"),
    };
    let get = |picked| Request::PasskeyGet {
        origin: "https://github.com/login".into(),
        rp_id: "github.com".into(),
        client_data_hash: vec![3u8; 32],
        allow_credentials: vec![cred_id.clone()],
        picked,
    };

    for picked in [true, false] {
        lock_vault(&state);
        let mut prompts = Vec::new();
        let r = dispatch_with(
            get(picked),
            &state,
            "t",
            &mut authed,
            None,
            &mut |_: &ConsentContext| panic!("the fingerprint already verified this sign-in"),
            &mut fingerprint(&state, &mut prompts),
        );
        let Response::PasskeyAssertion {
            authenticator_data, ..
        } = r
        else {
            panic!("expected an assertion, got {r:?}");
        };
        // Flags byte after the 32-byte rpIdHash: user present and verified.
        assert_eq!(authenticator_data[32] & 0x05, 0x05);
        assert_eq!(prompts, ["sign in to github.com"]);
    }

    state.lock().unwrap().settings.passkey_reprompt = true;
    lock_vault(&state);
    let mut asked = 0;
    let mut prompts = Vec::new();
    let r = dispatch_with(
        get(true),
        &state,
        "t",
        &mut authed,
        None,
        &mut |_: &ConsentContext| {
            asked += 1;
            true
        },
        &mut fingerprint(&state, &mut prompts),
    );
    assert!(matches!(r, Response::PasskeyAssertion { .. }), "{r:?}");
    assert_eq!(asked, 1, "the master password is still asked for");
}
