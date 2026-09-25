use super::*;
use crate::clipboard::ClipboardManager;
use crate::commands::{do_upsert_item, LoginInput};
use tempfile::TempDir;
use vault_core::{KdfAlgorithm, KdfParams, Vault};
use vault_store::VaultStore;

// Decode actual desktop output with the native host's production schema.
// Maintaining two independent JSON fixtures missed real protocol drift.
#[allow(dead_code)]
#[path = "../../../../../extension/native-host/src/bridge_schema.rs"]
mod native_host_schema;

#[test]
fn every_desktop_response_is_accepted_by_the_native_host() {
    let responses = [
        Response::Ok {
            protocol: PROTOCOL_VERSION,
            version: "test",
            build: "test",
            commit: "test",
            pid: 1,
            proof: Some("proof".into()),
        },
        Response::Logins {
            items: vec![
                LoginMatch {
                    id: "login".into(),
                    credential_id: vec![],
                    title: "Example".into(),
                    username: "alice".into(),
                    kind: "password".into(),
                },
                LoginMatch {
                    id: "passkey".into(),
                    credential_id: vec![1, 2, 255],
                    title: "Example".into(),
                    username: "bob".into(),
                    kind: "passkey".into(),
                },
            ],
        },
        Response::Credentials {
            username: "alice".into(),
            password: "synthetic".into(),
        },
        Response::PasskeyCredential {
            credential_id: vec![1],
            attestation_object: vec![2],
        },
        Response::PasskeyAssertion {
            credential_id: vec![1],
            authenticator_data: vec![2],
            signature: vec![3],
            user_handle: vec![4],
        },
        Response::SaveDecision {
            action: "new".into(),
            username: None,
        },
        Response::Saved,
        Response::GeneratedPassword {
            password: "synthetic".into(),
        },
        Response::CreatedLogin {
            id: "login".into(),
            title: "Example".into(),
            password: None,
        },
        Response::Password {
            password: "synthetic".into(),
        },
        Response::Deleted {
            id: "login".into(),
            title: "Example".into(),
        },
        Response::DeletedBookmarks { removed: 2 },
        Response::ImportedBookmarks { added: 3 },
        Response::Bookmarks {
            items: vec![BookmarkWire {
                title: "Example".into(),
                url: "https://example.test".into(),
                folder: "test".into(),
            }],
        },
        Response::UnlockRequested,
        Response::Error {
            message: "locked".into(),
        },
    ];
    for response in responses {
        let wire = serde_json::to_value(response).unwrap();
        let decoded: native_host_schema::BridgeResponse = serde_json::from_value(wire.clone())
            .unwrap_or_else(|error| panic!("{}: {error}", wire["type"]));
        assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
    }
}

/// A consent closure that always approves (autofill confirmation off is the
/// default, so this is only exercised when a test flips the setting on).
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
    let mut authed = true;
    let request =
        |req, authed: &mut bool| handle_request(req, &state, "t", authed, None, &mut allow());
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

/// The same trade for every other bridge write: a create that failed must
/// leave nothing behind, and a delete that failed must not hide an item the
/// disk still has. A vault that disagrees with its file always resolves the
/// wrong way — at the next unlock the file wins, and whatever the user saw
/// in between was a lie.
#[test]
fn a_failed_persist_leaves_creates_deletes_and_imports_undone() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = true;
    let request =
        |req, authed: &mut bool| handle_request(req, &state, "t", authed, None, &mut allow());
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
    let mut authed = true;
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
    let mut authed = true;
    let request =
        |req, authed: &mut bool| handle_request(req, &state, "t", authed, None, &mut allow());
    let id = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");

    // While it is active, both work — the refusal below has to come from
    // the deletion and nothing else.
    assert_eq!(
        request(
            Request::Fill {
                id: id.clone(),
                url: "https://github.com/login".into(),
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
    let mut authed = true;

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
            token: "t".into(),
            protocol: None,
            nonce: None,
        },
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
    let mut authed = true;

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
    let mut authed = false;
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
            token: "nope".into(),
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
    assert!(!authed);
    // Correct token -> ok.
    let r = handle_request(
        Request::Hello {
            token: "secret".into(),
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
            version: APP_VERSION,
            build: env!("ARCA_BUILD"),
            commit: env!("ARCA_COMMIT"),
            pid: std::process::id(),
            proof: None,
        }
    );
    assert!(authed);
}

/// A second consumer now opens this socket directly (a passkey client
/// inside an Electron app, which cannot use native messaging), so the
/// handshake has to say what it speaks and refuse what it cannot.
#[test]
fn the_handshake_negotiates_a_protocol_version() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);

    let hello = |protocol, token: &str, authed: &mut bool| {
        handle_request(
            Request::Hello {
                token: token.into(),
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
    let mut authed = false;
    assert_eq!(
        hello(None, "secret", &mut authed),
        Response::Ok {
            protocol: PROTOCOL_VERSION,
            version: APP_VERSION,
            build: env!("ARCA_BUILD"),
            commit: env!("ARCA_COMMIT"),
            pid: std::process::id(),
            proof: None,
        }
    );
    assert!(authed);

    // Our own version, stated explicitly.
    let mut authed = false;
    assert_eq!(
        hello(Some(PROTOCOL_VERSION), "secret", &mut authed),
        Response::Ok {
            protocol: PROTOCOL_VERSION,
            version: APP_VERSION,
            build: env!("ARCA_BUILD"),
            commit: env!("ARCA_COMMIT"),
            pid: std::process::id(),
            proof: None,
        }
    );
    assert!(authed);

    // A client from the future is refused rather than served responses it
    // would misread, and does not get to send anything afterwards.
    let mut authed = false;
    assert_eq!(
        hello(Some(PROTOCOL_VERSION + 1), "secret", &mut authed),
        Response::Error {
            message: "unsupported_protocol".into()
        }
    );
    assert!(!authed);

    // Zero is not a version anyone speaks.
    let mut authed = false;
    assert!(matches!(
        hello(Some(0), "secret", &mut authed),
        Response::Error { .. }
    ));
    assert!(!authed);

    // The token is checked first, so a caller that cannot authenticate
    // learns nothing about this build — not even that its version is wrong.
    let mut authed = false;
    assert_eq!(
        hello(Some(PROTOCOL_VERSION + 1), "wrong", &mut authed),
        Response::Error {
            message: "unauthorized".into()
        }
    );
    assert!(!authed);
}

#[test]
fn match_and_fill_respect_origin_and_unlock() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let gh = add(&state, "GitHub", "frank", "gh-pw", "https://github.com");
    add(&state, "Google", "frank@g", "g-pw", "https://google.com");

    let mut authed = true;

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
    let mut authed = true;
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
    let mut authed = true;

    // Denied consent -> no credential.
    let mut deny = |_: &ConsentContext| false;
    let r = handle_request(
        Request::Fill {
            id: gh.clone(),
            url: "https://github.com".into(),
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
    let mut authed = true;
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
    let mut authed = true;
    let probe = |url: &str, user: &str, pw: &str, authed: &mut bool| {
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
    let save = |url: &str, user: &str, pw: &str, authed: &mut bool| {
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
    let mut authed = true;
    let request =
        |req, authed: &mut bool| handle_request(req, &state, "t", authed, None, &mut allow());

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
    let mut authed = true;
    let probe = |user: &str, pw: &str, authed: &mut bool| {
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
    let save = |user: &str, pw: &str, authed: &mut bool| {
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
    let mut authed = true;
    let probe = |user: &str, pw: &str, authed: &mut bool| {
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
    let mut authed = true;

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

/// Shared handshake test vector.
///
/// The app, the native host and the CLI each compute this MAC in their own
/// crate, and a silent disagreement would break every bridge connection at
/// once. The same assertion lives in all three, so changing one without the
/// others fails here.
#[test]
fn handshake_proof_matches_the_shared_vector() {
    assert_eq!(
        handshake_proof("arca-test-token", "0123456789abcdef"),
        "e7b61fca20478c27d56236c0e24e1fc97e29d2a3ed757d7a61d0cee09b66c1fc"
    );
}

/// The handshake has to run BOTH ways.
///
/// It used to run one: the client proved it had the token, the app proved
/// nothing, and a client believed anything that answered `{"type":"ok"}`.
/// Arca's port is released the instant it exits and the file naming that
/// port outlived it, so whatever bound the port next was handed the next
/// submitted password.
#[test]
fn the_app_proves_it_holds_the_token_before_a_client_trusts_it() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = false;

    let hello = |nonce: Option<&str>, token: &str, authed: &mut bool| {
        handle_request(
            Request::Hello {
                token: token.into(),
                protocol: Some(PROTOCOL_VERSION),
                nonce: nonce.map(str::to_string),
            },
            &state,
            "the-real-token",
            authed,
            None,
            &mut allow(),
        )
    };

    // A client that challenges gets a MAC it can check against its own.
    match hello(Some("cafebabe"), "the-real-token", &mut authed) {
        Response::Ok { proof, .. } => assert_eq!(
            proof.as_deref(),
            Some(handshake_proof("the-real-token", "cafebabe").as_str()),
            "the proof must be HMAC(token, nonce) so a client can verify it"
        ),
        other => panic!("expected ok, got {other:?}"),
    }

    // The proof is bound to THIS nonce, so a proof captured from an earlier
    // handshake cannot be replayed into a later one.
    assert_ne!(
        handshake_proof("the-real-token", "cafebabe"),
        handshake_proof("the-real-token", "d00dfeed"),
    );
    // ...and to the token, which is the whole point: an impostor that never
    // read the info file cannot produce it.
    assert_ne!(
        handshake_proof("the-real-token", "cafebabe"),
        handshake_proof("a-guessed-token", "cafebabe"),
    );

    // A wrong token is still refused outright, and learns nothing.
    let mut other_authed = false;
    assert!(matches!(
        hello(Some("cafebabe"), "wrong-token", &mut other_authed),
        Response::Error { message } if message == "unauthorized"
    ));
    assert!(!other_authed);
}

#[test]
fn bridge_created_items_receive_real_timestamps() {
    let dir = TempDir::new().unwrap();
    let state = unlocked_state(&dir);
    let mut authed = true;

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
    let mut authed = true;
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
    let mut authed = true;

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
    let mut authed = true;

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
