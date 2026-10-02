//! Passkeys: creating one, signing in with one, and the approvals both need.
//! The relying party must belong to the page's origin, and neither happens
//! without the user.

use std::sync::LazyLock;
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use vault_core::{Item, VaultItem};

use crate::state::AppState;

use super::*;

#[derive(Clone, Serialize)]
pub(super) struct PasskeyChoice {
    pub(super) id: String,
    pub(super) account: String,
    pub(super) title: String,
    #[serde(skip)]
    pub(super) credential_id: Vec<u8>,
}

/// WebAuthn RP-ID validation: `rp_id` must equal the page origin's host or be a
/// *registrable* parent-domain suffix of it. So a page on `sub.github.com` may
/// use rp_id `github.com`, but a page on `evil.com` may NOT — this is the core
/// anti-phishing binding for passkey create/get.
///
/// Crucially, `rp_id` must NOT be a public suffix / eTLD (`com`, `co.uk`,
/// `github.io`): the Public Suffix List guard stops a page scoping a passkey so
/// broadly that mutually-distrusting tenants (e.g. every `*.github.io`) could
/// share it — exactly what a browser's WebAuthn client enforces.
/// `rp_id_matches_origin`, plus the origins the relying party itself published
/// (WebAuthn L3 Related Origin Requests).
///
/// NEVER call this while holding the app-state lock: the first use per rpId
/// makes an HTTPS request. The direct rule is tried first, so the common case
/// costs nothing.
pub(super) fn rp_id_allows_origin(rp_id: &str, origin: &str) -> bool {
    if rp_id_matches_origin(rp_id, origin) {
        return true;
    }
    // The RP publishes full origins (`https://www.example.com` is not
    // `https://example.com` in that file either), so the page's host must reach
    // the comparison with its `www.` intact.
    let host = vault_core::webauthn_host_of(origin);
    if host.is_empty() {
        return false;
    }
    crate::related_origins::is_related(rp_id, &host)
}

pub(super) fn rp_id_matches_origin(rp_id: &str, origin: &str) -> bool {
    // NOT `host_of`: that strips `www.` for password matching, and an rpId is a
    // name the page and the relying party agree on exactly. A page on
    // `https://www.example.com` that omits `rp.id` defaults it to the full
    // hostname, so stripping here compared `www.example.com` against
    // `example.com`, called it a mismatch, and refused the ceremony — and any
    // passkey already stored under a `www.` rpId became unusable.
    let host = vault_core::webauthn_host_of(origin);
    let rp = rp_id.trim().to_lowercase();
    if rp.is_empty() || host.is_empty() {
        return false;
    }
    // rp_id must equal or be a parent suffix of the origin host.
    if host != rp && !host.ends_with(&format!(".{rp}")) {
        return false;
    }
    // ...and rp_id and the origin must share the SAME registrable domain, which
    // also rejects rp_id being a bare public suffix (no registrable domain).
    match (psl::domain_str(&rp), psl::domain_str(&host)) {
        (Some(rp_reg), Some(host_reg)) => rp_reg == host_reg,
        _ => false,
    }
}

pub(super) fn passkey_create(
    ctx: &mut Ctx,
    origin: String,
    rp_id: String,
    user_name: String,
    user_handle: Vec<u8>,
    exclude_credentials: Vec<Vec<u8>>,
) -> Response {
    let state = ctx.state;
    let app = ctx.app;
    let consent = &mut *ctx.consent;
    // Kill switch: when passkey handling is off, ignore the ceremony so
    // the browser / platform authenticator takes over (the shim falls
    // back on this error). No prompt, ever.
    if !passkeys_enabled(state) {
        return error("passkeys_disabled");
    }
    // Anti-phishing: the RP id must belong to the page's origin.
    log_passkey_request(state, &origin, &rp_id, true);
    // Related Origin Requests apply to the ceremony too — a passkey
    // registered for login.microsoft.com must be usable on the page
    // Microsoft actually redirects you to. No lock is held here.
    if !rp_id_allows_origin(&rp_id, &origin) {
        return error("origin_mismatch");
    }
    match registered_already(state, &rp_id, &user_handle, &exclude_credentials) {
        Err(response) => return response,
        Ok(Some(Registered::Excluded)) => return error("excluded"),
        Ok(Some(Registered::SameAccount)) => {
            // Emitted outside the state lock: this reaches the webview, and
            // the webview answers by calling commands that take that lock.
            if let Some(app) = app {
                let _ = app.emit("passkey-registration-blocked", rp_id.clone());
            }
            return error("excluded");
        }
        Ok(None) => {}
    }
    // Registration ALWAYS requires an explicit user approval; a silent
    // create must never register a credential. `true` = this is a NEW
    // passkey, so the prompt says "create" (not "sign in").
    let require_password = passkey_reprompt(state);
    let Some(user_verified) = approve_passkey(&rp_id, true, app, consent, false, require_password)
    else {
        return error("denied");
    };
    let Ok(new_pk) = vault_core::passkey::create(&rp_id, user_verified) else {
        return error("internal");
    };
    let credential_id = new_pk.credential_id.clone();
    let attestation_object = new_pk.attestation_object;
    let key = (new_pk.credential_id, new_pk.private_key.to_vec());
    if let Err(response) = store_new_passkey(state, &rp_id, user_name, user_handle, key) {
        return response;
    }
    if let Some(app) = app {
        let _ = app.emit("passkey-created", rp_id);
    }
    Response::PasskeyCredential {
        credential_id,
        attestation_object,
    }
}

/// A passkey this relying party already has, which a registration would
/// duplicate.
pub(super) enum Registered {
    /// The site listed it in `excludeCredentials`.
    Excluded,
    /// Same relying party and user handle, whatever the site listed.
    SameAccount,
}

/// Checked before the user is asked anything, with the vault unlocked.
pub(super) fn registered_already(
    state: &Mutex<AppState>,
    rp_id: &str,
    user_handle: &[u8],
    exclude_credentials: &[Vec<u8>],
) -> Result<Option<Registered>, Response> {
    let st = state.lock().map_err(|_| error("internal"))?;
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
    };
    // Refuse a create WITHOUT prompting when we already hold a
    // passkey for this relying party — this is the loop killer.
    // Sites like GitHub re-fire `create` on nearly every sign-in;
    // if we serviced each one we'd pop a Touch ID prompt and pile up
    // a duplicate credential every single time (exactly the reported
    // bug). Refusing here makes the page see InvalidStateError, the
    // spec's "you already have a credential" signal, so it stops.
    //
    // Two conditions trigger the refusal, both BEFORE any prompt:
    //   1. The site listed a credential we hold in excludeCredentials
    //      (the polite, spec-driven path), OR
    //   2. we hold ANY passkey for this rp_id with the same
    //      user_handle — even when the site sent no exclude list.
    //      Byte-equal handle so a genuinely different account can
    //      still register once. (An RP that legitimately wants to
    //      re-register must first remove the old passkey in Arca.)
    //
    // Case 2 is a house rule, not the spec, and it has a nasty
    // failure mode: if the RP does NOT actually hold the credential
    // — a registration it rejected, or one deleted server-side —
    // then re-registering is the only way back, and this silently
    // refuses it. The page renders our InvalidStateError as "you
    // already have a passkey", which is a lie from the RP's point of
    // view, and nothing anywhere says the way out is to delete the
    // passkey in Arca first. So case 2 is reported to the user;
    // case 1 is the RP's own polite signal and needs no narration.
    for item in vault.active_items().into_iter().flatten() {
        if let VaultItem::Passkey {
            rp_id: r,
            credential_id: cid,
            user_handle: uh,
            ..
        } = &item.data
        {
            if r.as_str() != rp_id {
                continue;
            }
            if exclude_credentials.iter().any(|e| e == cid) {
                return Ok(Some(Registered::Excluded));
            }
            if uh.as_slice() == user_handle {
                return Ok(Some(Registered::SameAccount));
            }
        }
    }
    Ok(None)
}

/// Store a passkey just created for `rp_id`: its credential id and private
/// key. Rolled back out if the vault cannot be saved.
pub(super) fn store_new_passkey(
    state: &Mutex<AppState>,
    rp_id: &str,
    user_name: String,
    user_handle: Vec<u8>,
    (credential_id, private_key): (Vec<u8>, Vec<u8>),
) -> Result<(), Response> {
    let mut st = state.lock().map_err(|_| error("internal"))?;
    let AppState { store, vault, .. } = &mut *st;
    let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
    };
    // Dedup: if a passkey for the same relying party AND the same
    // user handle already exists, REPLACE it (reuse its id) instead
    // of piling up a duplicate. Only when the user handle is
    // non-empty — an empty handle can't distinguish accounts, so we
    // must not collapse them.
    //
    // This is a RACE GUARD, not the ordinary path: the check above
    // already refused that exact condition before prompting, so the
    // only way to arrive here holding a match is for one to have
    // been written while the approval dialog was open. Do not read
    // it as "re-registration replaces the old key" — re-registration
    // never gets this far.
    let existing_id = if user_handle.is_empty() {
        None
    } else {
        vault.active_items().ok().and_then(|mut active| {
            active.find_map(|item| match &item.data {
                VaultItem::Passkey {
                    rp_id: r,
                    user_handle: uh,
                    ..
                } if r == rp_id && *uh == user_handle => Some(item.id),
                _ => None,
            })
        })
    };
    let mut item = Item::new(
        VaultItem::Passkey {
            title: rp_id.to_owned(),
            rp_id: rp_id.to_owned(),
            user_name,
            user_handle,
            credential_id,
            private_key,
            sign_count: 0,
        },
        crate::state::now_millis(),
    );
    if let Some(id) = existing_id {
        item.id = id;
    }
    let new_id = item.id;
    vault.upsert_item(item).map_err(|_| error("internal"))?;
    if store.save_synced(vault).is_err() {
        // Roll the in-memory passkey back out. Left in place, it is
        // an orphan the site never registered, and the exclude-list
        // check would answer "excluded" on every retry — locking the
        // user out of registering until they hunt it down by hand.
        // Only for a fresh registration: reusing an existing id via
        // the race guard means undoing would delete a real passkey.
        if existing_id.is_none() {
            let _ = vault.purge_item(new_id, crate::state::now_millis());
        }
        return Err(error("internal"));
    }
    crate::sync::mark_dirty();
    Ok(())
}

pub(super) fn passkey_get(
    ctx: &mut Ctx,
    origin: String,
    rp_id: String,
    client_data_hash: Vec<u8>,
    allow_credentials: Vec<Vec<u8>>,
    picked: bool,
) -> Response {
    let state = ctx.state;
    let app = ctx.app;
    let consent = &mut *ctx.consent;
    if !passkeys_enabled(state) {
        return error("passkeys_disabled");
    }
    log_passkey_request(state, &origin, &rp_id, false);
    // Related Origin Requests apply to the ceremony too — a passkey
    // registered for login.microsoft.com must be usable on the page
    // Microsoft actually redirects you to. No lock is held here.
    if !rp_id_allows_origin(&rp_id, &origin) {
        return error("origin_mismatch");
    }
    let cooldown_key = format!("{rp_id}/get");
    let verified_by_unlock =
        match open_for_sign_in(state, app, &mut *ctx.unlock, &rp_id, &cooldown_key) {
            Ok(verified) => verified,
            Err(response) => return response,
        };
    // Discover eligible accounts without choosing the first matching key.
    let choices = match passkey_choices(state, &rp_id, &allow_credentials) {
        Ok(choices) => choices,
        Err(response) => return response,
    };
    if choices.is_empty() {
        log_passkey_outcome(state, &rp_id, "no_passkey_stored");
        return error("not_found");
    }
    // Who chooses, and whether choosing already counts as approving.
    let (selected, confirmed) =
        match chooser(choices.len(), picked, verified_by_unlock, app.is_some()) {
            Chooser::Settled { approved } => (choices[0].id.clone(), approved),
            Chooser::Window => {
                let Some(app) = app else {
                    return error("account_selection_required");
                };
                let Some(id) = request_passkey_choice(app, &rp_id, &choices) else {
                    log_passkey_outcome(state, &rp_id, "declined_in_chooser");
                    return error("account_selection_cancelled");
                };
                (id, true)
            }
        };
    let Some(choice) = choices.iter().find(|c| c.id == selected) else {
        return error("account_selection_cancelled");
    };
    // Reload after the choice: the vault may have locked or synced while
    // the dialog was open. Never substitute a different account.
    let ChosenPasskey {
        credential_id,
        user_handle,
        private_key,
    } = match chosen_passkey(state, &selected, &rp_id, &choice.credential_id) {
        Ok(chosen) => chosen,
        Err(response) => return response,
    };

    // An assertion ALWAYS requires an explicit user approval — otherwise
    // the authenticator would falsely claim user presence/verification,
    // which relying parties trust for step-up defenses. `false` = this
    // is a sign-in, so the prompt says "sign in" (not "create").
    let require_password = passkey_reprompt(state);
    let user_verified = if verified_by_unlock && !require_password {
        // The prompt that opened the vault said "sign in to <rp_id>" a moment
        // ago: that was the user verifying this sign-in.
        clear_passkey_decline(&cooldown_key);
        true
    } else {
        let Some(user_verified) =
            approve_passkey(&rp_id, false, app, consent, confirmed, require_password)
        else {
            // Cancelled, or a biometric prompt that never came back — which
            // looks to the user like the browser hanging on the sign-in.
            log_passkey_outcome(state, &rp_id, "declined_or_no_verification");
            return error("denied");
        };
        user_verified
    };

    // The prompt can outlast the vault, exactly as it can for a fill:
    // the private key was read before the wait, and idle or blur lock
    // can fire while the user is looking at the dialog. Signing anyway
    // would let a locked vault authenticate a sign-in — a stronger act
    // than releasing a password, since the relying party takes the
    // assertion as proof the user was present just now.
    let locked = state
        .lock()
        .map(|st| !st.vault.as_ref().is_some_and(|v| v.is_unlocked()))
        .unwrap_or(true);
    if locked {
        log_passkey_outcome(state, &rp_id, "locked_during_prompt");
        return error("locked");
    }

    let Ok((authenticator_data, signature)) =
        vault_core::passkey::assert(&private_key, &rp_id, &client_data_hash, user_verified)
    else {
        return error("internal");
    };
    log_passkey_outcome(state, &rp_id, "signed");
    if let Some(app) = app {
        let _ = app.emit("passkey-used", rp_id);
    }
    Response::PasskeyAssertion {
        credential_id,
        authenticator_data,
        signature,
        user_handle,
    }
}

/// Who decides which account a sign-in uses.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Chooser {
    /// Nobody needs to: the site allows one account. `approved` when the user
    /// has approved it already.
    Settled { approved: bool },
    /// Arca's window asks which, one button per account; choosing is approving.
    Window,
}

/// `accounts` the site allows; `picked`: the user chose one in Arca's in-page
/// list; `verified_by_unlock`: the fingerprint that opened the vault a moment
/// ago was for this sign-in, on this site; `window`: there is one to ask in.
///
/// Asking "which account?" after either of those, with one account to offer,
/// is asking the same question twice: Arca's window used to do it with a
/// single button, after the user had picked the account in the page or given
/// the fingerprint that named the site. A request nobody approved still gets
/// the window, whose click is the approval, however many accounts there are.
/// (Headless/tests: no window, so a single match is selected outright and the
/// injected consent closure approves.)
pub(super) fn chooser(
    accounts: usize,
    picked: bool,
    verified_by_unlock: bool,
    window: bool,
) -> Chooser {
    match accounts {
        1 if picked || verified_by_unlock => Chooser::Settled { approved: true },
        1 if !window => Chooser::Settled { approved: false },
        _ => Chooser::Window,
    }
}

/// With the vault locked, open it for a sign-in: one prompt that says "sign in
/// to <site>", and the request goes on. Whether that prompt verified the user,
/// or the answer to give when the vault did not open.
///
/// The fingerprint that opens the vault is the user verification the assertion
/// needs, so the caller does not ask for it twice. The relay used to open the
/// vault as a step of its own first, and the sign-in then asked again.
///
/// A site the user keeps declining is muted as before, and a declined unlock
/// counts: a background tab re-firing its request must not become a stream of
/// Touch ID sheets.
fn open_for_sign_in(
    state: &Mutex<AppState>,
    app: Option<&AppHandle>,
    unlock: &mut dyn FnMut(&str) -> RequestUnlock,
    rp_id: &str,
    cooldown_key: &str,
) -> Result<bool, Response> {
    if app.is_some() && passkey_suppressed(cooldown_key) {
        log_passkey_outcome(state, rp_id, "suppressed");
        return Err(error("denied"));
    }
    match unlock(&format!("sign in to {rp_id}")) {
        RequestUnlock::Verified => Ok(true),
        RequestUnlock::AlreadyOpen | RequestUnlock::Unattended => Ok(false),
        RequestUnlock::Declined => {
            log_passkey_outcome(state, rp_id, "declined_unlock");
            if let Some(app) = app {
                if record_passkey_decline(cooldown_key) {
                    let _ = app.emit(
                        "passkey-suppressed",
                        PasskeySuppressedDto {
                            site: rp_id.to_string(),
                            is_create: false,
                        },
                    );
                }
            }
            Err(error("unlock_cancelled"))
        }
        // The window asks for the master password; the relay waits for it and
        // sends this same request again.
        RequestUnlock::Window => Err(error("unlocking")),
    }
}

/// The passkeys stored for `rp_id` that the site allows, as accounts to
/// choose from.
pub(super) fn passkey_choices(
    state: &Mutex<AppState>,
    rp_id: &str,
    allow_credentials: &[Vec<u8>],
) -> Result<Vec<PasskeyChoice>, Response> {
    let st = state.lock().map_err(|_| error("internal"))?;
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
    };
    Ok(vault
        .active_items()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            if let VaultItem::Passkey {
                rp_id: r,
                credential_id,
                user_name,
                ..
            } = &item.data
            {
                let allowed =
                    allow_credentials.is_empty() || allow_credentials.contains(credential_id);
                if r == rp_id && allowed {
                    return Some(PasskeyChoice {
                        id: item.id.to_string(),
                        account: user_name.clone(),
                        title: item.data.title().to_owned(),
                        credential_id: credential_id.clone(),
                    });
                }
            }
            None
        })
        .collect())
}

/// What signing an assertion needs of the passkey the user chose.
pub(super) struct ChosenPasskey {
    pub(super) credential_id: Vec<u8>,
    pub(super) user_handle: Vec<u8>,
    pub(super) private_key: Vec<u8>,
}

/// The chosen passkey, if it is still the one chosen: same item, relying
/// party and credential, and not deleted.
pub(super) fn chosen_passkey(
    state: &Mutex<AppState>,
    selected: &str,
    rp_id: &str,
    credential_id: &[u8],
) -> Result<ChosenPasskey, Response> {
    let st = state.lock().map_err(|_| error("internal"))?;
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return Err(error("locked"));
    };
    let item = selected
        .parse::<Uuid>()
        .ok()
        .and_then(|id| vault.get_item(id).ok());
    match &item {
        Some(Item {
            data:
                VaultItem::Passkey {
                    rp_id: r,
                    credential_id: cid,
                    user_handle,
                    private_key,
                    ..
                },
            deleted_at: None,
            ..
        }) if r == rp_id && cid.as_slice() == credential_id => Ok(ChosenPasskey {
            credential_id: cid.clone(),
            user_handle: user_handle.clone(),
            private_key: private_key.clone(),
        }),
        _ => Err(error("not_found")),
    }
}

/// Mandatory user approval for a passkey create/get. Returns `Some(user_verified)`
/// on approval — `true` when a genuine user verification gated it — or `None`
/// on denial. A passkey operation must NEVER proceed without this.
/// Whether Arca should handle passkey ceremonies at all (the Settings kill
/// switch). Defaults to on if the state lock is unavailable.
pub(super) fn passkeys_enabled(state: &Mutex<AppState>) -> bool {
    state
        .lock()
        .map(|st| st.settings.handle_passkeys)
        .unwrap_or(true)
}

/// How long a decline silences further passkey prompts for the same relying
/// party, by how many times in a row it has been declined.
///
/// A single fixed cooldown was the original design and it was wrong: a page
/// that keeps firing ceremonies just gets a fresh prompt every time the window
/// expires, forever. Ninety seconds is not a cooldown, it is a snooze button
/// nobody asked for, and from the user's chair it is indistinguishable from the
/// nag never stopping.
///
/// The escalation matters more than the exact numbers. The browser side tries
/// to tell a real "sign in with a passkey" click from a page auto-firing one,
/// but it only has `navigator.userActivation`, which means "the user did
/// *something* in the last few seconds" — click anywhere on a login page and a
/// background ceremony sails straight through. That heuristic will always be
/// approximate, so this side, which is the one that actually puts a Touch ID
/// prompt on screen, must be the one that can say no permanently.
pub(super) const PASSKEY_DECLINE_BACKOFF: [Duration; 3] = [
    Duration::from_secs(90),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
];

/// Consecutive declines after which a site is suppressed for the rest of the
/// session. Deliberately not forever-across-restarts: quitting the app is a
/// clear, discoverable way back, and persisting a refusal the user cannot see
/// would strand a genuine sign-in with no explanation.
pub(super) const PASSKEY_DECLINE_LIMIT: u32 = 4;

/// A handful of declines and then stop, not an unbounded ladder. Checked here
/// rather than in a test because a test that loops to this value would hang
/// instead of failing if it ever grew.
const _: () = assert!(PASSKEY_DECLINE_LIMIT <= 10);

pub(super) struct PasskeyDecline {
    pub(super) at: Instant,
    /// Consecutive declines with no approval in between.
    pub(super) count: u32,
}

/// Per-(site, action) decline state (see the backoff above).
pub(super) static PASSKEY_DECLINED_AT: LazyLock<Mutex<HashMap<String, PasskeyDecline>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn passkey_decline_map(
) -> std::sync::MutexGuard<'static, HashMap<String, PasskeyDecline>> {
    match PASSKEY_DECLINED_AT.lock() {
        Ok(m) => m,
        Err(e) => e.into_inner(),
    }
}

/// Whether to stay silent instead of prompting again.
pub(super) fn passkey_suppressed(key: &str) -> bool {
    let map = passkey_decline_map();
    let Some(decline) = map.get(key) else {
        return false;
    };
    if decline.count >= PASSKEY_DECLINE_LIMIT {
        return true;
    }
    let step = (decline.count as usize).saturating_sub(1);
    decline.at.elapsed() < PASSKEY_DECLINE_BACKOFF[step.min(PASSKEY_DECLINE_BACKOFF.len() - 1)]
}

/// Record a decline. Returns true when this one crossed into "suppressed for
/// the session", so the caller can say so rather than going quiet unexplained.
pub(super) fn record_passkey_decline(key: &str) -> bool {
    let mut map = passkey_decline_map();
    let decline = map.entry(key.to_string()).or_insert(PasskeyDecline {
        at: Instant::now(),
        count: 0,
    });
    decline.at = Instant::now();
    decline.count += 1;
    decline.count == PASSKEY_DECLINE_LIMIT
}

/// Reset the backoff for a key (after a successful approval, so a later genuine
/// ceremony is not suppressed).
pub(super) fn clear_passkey_decline(key: &str) {
    passkey_decline_map().remove(key);
}

/// Approve a passkey ceremony. `is_create` distinguishes registering a NEW
/// passkey from signing in with an existing one — the user sees a different
/// prompt for each, so accepting a background "create a passkey" can never be
/// mistaken for a login. The decline cooldown is keyed per (site, action) so a
/// declined create never suppresses a real sign-in.
/// Whether the user wants the master password on every passkey use (the
/// stricter, pre-0.7 behaviour), rather than the unlocked vault plus a click.
pub(super) fn passkey_reprompt(state: &Mutex<AppState>) -> bool {
    state
        .lock()
        .map(|st| st.settings.passkey_reprompt)
        .unwrap_or(true)
}

pub(super) fn approve_passkey(
    rp_id: &str,
    is_create: bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
    confirmed: bool,
    require_password: bool,
) -> Option<bool> {
    let cooldown_key = format!("{rp_id}/{}", if is_create { "create" } else { "get" });
    // If the user just declined this same action for this site, a background tab
    // is almost certainly re-firing it — suppress silently instead of nagging.
    // (Only active in production, where `app` drives a real prompt; unit tests
    // inject their own consent and must run every time.)
    if app.is_some() && passkey_suppressed(&cooldown_key) {
        return None;
    }
    let result = approve_passkey_inner(rp_id, is_create, app, consent, confirmed, require_password);
    if let Some(app) = app {
        match result {
            None => {
                if record_passkey_decline(&cooldown_key) {
                    // Going quiet without saying so would look like a bug the
                    // next time the user genuinely wanted to sign in.
                    let _ = app.emit(
                        "passkey-suppressed",
                        PasskeySuppressedDto {
                            site: rp_id.to_string(),
                            is_create,
                        },
                    );
                }
            }
            Some(_) => clear_passkey_decline(&cooldown_key),
        }
    }
    result
}

/// Told to the UI when a site is muted for the session, so the user learns it
/// from Arca rather than from a sign-in that mysteriously stops working.
#[derive(Clone, serde::Serialize)]
pub(super) struct PasskeySuppressedDto {
    pub(super) site: String,
    pub(super) is_create: bool,
}

/// Append one line about an incoming passkey ceremony, so a prompt that appears
/// out of nowhere can be traced instead of guessed at.
///
/// This exists because the "GitHub keeps asking for Touch ID" report has come
/// back repeatedly with nothing to read: the ceremony arrives from a browser
/// context we cannot see, and the app recorded nothing at all. A prompt the
/// user did not expect is exactly the event that needs a paper trail.
///
/// No secret: an origin and an rp_id, which the relying party already knows.
/// But together they list the user's sites, so nothing is written unless the
/// log is turned on (see [`discard_passkey_log`]). Bounded so it cannot grow
/// without limit.
/// Record how a ceremony ENDED.
///
/// The arrival line alone was not enough the first time it mattered: a UniFi
/// sign-in was logged as having reached the app, and the log had nothing to say
/// about whether it found a passkey, was refused, timed out on a Touch ID
/// prompt nobody saw, or signed successfully. Those need four different fixes.
pub fn log_passkey_outcome(state: &Mutex<AppState>, rp_id: &str, outcome: &str) {
    log_line(state, &format!("\tresult\trp_id={rp_id}\t{outcome}"));
}

pub(super) fn log_passkey_request(
    state: &Mutex<AppState>,
    origin: &str,
    rp_id: &str,
    is_create: bool,
) {
    let kind = if is_create { "create" } else { "get" };
    log_line(state, &format!("{kind}\torigin={origin}\trp_id={rp_id}"));
}

/// The troubleshooting log of passkey ceremonies, beside the vault.
const PASSKEY_LOG: &str = "passkey-requests.log";

/// Delete the passkey log beside `vault_path`, if there is one.
///
/// Each line names a site the user signs in to, and when: no secret, but a
/// plaintext list of their accounts outside the encrypted vault, in every
/// backup of the folder. So it is kept only while the setting is on, and this
/// runs at startup and whenever the setting is off, which also removes the
/// log earlier versions kept unasked.
pub fn discard_passkey_log(vault_path: &std::path::Path) {
    let _ = std::fs::remove_file(vault_path.with_file_name(PASSKEY_LOG));
}

/// Append one tab-separated line to `passkey-requests.log`, timestamped, when
/// the user has turned the log on (Settings ▸ Keep a log of passkey requests).
///
/// The vault's own directory — no extra dependency, and it is where every other
/// file of ours already lives. The lock is taken and dropped here, never held
/// across the write.
pub(super) fn log_line(state: &Mutex<AppState>, rest: &str) {
    use std::io::Write;
    // `try_lock`, NOT `lock`. This is called from inside request handlers, and
    // one of them called it while already holding the guard — a std::sync
    // Mutex is not reentrant, so the app deadlocked on its own debug log and
    // the passkey test hung forever. A log line is worth losing; a hung
    // credential bridge is not, and the next caller to make the same mistake
    // should get a missing line rather than a frozen browser.
    let Some(dir) = state
        .try_lock()
        .ok()
        .filter(|st| st.settings.log_passkey_requests)
        .and_then(|st| st.store.path().parent().map(|p| p.to_path_buf()))
    else {
        return;
    };
    let path = dir.join(PASSKEY_LOG);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{stamp}\t{rest}\n");

    // Trim before appending, so the file stays roughly bounded without needing
    // a rotation scheme for what is a debugging aid.
    const MAX_LINES: usize = 500;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let count = existing.lines().count();
        if count >= MAX_LINES {
            let keep: String = existing
                .lines()
                .skip(count - MAX_LINES / 2)
                .map(|l| format!("{l}\n"))
                .collect();
            let _ = std::fs::write(&path, keep);
        }
    }
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// `confirmed`: the user already approved this exact ceremony by a click in
/// Arca's own UI (the in-page picker row, the desktop chooser). `require_password`:
/// the "ask for the master password on every passkey use" setting.
///
/// USER VERIFICATION, as Arca means it. The vault is open, and opening it was
/// the verification: the master password, Touch ID, Windows Hello or the USB
/// key the user enrolled for exactly that purpose, bounded by the idle lock.
/// A sign-in then needs presence — one deliberate click that names the site
/// and the account — not a second password. That is what 1Password and Apple
/// Passwords do; it is what the double prompt was standing in the way of. The
/// setting restores the per-use prompt for people who want it: Touch ID on a
/// Mac, the master password elsewhere.
pub(super) fn approve_passkey_inner(
    rp_id: &str,
    is_create: bool,
    app: Option<&AppHandle>,
    consent: &mut dyn FnMut(&ConsentContext) -> bool,
    confirmed: bool,
    require_password: bool,
) -> Option<bool> {
    // The click that chose this account in Arca's own UI is the approval, on
    // every platform. macOS used to ask for Touch ID on top of it, so a
    // sign-in that opened the vault first asked twice: once to unlock, and
    // again to sign in with the account the user had just picked.
    if confirmed && !require_password {
        return Some(true);
    }
    // The reason string the user reads — clearly different for registering a new
    // passkey vs signing in, so a create can't be mistaken for a login.
    let reason = if is_create {
        format!("create a NEW passkey for {rp_id}")
    } else {
        format!("sign in to {rp_id}")
    };
    // macOS: Touch ID — a genuine platform user verification. It's a system
    // prompt, so it works even though the ceremony is triggered from the
    // background (the browser).
    #[cfg(target_os = "macos")]
    if app.is_some() {
        return match crate::biometric::authenticate(None, &reason) {
            Ok(()) => Some(true),
            Err(_) => None,
        };
    }
    // Windows/Linux: the OS platform-authenticator (Windows Hello) dialog can't
    // receive keyboard input when invoked from our background bridge thread, so
    // we do user verification in our OWN window instead — the user re-enters the
    // master password. A correct password is a genuine user-verification factor
    // (the very secret that unlocks the vault), so we may honestly set UV=1.
    #[cfg(not(target_os = "macos"))]
    if let Some(app) = app {
        return request_passkey_verification(app, rp_id, is_create, require_password);
    }
    // Tests / headless (no AppHandle): the injected consent closure provides
    // user presence only (user_verified = false).
    let _ = app;
    let ctx = ConsentContext {
        site: rp_id.to_string(),
        account: String::new(),
        title: reason,
    };
    consent(&ctx).then_some(false)
}

/// Windows/Linux user verification for a passkey ceremony: emit a request to the
/// frontend (which prompts for the master password in our own window), bring the
/// window forward, and block this bridge thread until the password is verified
/// (`Some(true)`) or the user cancels / it times out (`None`). Reuses the
/// `PendingConsents` channel; `verify_passkey_approval` only resolves it `true`
/// after the master password checks out.
#[cfg(not(target_os = "macos"))]
pub(super) fn request_passkey_verification(
    app: &AppHandle,
    rp_id: &str,
    is_create: bool,
    require_password: bool,
) -> Option<bool> {
    let verify_id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        // Dedicated verification map — never the shared consent map — so only a
        // password-checked resolve (or, when the bridge said a click is enough,
        // the confirm command) can satisfy this `true`.
        let pending = app.state::<PendingVerifications>();
        let Ok(mut map) = pending.0.lock() else {
            return None;
        };
        map.insert(verify_id.clone(), (tx, require_password));
    }
    let _ = app.emit(
        "passkey-verify-request",
        serde_json::json!({
            "id": verify_id,
            "site": rp_id,
            "isCreate": is_create,
            "requirePassword": require_password,
        }),
    );
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
    let verified = rx.recv_timeout(CONSENT_TIMEOUT).unwrap_or(false);
    if let Ok(mut map) = app.state::<PendingVerifications>().0.lock() {
        map.remove(&verify_id);
    }
    verified.then_some(true)
}

pub(super) fn request_passkey_choice(
    app: &AppHandle,
    rp_id: &str,
    choices: &[PasskeyChoice],
) -> Option<String> {
    let id = Uuid::new_v4().simple().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let pending = app.state::<PendingPasskeyChoices>();
        let mut map = pending.0.lock().ok()?;
        // Keep one visible chooser; concurrent requests fail closed.
        if !map.is_empty() {
            return None;
        }
        map.insert(id.clone(), tx);
    }
    let emitted = app
        .emit(
            "passkey-choice-request",
            serde_json::json!({"id": id, "site": rp_id, "accounts": choices}),
        )
        .is_ok();
    if emitted {
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
    let choice = if emitted {
        rx.recv_timeout(CONSENT_TIMEOUT).ok().flatten()
    } else {
        None
    };
    if let Ok(mut map) = app.state::<PendingPasskeyChoices>().0.lock() {
        map.remove(&id);
    }
    let _ = app.emit("passkey-choice-closed", &id);
    choice.filter(|id| choices.iter().any(|c| &c.id == id))
}

pub fn resolve_passkey_choice(app: &AppHandle, id: &str, item_id: Option<String>) {
    if let Ok(mut map) = app.state::<PendingPasskeyChoices>().0.lock() {
        if let Some(tx) = map.remove(id) {
            let _ = tx.send(item_id);
        }
    }
}

/// Resolve a pending passkey user-verification. Called only from the
/// password-checked `verify_passkey_approval` command (with `true`) and the
/// `cancel_passkey_verification` command (always `false`), so the presence-only
/// autofill-consent path can never set UV=1.
pub fn resolve_verification(app: &AppHandle, id: &str, approved: bool) {
    if let Ok(mut map) = app.state::<PendingVerifications>().0.lock() {
        if let Some((tx, _)) = map.remove(id) {
            let _ = tx.send(approved);
        }
    }
}

/// Approve a pending passkey ceremony with a click alone. Refused — and the
/// ceremony left waiting for the password — when the bridge registered it as
/// password-required; a UI cannot downgrade the check by calling this instead.
pub fn confirm_verification(app: &AppHandle, id: &str) -> bool {
    let pending = app.state::<PendingVerifications>();
    let Ok(mut map) = pending.0.lock() else {
        return false;
    };
    match map.get(id) {
        Some((_, false)) => {
            if let Some((tx, _)) = map.remove(id) {
                let _ = tx.send(true);
            }
            true
        }
        _ => false,
    }
}
