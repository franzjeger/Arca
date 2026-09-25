//! Fresh authorization for sensitive operations, bound to the active session.
//! Password derivation and OS prompts never hold the app-state mutex.

use crate::state::{AppState, CmdError};
use std::sync::Mutex;
use tauri::Manager;
use uuid::Uuid;
use vault_core::VaultHeader;
use zeroize::Zeroizing;

pub struct Authorization {
    session: Uuid,
    header: Vec<u8>,
}

impl Authorization {
    pub fn capture(state: &AppState) -> Result<(Self, VaultHeader), CmdError> {
        let vault = state.vault.as_ref().ok_or_else(CmdError::no_vault)?;
        let session = vault
            .session_id()
            .ok_or_else(|| CmdError::new("locked", "Unlock the vault first."))?;
        Ok((
            Self {
                session,
                header: serde_json::to_vec(vault.header())
                    .map_err(|_| CmdError::new("internal", "Could not prepare verification."))?,
            },
            vault.header().clone(),
        ))
    }

    pub fn validate(&self, state: &AppState) -> Result<(), CmdError> {
        let (current, _) = Self::capture(state)?;
        if current.session != self.session || current.header != self.header {
            return Err(CmdError::new(
                "reauth_expired",
                "The vault changed during verification. Try again.",
            ));
        }
        Ok(())
    }
}

fn verify_password(
    header: &VaultHeader,
    password: Option<Zeroizing<String>>,
) -> Result<(), CmdError> {
    let password = password.ok_or_else(|| {
        CmdError::new(
            "reauth_required",
            "Enter your current master password to continue.",
        )
    })?;
    if header.check_master_password(&password) {
        Ok(())
    } else {
        Err(CmdError::new(
            "reauth_failed",
            "The current master password was not accepted.",
        ))
    }
}

pub async fn authorize(
    app: &tauri::AppHandle,
    reason: &'static str,
    password: Option<String>,
) -> Result<Authorization, CmdError> {
    let password = password.map(Zeroizing::new);
    let (authorization, header) = {
        let state = app.state::<Mutex<AppState>>();
        let state = state
            .lock()
            .map_err(|_| CmdError::new("internal", "Could not read the vault state."))?;
        Authorization::capture(&state)?
    };
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if crate::biometric::available() {
            let _password = password;
            crate::biometric::authenticate(Some(&app), reason)
                .map_err(|_| CmdError::new("biometric_failed", "Verification was not confirmed."))
        } else {
            verify_password(&header, password)
        }
    })
    .await
    .map_err(|_| CmdError::new("internal", "Verification failed."))??;
    Ok(authorization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, Vault};
    #[test]
    fn password_confirmation_rejects_missing_wrong_and_empty_passwords() {
        let vault = Vault::create("correct-password", KdfParams::new_default().unwrap()).unwrap();
        for password in [None, Some(String::new()), Some("wrong".into())] {
            assert!(verify_password(vault.header(), password.map(Zeroizing::new)).is_err());
        }
        verify_password(
            vault.header(),
            Some(Zeroizing::new("correct-password".into())),
        )
        .unwrap();
    }

    #[test]
    fn authorization_expires_on_lock_reunlock_rotation_or_vault_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let store = vault_store::VaultStore::new(directory.path().join("vault"), "test", "reauth");
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        let mut params = KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        params.p_cost = 1;
        let vault = Vault::create("correct-password", params.clone()).unwrap();
        let mut state = AppState::new(store, Some(vault), clipboard);
        let (authorization, _) = Authorization::capture(&state).unwrap();
        authorization.validate(&state).unwrap();
        state.vault.as_mut().unwrap().lock().unwrap();
        assert!(authorization.validate(&state).is_err());
        state
            .vault
            .as_mut()
            .unwrap()
            .unlock("correct-password")
            .unwrap();
        assert!(authorization.validate(&state).is_err());
        let (authorization, _) = Authorization::capture(&state).unwrap();
        state
            .vault
            .as_mut()
            .unwrap()
            .change_master_password("new-password")
            .unwrap();
        assert!(authorization.validate(&state).is_err());
        let (authorization, _) = Authorization::capture(&state).unwrap();
        state.vault = Some(Vault::create("new-password", params).unwrap());
        assert!(authorization.validate(&state).is_err());
    }
}
