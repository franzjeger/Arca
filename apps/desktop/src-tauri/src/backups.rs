//! Optional rotating encrypted copies in a user-selected folder.
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use uuid::Uuid;

use crate::state::{now_secs, AppState, CmdError};

const INTERVAL: u64 = 15 * 60;
const KEEP: usize = 30;
const KEEP_DAYS: u64 = 30;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BackupStatus {
    pub directory: Option<PathBuf>,
    pub last_success_unix: Option<u64>,
    pub last_error: Option<String>,
    pub last_file: Option<PathBuf>,
    // Own namespace: pruning must never remove someone else's backups.
    namespace: String,
}

fn is_git_repository_or_internal(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == ".git") || path.join(".git").exists()
}

pub struct Backups {
    config: PathBuf,
    status: BackupStatus,
}

impl Backups {
    pub fn load(vault_path: &Path) -> Self {
        let config = vault_path.with_file_name("backups.json");
        let mut status: BackupStatus = match std::fs::read(&config) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| BackupStatus {
                last_error: Some(
                    "Backup settings are unreadable. Choose the backup folder again.".into(),
                ),
                ..Default::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BackupStatus::default(),
            Err(_) => BackupStatus {
                last_error: Some("Could not read backup settings.".into()),
                ..Default::default()
            },
        };
        if status.directory.is_some() && Uuid::parse_str(&status.namespace).is_err() {
            status.directory = None;
            status.last_error =
                Some("Backup settings are invalid. Choose the folder again.".into());
        }
        if let Some(dir) = &status.directory {
            if is_git_repository_or_internal(dir) {
                status.directory = None;
                status.last_error = Some(
                    "Backup folder inside a Git repository is invalid. Choose the folder again."
                        .into(),
                );
            }
        }
        Self { config, status }
    }

    fn persist(&self, status: &BackupStatus) -> Result<(), CmdError> {
        let bytes = serde_json::to_vec_pretty(status)
            .map_err(|_| CmdError::new("backup", "Could not encode backup settings."))?;
        vault_store::write_atomic(&self.config, &bytes)
            .map_err(|_| CmdError::new("backup", "Could not save backup settings."))
    }

    fn configure(&mut self, directory: Option<PathBuf>) -> Result<(), CmdError> {
        let directory = directory
            .map(|path| {
                if !path.is_dir() {
                    return Err(CmdError::new(
                        "backup",
                        "Choose an available backup folder.",
                    ));
                }
                let canonical = path
                    .canonicalize()
                    .map_err(|_| CmdError::new("backup", "Could not open that folder."))?;
                if is_git_repository_or_internal(&canonical) {
                    return Err(CmdError::new(
                        "backup",
                        "Cannot use a Git repository as a backup folder.",
                    ));
                }
                Ok(canonical)
            })
            .transpose()?;
        let next = BackupStatus {
            directory,
            namespace: Uuid::new_v4().to_string(),
            ..Default::default()
        };
        self.persist(&next)?;
        self.status = next;
        Ok(())
    }

    fn run(&mut self, vault_path: &Path, force: bool, now: u64) -> Result<(), CmdError> {
        let Some(directory) = self.status.directory.clone() else {
            return Ok(());
        };
        if !force
            && self
                .status
                .last_success_unix
                .is_some_and(|last| now.saturating_sub(last) < INTERVAL)
        {
            return Ok(());
        }
        let result = self.capture(vault_path, &directory, now);
        match result {
            Ok(path) => {
                let mut next = self.status.clone();
                next.last_success_unix = Some(now);
                next.last_file = Some(path);
                next.last_error = None;
                // A backup can be valid while recording its status fails. Say so.
                if let Err(error) = self.persist(&next) {
                    next.last_error = Some(error.message.clone());
                    self.status = next;
                    return Err(error);
                }
                self.status = next;
                Ok(())
            }
            Err(error) => {
                self.status.last_error = Some(error.message.clone());
                let _ = self.persist(&self.status);
                Err(error)
            }
        }
    }

    fn capture(&self, vault_path: &Path, directory: &Path, now: u64) -> Result<PathBuf, CmdError> {
        // Do not recreate a missing mount point and silently back up to the
        // system disk when an external drive is unplugged.
        if !directory.is_dir() {
            return Err(CmdError::new(
                "backup",
                "Backup folder unavailable. Reconnect the drive and retry.",
            ));
        }
        if is_git_repository_or_internal(directory) {
            return Err(CmdError::new(
                "backup",
                "Cannot back up to a Git repository.",
            ));
        }
        let prefix = format!("arca-{}-", self.status.namespace);
        let path = directory.join(format!("{prefix}{now:020}-{}.vault", Uuid::new_v4()));
        vault_store::export_backup_file(vault_path, &path)?;
        let mut files: Vec<(u64, PathBuf)> = std::fs::read_dir(directory)
            .map_err(|_| {
                CmdError::new(
                    "backup",
                    "Backup saved, but older copies could not be listed.",
                )
            })?
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .filter_map(|e| {
                let name = e.file_name();
                let rest = name
                    .to_str()?
                    .strip_prefix(&prefix)?
                    .strip_suffix(".vault")?;
                let (timestamp, unique) = rest.split_once('-')?;
                Uuid::parse_str(unique).ok()?;
                Some((timestamp.parse().ok()?, e.path()))
            })
            .collect();
        files.sort();
        let mut days = std::collections::HashSet::new();
        for (index, (timestamp, old)) in files.iter().rev().enumerate() {
            let daily = now.saturating_sub(*timestamp) < KEEP_DAYS * 86_400
                && days.insert(timestamp / 86_400);
            if index < KEEP || daily {
                continue;
            }
            std::fs::remove_file(old).map_err(|_| {
                CmdError::new(
                    "backup",
                    "Backup saved, but an older copy could not be removed.",
                )
            })?;
        }
        Ok(path)
    }
}

#[tauri::command]
pub fn backup_status(backups: tauri::State<'_, Mutex<Backups>>) -> Result<BackupStatus, CmdError> {
    Ok(backups
        .lock()
        .map_err(|_| CmdError::new("backup", "Backup service unavailable."))?
        .status
        .clone())
}

#[tauri::command]
pub fn configure_backups(
    backups: tauri::State<'_, Mutex<Backups>>,
    directory: Option<String>,
) -> Result<BackupStatus, CmdError> {
    let mut backups = backups
        .lock()
        .map_err(|_| CmdError::new("backup", "Backup service unavailable."))?;
    backups.configure(directory.map(PathBuf::from))?;
    Ok(backups.status.clone())
}

fn run(app: &AppHandle, force: bool) -> Result<BackupStatus, CmdError> {
    // Backups contain ciphertext already on disk. Never keep the app-state
    // mutex while writing to a removable/network drive: auto-lock and ordinary
    // vault commands must remain responsive even if that drive stops responding.
    let vault_path = {
        let state = app.state::<Mutex<AppState>>();
        let state = state
            .lock()
            .map_err(|_| CmdError::new("backup", "Vault unavailable."))?;
        state.store.path().to_owned()
    };
    let backups = app.state::<Mutex<Backups>>();
    let mut backups = backups
        .lock()
        .map_err(|_| CmdError::new("backup", "Backup service unavailable."))?;
    if vault_path.is_file() {
        backups.run(&vault_path, force, now_secs())?;
    }
    Ok(backups.status.clone())
}

#[tauri::command]
pub async fn run_backup_now(app: AppHandle) -> Result<BackupStatus, CmdError> {
    tauri::async_runtime::spawn_blocking(move || run(&app, true))
        .await
        .map_err(|_| CmdError::new("backup", "Backup worker stopped."))?
}

pub fn start(app: AppHandle) {
    std::thread::spawn(move || loop {
        let _ = run(&app, false);
        std::thread::sleep(Duration::from_secs(60));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (
        tempfile::TempDir,
        vault_store::VaultStore,
        vault_core::Vault,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = vault_store::VaultStore::new(dir.path().join("current.vault"), "test", "test");
        let mut params = vault_core::KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        let vault = vault_core::Vault::create("backup-password", params).unwrap();
        store.save(&vault).unwrap();
        (dir, store, vault)
    }

    #[test]
    fn automatic_backup_restores_with_password_and_rotates_only_own_files() {
        let (dir, store, _) = setup();
        let folder = dir.path().join("external");
        std::fs::create_dir(&folder).unwrap();
        let unrelated = folder.join("personal.vault");
        std::fs::write(&unrelated, b"leave alone").unwrap();
        let mut backups = Backups::load(store.path());
        backups.configure(Some(folder.clone())).unwrap();
        for now in 1..=35 {
            backups.run(store.path(), true, now).unwrap();
        }
        assert_eq!(std::fs::read_dir(&folder).unwrap().count(), KEEP + 1);
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"leave alone");
        let restored_store = vault_store::VaultStore::new(
            backups.status.last_file.as_ref().unwrap(),
            "test",
            "restore",
        );
        let mut restored = restored_store.load().unwrap();
        assert!(restored.unlock("wrong").is_err());
        restored.unlock("backup-password").unwrap();
        assert_eq!(
            Backups::load(store.path()).status.last_success_unix,
            Some(35)
        );
        let previous = backups.status.last_file.clone();
        backups.run(store.path(), false, 36).unwrap();
        assert_eq!(backups.status.last_file, previous);
    }

    #[test]
    fn daily_copies_survive_more_than_thirty_recent_backups() {
        let (dir, store, _) = setup();
        let folder = dir.path().join("external");
        std::fs::create_dir(&folder).unwrap();
        let mut backups = Backups::load(store.path());
        backups.configure(Some(folder.clone())).unwrap();
        backups.run(store.path(), true, 1).unwrap();
        let yesterday = backups.status.last_file.clone().unwrap();
        for now in 100_000..100_035 {
            backups.run(store.path(), true, now).unwrap();
        }
        assert!(yesterday.is_file());
        assert_eq!(std::fs::read_dir(folder).unwrap().count(), KEEP + 1);
    }

    #[test]
    fn missing_drive_reports_failure_without_recreating_it_or_advancing_success() {
        let (dir, store, _) = setup();
        let folder = dir.path().join("external");
        std::fs::create_dir(&folder).unwrap();
        let mut backups = Backups::load(store.path());
        backups.configure(Some(folder.clone())).unwrap();
        backups.run(store.path(), true, 1).unwrap();
        std::fs::rename(&folder, dir.path().join("unmounted")).unwrap();
        assert!(backups.run(store.path(), true, 2).is_err());
        assert!(!folder.exists());
        assert_eq!(backups.status.last_success_unix, Some(1));
        assert!(backups.status.last_error.is_some());
    }

    #[test]
    fn repo_root_is_rejected_as_backup_destination() {
        let (dir, store, _) = setup();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let mut backups = Backups::load(store.path());

        // configure() rejects the repository root
        let err = backups.configure(Some(repo.clone())).unwrap_err();
        assert_eq!(err.code, "backup");
        assert!(err.message.contains("Git repository"));

        // configure() also rejects a path containing .git
        let git_dir = repo.join(".git");
        let err2 = backups.configure(Some(git_dir)).unwrap_err();
        assert_eq!(err2.code, "backup");
        assert!(err2.message.contains("Git repository"));

        // capture() also rejects if invoked directly with a repo path
        let err3 = backups.capture(store.path(), &repo, 1).unwrap_err();
        assert_eq!(err3.code, "backup");
        assert!(err3.message.contains("Git repository"));

        // Backups::load sanitizes pre-existing config pointing to a repo
        let config_path = store.path().with_file_name("backups.json");
        let pre_existing = BackupStatus {
            directory: Some(repo),
            namespace: Uuid::new_v4().to_string(),
            ..Default::default()
        };
        std::fs::write(&config_path, serde_json::to_vec(&pre_existing).unwrap()).unwrap();
        let loaded = Backups::load(store.path());
        assert_eq!(loaded.status.directory, None);
        assert!(loaded.status.last_error.is_some());
    }
}
