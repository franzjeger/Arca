//! SSH keys already on this computer: find them in `~/.ssh`, cross them off
//! against each other and against the keys the vault holds, and take in the
//! ones the user picks.
//!
//! Keys are told apart by their public half's SHA-256 fingerprint, the one
//! `ssh-keygen -l` shows, which reads without a passphrase. So a key the vault
//! already has, or that two files hold, is named before anything is asked.
//!
//! The private halves are read and decrypted here, in Rust. The webview gets
//! file names, fingerprints and comments, and sends back only which files to
//! take and their passphrases. It names a file, never a path: nothing outside
//! `~/.ssh` is read.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use vault_core::ssh::{self, KeyFileError};
use vault_core::{Item, Vault, VaultItem};
use zeroize::Zeroize;

use crate::commands::{guard, persist, write_guard};
use crate::state::{now_millis, AppState, CmdError};

/// Anything larger is not a private key: `ssh-keygen`'s biggest (RSA 16384)
/// is a little over 12 KiB.
const MAX_KEY_FILE: u64 = 64 * 1024;

/// One private-key file in `~/.ssh`.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FoundKey {
    pub file: String,
    /// On the wire, e.g. `ssh-ed25519`; for an old PEM file, what its header
    /// says (`RSA`, `EC`, `DSA`).
    pub key_type: String,
    /// Empty for an old PEM file, which this does not read.
    pub fingerprint: String,
    pub comment: String,
    pub encrypted: bool,
    pub status: Found,
}

/// What the cross-check made of a file.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Found {
    /// Not in the vault yet: this one can be imported.
    New,
    /// The vault already holds this key, under `title`.
    #[serde(rename_all = "camelCase")]
    InVault { title: String },
    /// An earlier file here holds the same key.
    #[serde(rename_all = "camelCase")]
    SameAs { file: String },
    /// A key type the agent does not sign with yet.
    Unsupported,
}

/// `~/.ssh`.
pub fn ssh_dir(home: &Path) -> PathBuf {
    home.join(".ssh")
}

fn home_ssh(app: &tauri::AppHandle) -> Result<PathBuf, CmdError> {
    let home = app
        .path()
        .home_dir()
        .map_err(|_| CmdError::new("io", "Could not find your home folder."))?;
    Ok(ssh_dir(&home))
}

/// The private-key files in `~/.ssh`, crossed off against the vault.
#[tauri::command]
pub fn ssh_import_scan(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<FoundKey>, CmdError> {
    let dir = home_ssh(&app)?;
    let st = guard(state.inner())?;
    scan(&dir, st.vault()?)
}

/// Take the files the user picked in `~/.ssh` into the vault.
#[tauri::command]
pub fn ssh_import(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
    picks: Vec<Pick>,
) -> Result<Imported, CmdError> {
    let dir = home_ssh(&app)?;
    let mut st = write_guard(state.inner())?;
    st.touch();
    let done = import(&dir, st.vault_mut()?, &picks, now_millis())?;
    if !done.ids.is_empty() {
        persist(&mut st)?;
    }
    Ok(done)
}

/// The vault's SSH keys, by fingerprint, with their titles.
fn vault_keys(vault: &Vault) -> Result<HashMap<String, String>, CmdError> {
    Ok(vault
        .active_items()?
        .filter_map(|item| match &item.data {
            VaultItem::SshKey {
                title, public_key, ..
            } => Some((ssh::fingerprint(public_key), title.clone())),
            _ => None,
        })
        .collect())
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// The type an old PEM private key (`-----BEGIN RSA PRIVATE KEY-----`) names,
/// if `text` is one. OpenSSH's own format is read by `ssh::read_key_file`.
fn pem_type(text: &str) -> Option<String> {
    let header = text.trim_start().lines().next()?;
    let kind = header
        .strip_prefix("-----BEGIN ")?
        .strip_suffix(" PRIVATE KEY-----")?;
    (kind != "OPENSSH").then(|| kind.to_owned())
}

/// Every private-key file in `dir`, crossed off against each other and against
/// the vault, in file-name order.
pub fn scan(dir: &Path, vault: &Vault) -> Result<Vec<FoundKey>, CmdError> {
    let in_vault = vault_keys(vault)?;
    let mut names: Vec<String> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .collect(),
        // No ~/.ssh is no keys, not a failure.
        Err(_) => Vec::new(),
    };
    names.sort();

    let mut first_with: HashMap<String, String> = HashMap::new();
    let mut found = Vec::new();
    for name in names {
        let Some(text) = read_small(&dir.join(&name)) else {
            continue;
        };
        let file = match ssh::read_key_file(&text) {
            Ok(file) => file,
            Err(_) => {
                if let Some(key_type) = pem_type(&text) {
                    found.push(FoundKey {
                        file: name,
                        key_type,
                        fingerprint: String::new(),
                        comment: String::new(),
                        encrypted: false,
                        status: Found::Unsupported,
                    });
                }
                continue;
            }
        };
        let status = if !file.supported() {
            Found::Unsupported
        } else if let Some(title) = in_vault.get(&file.fingerprint) {
            Found::InVault {
                title: title.clone(),
            }
        } else if let Some(first) = first_with.get(&file.fingerprint) {
            Found::SameAs {
                file: first.clone(),
            }
        } else {
            first_with.insert(file.fingerprint.clone(), name.clone());
            Found::New
        };
        found.push(FoundKey {
            file: name,
            key_type: file.key_type,
            fingerprint: file.fingerprint,
            comment: file.comment,
            encrypted: file.encrypted,
            status,
        });
    }
    Ok(found)
}

/// A file the user picked, and its passphrase if it has one.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pick {
    pub file: String,
    pub passphrase: Option<String>,
}

impl Drop for Pick {
    fn drop(&mut self) {
        if let Some(passphrase) = self.passphrase.as_mut() {
            passphrase.zeroize();
        }
    }
}

/// What an import did, file by file.
#[derive(Serialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Imported {
    /// The new items' ids, in the order the files were picked.
    pub ids: Vec<String>,
    /// Files not taken, with why.
    pub failed: Vec<Failed>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Failed {
    pub file: String,
    /// `passphrase`, `unsupported`, `unreadable`, `in_vault` or `not_a_key_file`.
    pub reason: String,
}

/// Take the picked files into `vault`. Each is checked against the vault again,
/// and against those taken before it, so neither a second pick of the same key
/// nor a key the vault holds is ever stored twice. The caller persists.
pub fn import(
    dir: &Path,
    vault: &mut Vault,
    picks: &[Pick],
    now: i64,
) -> Result<Imported, CmdError> {
    let mut known = vault_keys(vault)?;
    let mut done = Imported::default();
    for pick in picks {
        let fail = |reason: &str| Failed {
            file: pick.file.clone(),
            reason: reason.to_owned(),
        };
        // A name, not a path: the webview never chooses what is read.
        let plain = Path::new(&pick.file)
            .file_name()
            .is_some_and(|n| n == pick.file.as_str());
        let Some(text) = plain.then(|| read_small(&dir.join(&pick.file))).flatten() else {
            done.failed.push(fail("not_a_key_file"));
            continue;
        };
        let key = match ssh::import_key_file(&text, pick.passphrase.as_deref()) {
            Ok(key) => key,
            Err(KeyFileError::Passphrase) => {
                done.failed.push(fail("passphrase"));
                continue;
            }
            Err(KeyFileError::Unsupported(_)) => {
                done.failed.push(fail("unsupported"));
                continue;
            }
            Err(KeyFileError::Unreadable) => {
                done.failed.push(fail("unreadable"));
                continue;
            }
        };
        if known.contains_key(&key.fingerprint) {
            done.failed.push(fail("in_vault"));
            continue;
        }
        let title = if key.comment.trim().is_empty() {
            pick.file.clone()
        } else {
            key.comment.trim().to_owned()
        };
        let item = Item::new(
            VaultItem::SshKey {
                title: title.clone(),
                comment: key.comment.trim().to_owned(),
                key_type: ssh::ALGORITHM.to_owned(),
                public_key: key.public_blob.clone(),
                private_key: key.private_key.to_vec(),
                fingerprint: key.fingerprint.clone(),
            },
            now,
        );
        done.ids.push(item.id.to_string());
        vault.upsert_item(item)?;
        known.insert(key.fingerprint, title);
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use vault_core::KdfParams;

    fn vault() -> Vault {
        let mut params = KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        Vault::create("pw", params).unwrap()
    }

    fn write_key(dir: &Path, name: &str, key: &PrivateKey) {
        let text = key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(dir.join(name), text.as_bytes()).unwrap();
    }

    fn ed25519(comment: &str) -> PrivateKey {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        key.set_comment(comment);
        key
    }

    #[test]
    fn a_scan_names_every_key_and_what_the_vault_holds() {
        let dir = tempfile::tempdir().unwrap();
        let mine = ed25519("me@laptop");
        let copied = ed25519("me@desktop");
        let locked = ed25519("");
        write_key(dir.path(), "id_ed25519", &mine);
        write_key(dir.path(), "a_copy", &copied);
        write_key(dir.path(), "b_copy", &copied);
        write_key(
            dir.path(),
            "locked",
            &locked.encrypt(&mut OsRng, "pw").unwrap(),
        );
        std::fs::write(
            dir.path().join("id_ed25519.pub"),
            "ssh-ed25519 AAAA me@laptop",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("known_hosts"),
            "github.com ssh-ed25519 AAAA",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("id_rsa"),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        let mut vault = vault();
        let first = import(
            dir.path(),
            &mut vault,
            &[Pick {
                file: "id_ed25519".into(),
                passphrase: None,
            }],
            1,
        )
        .unwrap();
        assert_eq!(first.ids.len(), 1);

        let found = scan(dir.path(), &vault).unwrap();
        let by_file: HashMap<_, _> = found.iter().map(|f| (f.file.as_str(), f)).collect();
        assert_eq!(found.len(), 5, "private keys only: {found:?}");
        assert_eq!(by_file["a_copy"].status, Found::New);
        assert_eq!(
            by_file["b_copy"].status,
            Found::SameAs {
                file: "a_copy".into()
            }
        );
        assert_eq!(
            by_file["id_ed25519"].status,
            Found::InVault {
                title: "me@laptop".into()
            }
        );
        assert!(by_file["locked"].encrypted);
        assert_eq!(by_file["locked"].status, Found::New);
        assert_eq!(by_file["id_rsa"].key_type, "RSA");
        assert_eq!(by_file["id_rsa"].status, Found::Unsupported);
    }

    #[test]
    fn an_import_takes_each_key_once_and_says_why_it_skipped_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let copied = ed25519("me@desktop");
        write_key(dir.path(), "a_copy", &copied);
        write_key(dir.path(), "b_copy", &copied);
        let locked = ed25519("locked@laptop");
        write_key(
            dir.path(),
            "locked",
            &locked.encrypt(&mut OsRng, "right").unwrap(),
        );

        let pick = |file: &str, passphrase: Option<&str>| Pick {
            file: file.into(),
            passphrase: passphrase.map(str::to_owned),
        };
        let mut vault = vault();
        let done = import(
            dir.path(),
            &mut vault,
            &[
                pick("a_copy", None),
                pick("b_copy", None),
                pick("locked", Some("wrong")),
                pick("../outside", None),
                pick("missing", None),
            ],
            1,
        )
        .unwrap();
        assert_eq!(done.ids.len(), 1);
        let reasons: Vec<_> = done
            .failed
            .iter()
            .map(|f| (f.file.as_str(), f.reason.as_str()))
            .collect();
        assert_eq!(
            reasons,
            [
                ("b_copy", "in_vault"),
                ("locked", "passphrase"),
                ("../outside", "not_a_key_file"),
                ("missing", "not_a_key_file"),
            ]
        );

        let again = import(dir.path(), &mut vault, &[pick("locked", Some("right"))], 2).unwrap();
        assert_eq!(again.ids.len(), 1);
        let keys: Vec<_> = vault
            .active_items()
            .unwrap()
            .filter_map(|item| match &item.data {
                VaultItem::SshKey {
                    title, private_key, ..
                } => Some((title.clone(), private_key.len())),
                _ => None,
            })
            .collect();
        assert_eq!(keys.len(), 2);
        assert!(keys
            .iter()
            .any(|(title, len)| title == "locked@laptop" && *len == 32));
    }
}
