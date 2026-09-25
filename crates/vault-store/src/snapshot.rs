//! Rotating local snapshots of the encrypted vault file.
//!
//! The vault is a single file that every save rewrites. Sync makes that worse,
//! not better: a bad merge, an accidental bulk delete or a dedupe that ate too
//! much propagates to every device, and there is nothing to roll back to. So we
//! keep a short history of the file *as it was before each save*.
//!
//! Snapshots are byte-for-byte copies of the encrypted container — the same
//! ciphertext, the same master password, no extra key material and nothing in
//! plaintext. A snapshot is therefore exactly as safe (and as useless to a
//! thief) as the vault itself.
//!
//! Retention is tiered so the history stays useful without growing forever:
//! the most recent [`KEEP_RECENT`] snapshots (undo the last few edits) plus the
//! newest snapshot of each of the last [`KEEP_DAILY`] days (undo something you
//! only noticed a week later).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Always keep this many of the newest snapshots, whatever their age.
pub const KEEP_RECENT: usize = 5;
/// Additionally keep the newest snapshot from each of this many recent days.
pub const KEEP_DAILY: usize = 7;

const SNAPSHOT_EXT: &str = "snap";
const SECS_PER_DAY: i64 = 86_400;

/// One stored snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub path: PathBuf,
    /// Unix seconds the snapshot was taken (encoded in the filename).
    pub created_unix: i64,
    pub bytes: u64,
}

/// Where snapshots for `vault_path` live: a sibling `snapshots/` directory, so
/// they sit on the same filesystem and inherit the same directory protection.
pub fn snapshot_dir(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("snapshots")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Copy the current vault file into the snapshot directory, then prune.
///
/// Call this *before* overwriting the vault, so the snapshot captures the
/// pre-change state. A missing vault file (first run) is not an error and does
/// nothing. Snapshot failures must never block a save, so callers treat the
/// result as advisory.
pub fn capture(vault_path: &Path) -> Result<Option<SnapshotInfo>> {
    capture_at(vault_path, now_unix())
}

/// [`capture`] with an injected timestamp (tests).
pub fn capture_at(vault_path: &Path, now: i64) -> Result<Option<SnapshotInfo>> {
    if !vault_path.is_file() {
        return Ok(None);
    }
    let dir = snapshot_dir(vault_path);
    fs::create_dir_all(&dir)?;

    let stem = vault_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vault");
    // Second granularity can collide when several saves land in the same
    // second; step forward to the first free slot so no snapshot is lost.
    let mut ts = now;
    let mut dest = dir.join(format!("{stem}.{ts}.{SNAPSHOT_EXT}"));
    while dest.exists() {
        ts += 1;
        dest = dir.join(format!("{stem}.{ts}.{SNAPSHOT_EXT}"));
    }

    // Copy via the same atomic write the vault itself uses, so a crash mid-copy
    // cannot leave a torn snapshot that later looks restorable.
    let bytes = crate::read_vault_file(vault_path)?;
    crate::write_atomic(&dest, &bytes)?;

    prune(vault_path, now)?;
    Ok(Some(SnapshotInfo {
        path: dest,
        created_unix: ts,
        bytes: bytes.len() as u64,
    }))
}

/// All snapshots for `vault_path`, newest first.
pub fn list(vault_path: &Path) -> Vec<SnapshotInfo> {
    let dir = snapshot_dir(vault_path);
    let stem = vault_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vault");
    let prefix = format!("{stem}.");

    let mut out: Vec<SnapshotInfo> = match fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_string();
                // <stem>.<unix>.snap
                let rest = name.strip_prefix(&prefix)?;
                let ts: i64 = rest
                    .strip_suffix(&format!(".{SNAPSHOT_EXT}"))?
                    .parse()
                    .ok()?;
                Some(SnapshotInfo {
                    path: e.path(),
                    created_unix: ts,
                    bytes: e.metadata().map(|m| m.len()).unwrap_or(0),
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort_by_key(|s| std::cmp::Reverse(s.created_unix));
    out
}

/// Delete snapshots outside the retention policy: keep the newest
/// [`KEEP_RECENT`], plus the newest of each of the last [`KEEP_DAILY`] days.
fn prune(vault_path: &Path, now: i64) -> Result<()> {
    let all = list(vault_path);
    let cutoff = now - (KEEP_DAILY as i64 * SECS_PER_DAY);

    let mut keep: Vec<&SnapshotInfo> = all.iter().take(KEEP_RECENT).collect();
    let mut seen_days: Vec<i64> = Vec::new();
    for s in &all {
        if s.created_unix < cutoff {
            continue;
        }
        let day = s.created_unix.div_euclid(SECS_PER_DAY);
        // `all` is newest-first, so the first hit for a day IS that day's newest.
        if !seen_days.contains(&day) {
            seen_days.push(day);
            if !keep.iter().any(|k| k.path == s.path) {
                keep.push(s);
            }
        }
    }

    for s in &all {
        if !keep.iter().any(|k| k.path == s.path) {
            let _ = fs::remove_file(&s.path);
        }
    }
    Ok(())
}

/// Replace the vault file with `snapshot`, after snapshotting the *current*
/// file first — so restoring is itself undoable and can never be the operation
/// that loses data.
pub fn restore(vault_path: &Path, snapshot: &Path) -> Result<()> {
    // Only ever restore from our own snapshot directory: this path arrives from
    // the UI, and a vault file is about to be overwritten with its contents.
    let dir = snapshot_dir(vault_path);
    let canonical_dir = dir.canonicalize().map_err(|_| Error::SnapshotNotFound)?;
    let canonical_snap = snapshot
        .canonicalize()
        .map_err(|_| Error::SnapshotNotFound)?;
    if canonical_snap.parent() != Some(canonical_dir.as_path()) {
        return Err(Error::SnapshotNotFound);
    }

    let bytes = crate::read_vault_file(&canonical_snap)?;
    // Sanity-check that it really is a vault container before clobbering the
    // live file; a truncated or foreign file must not replace a good vault.
    vault_core::Vault::from_bytes(&bytes)?;

    let _ = capture(vault_path);
    crate::write_atomic(vault_path, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_vault(path: &Path, marker: u8) {
        // A real (tiny) vault container, so `restore`'s validity check passes.
        let params = vault_core::KdfParams {
            algorithm: vault_core::KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![marker; vault_core::KdfParams::SALT_LEN],
        };
        let v = vault_core::Vault::create("pw", params).unwrap();
        fs::write(path, v.to_bytes().unwrap()).unwrap();
    }

    #[test]
    fn capture_is_a_noop_without_a_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        assert_eq!(capture(&vault).unwrap(), None);
        assert!(list(&vault).is_empty());
    }

    #[test]
    fn capture_then_restore_round_trips_the_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        write_vault(&vault, 1);
        let original = fs::read(&vault).unwrap();

        let snap = capture(&vault).unwrap().unwrap();
        assert_eq!(snap.bytes as usize, original.len());

        // The vault is then overwritten (a bad merge, a bulk delete…).
        write_vault(&vault, 2);
        assert_ne!(fs::read(&vault).unwrap(), original);

        restore(&vault, &snap.path).unwrap();
        assert_eq!(fs::read(&vault).unwrap(), original);
    }

    #[test]
    fn restore_snapshots_the_current_state_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        write_vault(&vault, 1);
        let snap = capture_at(&vault, 1_000).unwrap().unwrap();

        write_vault(&vault, 2);
        let before_restore = fs::read(&vault).unwrap();
        restore(&vault, &snap.path).unwrap();

        // The state we restored away from is still recoverable.
        let saved: Vec<Vec<u8>> = list(&vault)
            .iter()
            .map(|s| fs::read(&s.path).unwrap())
            .collect();
        assert!(saved.contains(&before_restore));
    }

    #[test]
    fn restore_refuses_a_path_outside_the_snapshot_dir() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        write_vault(&vault, 1);
        let good = fs::read(&vault).unwrap();

        let outsider = dir.path().join("elsewhere.vault");
        write_vault(&outsider, 9);

        assert!(restore(&vault, &outsider).is_err());
        assert_eq!(fs::read(&vault).unwrap(), good); // untouched
    }

    #[test]
    fn restore_refuses_a_corrupt_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        write_vault(&vault, 1);
        let good = fs::read(&vault).unwrap();
        capture(&vault).unwrap();

        let junk = snapshot_dir(&vault).join("v.vault.999999.snap");
        fs::write(&junk, b"not a vault").unwrap();

        assert!(restore(&vault, &junk).is_err());
        assert_eq!(fs::read(&vault).unwrap(), good); // untouched
    }

    #[test]
    fn same_second_captures_do_not_overwrite_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        write_vault(&vault, 1);

        capture_at(&vault, 5_000).unwrap();
        capture_at(&vault, 5_000).unwrap();
        assert_eq!(list(&vault).len(), 2);
    }

    #[test]
    fn retention_keeps_recent_plus_one_per_day() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.vault");
        write_vault(&vault, 1);

        // Day 100: 10 rapid saves. Only KEEP_RECENT survive from a single day…
        let day100 = 100 * SECS_PER_DAY;
        for i in 0..10 {
            capture_at(&vault, day100 + i).unwrap();
        }
        assert_eq!(list(&vault).len(), KEEP_RECENT);

        // …then one save a day for the next 10 days. The recent 5 plus one per
        // day for the last 7 days are kept, and nothing older lingers.
        for d in 1..=10 {
            capture_at(&vault, (100 + d) * SECS_PER_DAY).unwrap();
        }
        let kept = list(&vault);
        assert!(
            kept.len() <= KEEP_DAILY + KEEP_RECENT,
            "kept {}",
            kept.len()
        );
        // Everything from the original burst is now well outside the window.
        assert!(kept.iter().all(|s| s.created_unix > day100 + 9));
        // One entry per distinct day in the retained window.
        let mut days: Vec<i64> = kept
            .iter()
            .map(|s| s.created_unix.div_euclid(SECS_PER_DAY))
            .collect();
        days.dedup();
        assert_eq!(days.len(), kept.len(), "expected one snapshot per day");
    }
}
