//! The devices that push a vault, so that a current copy can be told from an
//! older one.
//!
//! Storage the user does not control, a cloud account above all, can show any
//! copy it has ever held. It cannot forge one: every copy is sealed. So each
//! copy carries, sealed in its header, how many copies each device had pushed
//! when it was made. Copies only ever merge upwards, so the copies in storage
//! together always account for every upload a device has already seen, unless
//! somebody took the newer ones away.
//!
//! Except around a password change: copies sealed with the old key are left
//! out on purpose (`StaleKey`), uploads included. So each entry also says which
//! key its latest upload was sealed with, and only uploads made with the
//! current key are ever judged.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A device that pushes this vault, as its sealed header records it. Only the
/// holders of the vault key read this: the storage provider never learns what
/// the devices are called or how often they sync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Chosen at random by the device the first time it pushes, and kept by
    /// that installation.
    pub id: Uuid,
    /// What the user calls it ("MacBook Pro", "iPhone").
    pub name: String,
    /// How many copies it has pushed. Only ever goes up.
    pub uploads: u64,
    /// When it last pushed one, by its own clock (Unix ms). For people to
    /// read, never compared.
    pub last_upload: i64,
    /// The key epoch (`VaultHeader::key_epoch`) that upload was sealed under.
    #[serde(default)]
    pub key_epoch: u64,
}

/// `known` with `seen` merged in: per device, the entry that knows of more
/// uploads. Order is kept, new devices go at the end.
pub(crate) fn merge(known: &mut Vec<Device>, seen: impl IntoIterator<Item = Device>) {
    for device in seen {
        match known.iter_mut().find(|d| d.id == device.id) {
            Some(mine) if device.uploads > mine.uploads => *mine = device,
            Some(_) => {}
            None => known.push(device),
        }
    }
}

/// The devices in `known`, other than `except`, whose latest upload was sealed
/// under `key_epoch` and whose uploads `seen` accounts for fewer of than `known`
/// does. A device `seen` lacks entirely counts as none.
pub(crate) fn behind(
    known: &[Device],
    seen: &[Device],
    except: Uuid,
    key_epoch: u64,
) -> Vec<Device> {
    let mut accounted: HashMap<Uuid, u64> = HashMap::new();
    for device in seen {
        let count = accounted.entry(device.id).or_default();
        *count = (*count).max(device.uploads);
    }
    known
        .iter()
        .filter(|d| d.id != except && d.key_epoch == key_epoch)
        .filter(|d| d.uploads > accounted.get(&d.id).copied().unwrap_or(0))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: u8, uploads: u64) -> Device {
        Device {
            id: Uuid::from_bytes([id; 16]),
            name: format!("device {id}"),
            uploads,
            last_upload: i64::from(id),
            key_epoch: 0,
        }
    }

    #[test]
    fn merging_keeps_the_entry_that_knows_of_more_uploads() {
        let mut known = vec![device(1, 5), device(2, 3)];
        merge(&mut known, [device(1, 4), device(2, 7), device(3, 1)]);
        let counts: Vec<_> = known
            .iter()
            .map(|d| (d.id.as_bytes()[0], d.uploads))
            .collect();
        assert_eq!(counts, [(1, 5), (2, 7), (3, 1)]);
    }

    #[test]
    fn behind_is_whatever_no_copy_accounts_for() {
        let me = Uuid::from_bytes([9; 16]);
        let known = [device(1, 5), device(2, 3), device(9, 40)];
        // Several copies together: the newest account of each device counts.
        let seen = [device(1, 2), device(1, 5), device(2, 1)];
        let late: Vec<_> = behind(&known, &seen, me, 0).iter().map(|d| d.id).collect();
        assert_eq!(late, [Uuid::from_bytes([2; 16])]);
        // A device no copy knows of at all is behind, and the asking device
        // never is: its own count runs ahead whenever an upload fails.
        assert_eq!(behind(&known, &[], me, 0).len(), 2);
        assert!(behind(&known, &[device(1, 5), device(2, 3)], me, 0).is_empty());
    }

    #[test]
    fn only_uploads_made_with_the_current_key_are_judged() {
        let me = Uuid::from_bytes([9; 16]);
        let since = Device {
            key_epoch: 1,
            ..device(2, 3)
        };
        let late = behind(&[device(1, 5), since.clone()], &[], me, 1);
        assert_eq!(late, [since]);
    }
}
