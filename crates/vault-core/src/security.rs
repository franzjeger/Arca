//! Password-health auditing: a lightweight, dependency-free strength estimate
//! plus a weak/reused audit over the vault's login items.
//!
//! The strength estimate is a coarse entropy heuristic (length × log2 of the
//! character-class pool). It deliberately does NOT model dictionary words or
//! repetition, so `"aaaaaaaaaaaa"` scores higher than it should — a real
//! product would use something like zxcvbn. It is good enough to flag the
//! obvious problems (short passwords, single character class) for the Security
//! view, and it never sees or stores anything beyond the password it is given.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::item::{Item, VaultItem};

/// Coarse password-strength bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasswordStrength {
    Weak,
    Fair,
    Strong,
}

/// A flagged item and what is wrong with it. Only items with at least one issue
/// are reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityIssue {
    /// Low estimated entropy (short and/or few character classes).
    WeakPassword,
    /// The same password is used by more than one item in the vault.
    ReusedPassword,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSecurity {
    pub id: Uuid,
    pub issues: Vec<SecurityIssue>,
}

/// Estimate password strength from a rough entropy figure: the number of
/// characters times log2 of the size of the character-class pool used.
pub fn estimate_strength(password: &str) -> PasswordStrength {
    let len = password.chars().count();
    if len == 0 {
        return PasswordStrength::Weak;
    }

    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 32; // approximate size of the symbol/space space
    }

    let bits = (len as f64) * (pool.max(1) as f64).log2();
    if bits < 50.0 {
        PasswordStrength::Weak
    } else if bits < 75.0 {
        PasswordStrength::Fair
    } else {
        PasswordStrength::Strong
    }
}

/// Audit the active (non-deleted) login items for weak and reused passwords.
/// Returns one entry per flagged item; items with no issues are omitted.
pub fn audit(items: &[Item]) -> Vec<ItemSecurity> {
    use std::collections::HashMap;

    // Count password occurrences across active logins to detect reuse.
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for item in items {
        if item.is_deleted() {
            continue;
        }
        if let VaultItem::Login { password, .. } = &item.data {
            if !password.is_empty() {
                *counts.entry(password.as_str()).or_default() += 1;
            }
        }
    }

    let mut report = Vec::new();
    for item in items {
        if item.is_deleted() {
            continue;
        }
        let VaultItem::Login { password, .. } = &item.data else {
            continue;
        };

        let mut issues = Vec::new();
        if password.is_empty() || estimate_strength(password) == PasswordStrength::Weak {
            issues.push(SecurityIssue::WeakPassword);
        }
        if !password.is_empty() && counts.get(password.as_str()).copied().unwrap_or(0) > 1 {
            issues.push(SecurityIssue::ReusedPassword);
        }

        if !issues.is_empty() {
            report.push(ItemSecurity {
                id: item.id,
                issues,
            });
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(password: &str, deleted: bool) -> Item {
        let mut item = Item::new(
            VaultItem::Login {
                title: "x".into(),
                username: "u".into(),
                password: password.into(),
                url: String::new(),
                totp_secret: None,
                notes: String::new(),
            },
            0,
        );
        if deleted {
            item.deleted_at = Some(1);
        }
        item
    }

    #[test]
    fn strength_buckets() {
        assert_eq!(estimate_strength(""), PasswordStrength::Weak);
        assert_eq!(estimate_strength("p4ss"), PasswordStrength::Weak);
        assert_eq!(estimate_strength("password"), PasswordStrength::Weak);
        // 11 mixed-class chars lands in the middle band.
        assert_eq!(estimate_strength("Tr0ub4dor&3"), PasswordStrength::Fair);
        // Long + multi-class is strong.
        assert_eq!(
            estimate_strength("correct horse battery staple"),
            PasswordStrength::Strong
        );
        assert_eq!(
            estimate_strength("wf*QB(=0QIc0.Z^RI,A6"),
            PasswordStrength::Strong
        );
    }

    #[test]
    fn audit_flags_weak_passwords() {
        let items = vec![login("abc", false), login("wf*QB(=0QIc0.Z^RI,A6", false)];
        let report = audit(&items);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].id, items[0].id);
        assert!(report[0].issues.contains(&SecurityIssue::WeakPassword));
    }

    #[test]
    fn audit_flags_reuse_across_items() {
        // A strong password used twice: flagged Reused, not Weak.
        let strong = "Str0ng&Passphrase!2024xyz";
        let items = vec![
            login(strong, false),
            login(strong, false),
            login("Unique&Strong!2024abc", false),
        ];
        let report = audit(&items);
        assert_eq!(report.len(), 2);
        for r in &report {
            assert_eq!(r.issues, vec![SecurityIssue::ReusedPassword]);
        }
    }

    #[test]
    fn audit_ignores_deleted_items() {
        let items = vec![login("abc", true)]; // weak but deleted
        assert!(audit(&items).is_empty());
    }
}
