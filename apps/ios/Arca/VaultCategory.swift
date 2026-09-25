// The slices of the vault the list can show.
//
// Deliberately the SAME set, in the same order, as the desktop sidebar
// (apps/desktop/src/lib/categories.ts). Two apps over one vault that disagree
// about what a category means is a way to make people distrust both — if
// "Codes" counts one thing on the Mac and another on the phone, the smaller
// number reads as missing data.
//
// Two of the desktop's are absent rather than stubbed:
//
// "Security" is the weak/reused/breached audit, which needs every password in
// memory at once. That is the one thing the phone's design avoids — the FFI
// hands out one secret at a time, and the AutoFill extension has a memory
// ceiling measured in tens of megabytes.
//
// "Deleted" needs tombstones the phone does not carry; `apply_purges` drops
// purged items before they ever reach the list.

import Foundation

enum VaultCategory: String, CaseIterable, Identifiable {
    case all
    case passkeys
    case codes
    case wifi
    case sshKeys
    case notes

    var id: String { rawValue }

    var label: String {
        switch self {
        case .all: return "All Items"
        case .passkeys: return "Passkeys"
        case .codes: return "Codes"
        case .wifi: return "Wi-Fi"
        case .sshKeys: return "SSH Keys"
        case .notes: return "Notes"
        }
    }

    /// Short enough for a title that already has a chevron next to it.
    var shortLabel: String {
        self == .all ? "All" : label
    }

    var symbol: String {
        switch self {
        case .all: return "square.grid.2x2"
        case .passkeys: return "person.badge.key.fill"
        case .codes: return "clock.badge.checkmark"
        case .wifi: return "wifi"
        case .sshKeys: return "terminal.fill"
        case .notes: return "note.text"
        }
    }

    /// Said when the category is empty, in its own words. "No items" under
    /// Passkeys leaves you wondering whether the filter is broken.
    var emptyMessage: String {
        switch self {
        case .all: return "Nothing in this vault yet."
        case .passkeys: return "No passkeys yet. Sites offer them at sign-in."
        case .codes: return "No verification codes. Add one to a login to see it here."
        case .wifi: return "No Wi-Fi networks saved."
        case .sshKeys: return "No SSH keys. They are managed from the desktop app."
        case .notes: return "No secure notes yet."
        }
    }

    func contains(_ item: VaultItemMeta) -> Bool {
        switch self {
        case .all: return true
        // By capability, not by kind: a login WITH a code belongs here, which is
        // the only reason this category is useful. Filtering on kind would make
        // it a duplicate of All.
        case .codes: return item.hasTotp
        case .passkeys: return item.kind == .passkey
        case .wifi: return item.kind == .wifi
        case .sshKeys: return item.kind == .sshKey
        case .notes: return item.kind == .secureNote
        }
    }
}
