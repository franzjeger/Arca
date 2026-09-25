// Copying a password to the system pasteboard.
//
// Two options carry the whole security argument, so they are not optional:
// `localOnly` keeps the password off Universal Clipboard (otherwise it lands on
// every other device signed into the same Apple ID), and `expirationDate` has
// iOS clear it without anything of ours having to stay alive to do it.

import UIKit
import UniformTypeIdentifiers

enum SecretPasteboard {

    /// How long a copied password survives on the pasteboard. Matches the
    /// desktop app's clipboard auto-clear.
    static let lifetime: TimeInterval = 30

    static func copy(_ secret: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: secret]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(lifetime),
            ])
    }
}
