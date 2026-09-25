// The encrypted vault inside the shared App Group container.
//
// There is no sync client on iOS — that is the big missing piece in docs/IOS.md
// — so the file gets onto the phone by hand: the user picks it in Files and the
// app copies it in. Deliberately a copy rather than a bookmark, because the
// AutoFill extension is a separate process and can only read what lives in the
// group container.

import Foundation

enum VaultFile {

    enum ImportError: Error, LocalizedError {
        case noContainer
        case notReadable
        case empty

        var errorDescription: String? {
            switch self {
            case .noContainer:
                return "Arca can't reach its shared container. Check that the App Group entitlement is provisioned."
            case .notReadable:
                return "Couldn't read that file. Try picking it again."
            case .empty:
                return "That file is empty, so it isn't a vault."
            }
        }
    }

    /// Where the vault lives, or `nil` if the App Group isn't provisioned.
    static var url: URL? { VaultShared.vaultURL }

    static var exists: Bool {
        guard let url else { return false }
        return (try? url.checkResourceIsReachable()) == true
    }

    /// Copy a vault picked from Files into the shared container, replacing any
    /// vault already there.
    static func replace(with source: URL) throws {
        guard let destination = url else { throw ImportError.noContainer }

        // A URL from the document picker is security-scoped: access has to be
        // opened explicitly and closed again, including on the throwing paths.
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }

        guard let bytes = try? Data(contentsOf: source) else { throw ImportError.notReadable }
        // Not a real format check — only the FFI can tell a vault from noise, and
        // it will. This just turns the most common mis-pick into a clear message
        // instead of "that key doesn't open this vault".
        guard !bytes.isEmpty else { throw ImportError.empty }

        // .completeFileProtection makes the file unreadable while the device is
        // locked. It is ciphertext already; this is the second lock on the door.
        // AutoFill only ever runs on an unlocked device, so nothing is lost.
        try bytes.write(to: destination, options: [.atomic, .completeFileProtection])
    }
}
