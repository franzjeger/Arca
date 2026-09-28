// The encrypted vault inside the shared App Group container.
//
// Sync keeps a phone up to date but cannot deliver the first copy, so the file
// gets onto the phone by hand: the user picks it in Files and the app copies it
// in. Deliberately a copy rather than a bookmark, because the AutoFill
// extension is a separate process and can only read what lives in the group
// container.

import Foundation

enum VaultFile {

    enum ImportError: Error, LocalizedError {
        case noContainer
        case notReadable
        case empty
        case notAVault

        var errorDescription: String? {
            switch self {
            case .noContainer:
                return "Arca can't reach its shared container. Check that the App Group entitlement is provisioned."
            case .notReadable:
                return "Couldn't read that file. Try picking it again."
            case .empty:
                return "That file is empty, so it isn't a vault."
            case .notAVault:
                return "That file isn't a vault this version of Arca can open."
            }
        }
    }

    /// Where the vault lives, or `nil` if the App Group isn't provisioned.
    static var url: URL? { VaultShared.vaultURL }

    static var exists: Bool {
        guard let url else { return false }
        return (try? url.checkResourceIsReachable()) == true
    }

    /// Read a vault picked from Files and check that it is one, before anything
    /// is replaced.
    static func read(from source: URL) throws -> Data {
        // A URL from the document picker is security-scoped: access has to be
        // opened explicitly and closed again, including on the throwing paths.
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }

        guard let bytes = try? Data(contentsOf: source) else { throw ImportError.notReadable }
        guard !bytes.isEmpty else { throw ImportError.empty }
        guard VaultShared.isOpenableVault(bytes) else { throw ImportError.notAVault }
        return bytes
    }

    /// Install checked vault bytes in the shared container, under the vault
    /// lock like every other writer. The file it replaces is kept beside it as
    /// `<vault>.replaced`: it may hold the only copy of something not yet
    /// synced, such as a passkey created on this phone.
    static func install(_ bytes: Data) throws {
        guard let destination = url else { throw ImportError.noContainer }
        try VaultShared.withVaultLock {
            if let current = try? Data(contentsOf: destination), !current.isEmpty {
                try current.write(
                    to: destination.appendingPathExtension("replaced"),
                    options: [.atomic, .completeFileProtection])
            }
            try VaultShared.writeVault(bytes)
        }
    }
}
