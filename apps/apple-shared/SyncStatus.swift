import Foundation

/// What a cycle (or a status query) reports back. Mirrors the engine's status
/// JSON; unknown fields are ignored so the Rust side can add some without
/// breaking an older app.
struct SyncStatus: Decodable, Sendable, Equatable {
    var connected: Bool = false
    var account: String?
    var lastSyncUnix: Int64?
    var lastError: String?
    /// True when the last cycle pulled changes in from another device.
    var merged: Bool = false

    private enum CodingKeys: String, CodingKey {
        case connected, account, merged
        case lastSyncUnix, lastError
    }
}
