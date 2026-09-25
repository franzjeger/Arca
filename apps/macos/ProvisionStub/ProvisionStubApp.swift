// Minimal app whose only purpose is to make Xcode provision the no.sybr.vault
// App ID with App Groups + Keychain Sharing, so its provisioning profile can be
// embedded into the (Tauri-built) Arca.app. Not shipped.
import SwiftUI

@main
struct ProvisionStubApp: App {
    var body: some Scene { WindowGroup { Text("Arca provisioning stub") } }
}
