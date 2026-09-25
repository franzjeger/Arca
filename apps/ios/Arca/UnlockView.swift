// Unlock: Face ID if a device key has been minted on this device, the master
// password otherwise.
//
// The biometric path is attempted once automatically. A password manager that
// makes you tap before it will even ask is one you stop using, and the password
// field stays right there for when it is declined or unavailable.
//
// The password path runs Argon2id with the vault header's parameters, which is
// deliberately expensive — hence progress rather than a button pretending to be
// instant. Quick unlock exists precisely to avoid paying that on every fill.

import SwiftUI

struct UnlockView: View {
    @Environment(VaultStore.self) private var store

    @Environment(\.scenePhase) private var scenePhase

    @State private var password = ""
    @State private var didTryBiometrics = false
    @FocusState private var focused: Bool

    /// Ask for Face ID once per stretch of being the app in front.
    ///
    /// Not once per appearance: locking the PHONE backgrounds Arca, which locks
    /// the vault and puts this view on screen while the device itself is still
    /// locked — where a biometric prompt cannot possibly succeed. Firing there
    /// spent the one attempt on nothing, so coming back to an unlocked phone
    /// offered a button instead of a face. The attempt now belongs to becoming
    /// active, and leaving active re-arms it.
    private func attemptBiometrics() async {
        guard scenePhase == .active, !didTryBiometrics else { return }
        guard await store.resolveQuickUnlockAvailability() else { return }
        didTryBiometrics = true
        await store.unlockWithDeviceKey()
    }

    private var isUnlocking: Bool { store.phase == .unlocking }

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("Arca")
                .font(.largeTitle.bold())

            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.go)
                .focused($focused)
                .onSubmit(submit)
                .disabled(isUnlocking)

            if let failure = store.failure {
                Text(failure)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Button(action: submit) {
                if isUnlocking {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text("Unlock").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || isUnlocking)

            if store.quickUnlockAvailable {
                Button("Use Face ID", systemImage: "faceid") {
                    Task { await store.unlockWithDeviceKey() }
                }
                .disabled(isUnlocking)
            } else {
                Text("Deriving the key takes a moment — that is Argon2id doing its job.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            ImportVaultButton(title: "Import a different vault")
                .font(.caption)

            Spacer()
        }
        .padding(28)
        .task {
            // Covers arriving here while already in front — locking from inside
            // the app, or a fresh launch. `scenePhase` does not change in that
            // case, so `onChange` alone would never fire.
            await attemptBiometrics()
            focused = store.phase != .unlocked
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                Task { await attemptBiometrics() }
            } else {
                // Going away re-arms it. A declined or failed attempt still does
                // not loop, because nothing re-triggers until the app comes back.
                didTryBiometrics = false
            }
        }
    }

    private func submit() {
        guard !password.isEmpty, !isUnlocking else { return }
        Task {
            await store.unlock(password: password)
            // Cleared either way. A wrong password is worth retyping; leaving it
            // in a live @State String is not worth the convenience.
            password = ""
        }
    }
}
