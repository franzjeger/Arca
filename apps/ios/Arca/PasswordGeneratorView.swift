// Generate a strong password.
//
// The generator lives in Rust (vault-core), drawing from the OS CSPRNG with
// rejection sampling. This is the phone's window onto it — no randomness is
// invented in Swift, because two implementations of "random enough" is one more
// than anybody can keep honest.
//
// A new password appears the moment the sheet opens and on every change to the
// recipe. Making the user press Generate before there is anything to look at
// wastes the first tap of every single use.

import SwiftUI

struct PasswordGeneratorView: View {
    /// Handed the chosen password. The sheet dismisses itself afterwards.
    ///
    /// nil when the generator is opened on its own rather than to fill a field:
    /// then there is nowhere to put it and Copy is the only sensible action.
    var onUse: ((String) -> Void)?

    @Environment(\.dismiss) private var dismiss

    @State private var recipe = VaultShared.PasswordRecipe()
    @State private var candidate = ""
    @State private var failure: String?
    @State private var copied = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    // Monospaced so l/1 and O/0 are told apart, and selectable
                    // so it can be read out character by character if it is
                    // going somewhere Arca cannot reach.
                    Text(candidate.isEmpty ? " " : candidate)
                        .font(.title3.monospaced())
                        .textSelection(.enabled)
                        .privacySensitive()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentTransition(.identity)

                    Button("Generate again", systemImage: "arrow.clockwise") { regenerate() }
                        .disabled(!recipe.isUsable)
                }

                Section {
                    LabeledContent("Length") {
                        Text("\(recipe.length)").monospacedDigit().foregroundStyle(.secondary)
                    }
                    Slider(
                        value: Binding(
                            get: { Double(recipe.length) },
                            set: { recipe.length = Int($0.rounded()) }),
                        in: 8...64,
                        step: 1
                    )
                    .accessibilityLabel("Password length")
                    .accessibilityValue("\(recipe.length) characters")
                }

                Section("Include") {
                    Toggle("Lowercase  a-z", isOn: $recipe.lowercase)
                    Toggle("Uppercase  A-Z", isOn: $recipe.uppercase)
                    Toggle("Digits  0-9", isOn: $recipe.digits)
                    Toggle("Symbols  !@#$", isOn: $recipe.symbols)

                    // Said plainly rather than fought with. Silently switching a
                    // toggle back on would be a control disagreeing with the
                    // user without telling them why.
                    if !recipe.isUsable {
                        Label(
                            "Leave at least one of these on.",
                            systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(.orange)
                    }
                }

                Section {
                    if let onUse {
                        Button("Use this password", systemImage: "checkmark.circle") {
                            onUse(candidate)
                            dismiss()
                        }
                        .disabled(candidate.isEmpty)
                    }
                    Button("Copy", systemImage: "doc.on.doc") {
                        SecretPasteboard.copy(candidate)
                        copied = true
                    }
                    .disabled(candidate.isEmpty)

                    if copied {
                        Text("Copied. iOS clears the pasteboard in \(Int(SecretPasteboard.lifetime)) seconds.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                if let failure {
                    Section {
                        Text(failure).font(.footnote).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Generate Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .onAppear { regenerate() }
        // `PasswordRecipe` is Equatable, so this fires on a real change rather
        // than on every slider tick that lands on the same integer.
        .onChange(of: recipe) { regenerate() }
    }

    private func regenerate() {
        guard recipe.isUsable else { return }
        // The old candidate is dropped here. Swift strings cannot be wiped, so
        // the honest statement is that a generated password lives until the
        // runtime reclaims it — which is why the sheet holds one, not a history.
        copied = false
        do {
            candidate = try VaultShared.generatePassword(recipe)
            failure = nil
        } catch {
            candidate = ""
            failure = "Could not generate a password: \(error)"
        }
    }
}
