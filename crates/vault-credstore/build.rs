fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos" {
        cc::Build::new()
            .file("src/credstore.m")
            .flag("-fobjc-arc")
            // The workspace's inherited 10.13 floor predates every symbol in
            // this file: ASPasskeyCredentialIdentity and
            // replaceCredentialIdentityEntries: are macOS 14. Ten warnings
            // about symbols the file cannot work without are noise that trains
            // people to skim past warnings, and the passkey identities this
            // publishes need 14 regardless.
            .flag("-mmacosx-version-min=14.0")
            .compile("arca_credstore");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=AuthenticationServices");
        println!("cargo:rerun-if-changed=src/credstore.m");
    }
}
