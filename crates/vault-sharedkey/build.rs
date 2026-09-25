fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos" {
        cc::Build::new()
            .file("src/sharedkey.m")
            .file("src/protected.m")
            .flag("-fobjc-arc")
            // The workspace inherits a 10.13 floor that predates everything
            // here. kSecUseDataProtectionKeychain (10.15) and
            // kSecAccessControlBiometryCurrentSet (10.13.4) both sit above it,
            // and a warning about a symbol this file cannot work without is
            // noise that trains people to ignore warnings. Arca's real floor is
            // far higher anyway: the AutoFill credential provider this serves
            // is macOS 11+, and its passkeys are 14+.
            .flag("-mmacosx-version-min=10.15")
            .compile("arca_sharedkey");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rerun-if-changed=src/sharedkey.m");
        println!("cargo:rerun-if-changed=src/protected.m");
    }
}
