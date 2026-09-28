//! An `otpauth://` URI, as a QR code or a paste delivers it.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(uri) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = vault_core::parse_otpauth_uri(uri) {
        let _ = vault_core::current_totp(&parsed.secret, 1_700_000_000);
    }
    let _ = vault_core::edit::normalize_totp(uri);
});
