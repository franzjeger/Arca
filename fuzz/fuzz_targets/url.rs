//! A URL from a web page or an imported file, reduced to the host a login is
//! matched on. Every origin check in Arca rests on this.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(url) = std::str::from_utf8(data) else {
        return;
    };
    let host = vault_core::host_of(url);
    assert!(
        !host.contains(['/', '@']),
        "{url:?} gave host {host:?}, which still has a path or userinfo in it"
    );
    let _ = vault_core::webauthn_host_of(url);
    let _ = vault_core::origin_of(url);
});
