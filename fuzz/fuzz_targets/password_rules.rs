//! A `passwordrules` string, written by hand on some website. Whatever it
//! says, the generator has to produce a password rather than fail.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::password::options_from_rules;

fuzz_target!(|data: &[u8]| {
    let Ok(rules) = std::str::from_utf8(data) else {
        return;
    };
    let options = options_from_rules(rules, 20);
    let password = vault_core::generate_password(&options)
        .unwrap_or_else(|e| panic!("{rules:?} gave {options:?}, which fails: {e}"));
    assert_eq!(password.chars().count(), options.length);
});
