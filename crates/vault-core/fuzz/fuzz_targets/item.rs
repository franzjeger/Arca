#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the CBOR deserialization logic of VaultItem.
    // Exercise malformed inputs and retain any panic as a regression corpus.
    let _: Result<vault_core::VaultItem, _> = ciborium::from_reader(data);
});
