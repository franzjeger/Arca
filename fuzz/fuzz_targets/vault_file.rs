//! A vault file, and a peer's copy merged into an open vault. Both are read
//! before anything in them is authenticated, from a disk or a cloud account
//! someone else may write to.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use vault_core::{KdfAlgorithm, KdfParams, Vault};

fn open_vault() -> &'static Vault {
    static VAULT: OnceLock<Vault> = OnceLock::new();
    VAULT.get_or_init(|| {
        let cheap = KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7; KdfParams::SALT_LEN],
        };
        Vault::create("fuzz", cheap).expect("a vault with fixed parameters")
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = Vault::from_bytes(data) {
        let _ = parsed.to_bytes();
    }
    let _ = open_vault().clone().merge_remote(data);
});
