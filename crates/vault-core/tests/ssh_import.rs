//! Keys people already have in ~/.ssh: what `ssh-keygen` writes imports as the
//! key it holds, in the shape Arca's own keys have, and nothing else does.
//!
//! No key file is checked in. The tests make their own, with the ssh-key crate
//! and, where it is installed, with the real `ssh-keygen`.

use std::process::Command;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};
use vault_core::ssh::{self, KeyFileError};

fn openssh(key: &PrivateKey) -> String {
    key.to_openssh(LineEnding::LF).unwrap().to_string()
}

fn fingerprint(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

#[test]
fn an_ed25519_key_file_imports_as_the_key_it_holds() {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    key.set_comment("frank@laptop");
    let text = openssh(&key);

    let file = ssh::read_key_file(&text).unwrap();
    assert!(file.supported() && !file.encrypted);
    assert_eq!(file.comment, "frank@laptop");
    assert_eq!(file.fingerprint, fingerprint(&key));

    let imported = ssh::import_key_file(&text, None).unwrap();
    assert_eq!(imported.fingerprint, file.fingerprint);
    assert_eq!(imported.comment, "frank@laptop");
    // It signs like a generated key, for the public half the file named.
    let blob = ssh::sign(&imported.private_key, b"challenge").unwrap();
    let signature = Signature::from_slice(&blob[blob.len() - 64..]).unwrap();
    let public = key.public_key().key_data().ed25519().unwrap().0;
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify(b"challenge", &signature)
        .unwrap();
}

#[test]
fn an_encrypted_key_is_known_before_its_passphrase_and_imported_with_it() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let text = openssh(&key.encrypt(&mut OsRng, "correct horse").unwrap());

    // The public half reads without the passphrase: enough to tell whether
    // the vault holds the key already.
    let file = ssh::read_key_file(&text).unwrap();
    assert!(file.encrypted);
    assert_eq!(file.fingerprint, fingerprint(&key));

    assert_eq!(
        ssh::import_key_file(&text, None).err(),
        Some(KeyFileError::Passphrase)
    );
    assert_eq!(
        ssh::import_key_file(&text, Some("wrong")).err(),
        Some(KeyFileError::Passphrase)
    );
    let imported = ssh::import_key_file(&text, Some("correct horse")).unwrap();
    assert_eq!(imported.fingerprint, file.fingerprint);
}

#[test]
fn other_key_types_and_other_files_are_named_not_imported() {
    let ecdsa = PrivateKey::random(
        &mut OsRng,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let text = openssh(&ecdsa);
    let file = ssh::read_key_file(&text).unwrap();
    assert!(!file.supported());
    assert_eq!(file.key_type, "ecdsa-sha2-nistp256");
    assert_eq!(
        ssh::import_key_file(&text, None).err(),
        Some(KeyFileError::Unsupported("ecdsa-sha2-nistp256".into()))
    );

    let public_line = ssh::authorized_key_from_blob(&[0; 51], "").unwrap();
    for junk in [
        "",
        public_line.as_str(),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END OPENSSH PRIVATE KEY-----\n",
    ] {
        assert_eq!(
            ssh::read_key_file(junk).err(),
            Some(KeyFileError::Unreadable)
        );
        assert_eq!(
            ssh::import_key_file(junk, None).err(),
            Some(KeyFileError::Unreadable)
        );
    }
}

/// What the real `ssh-keygen` writes, where it is installed: the fingerprint
/// is the one it shows, with a passphrase and without.
#[test]
fn keys_from_ssh_keygen_import_with_its_own_fingerprint() {
    let dir = std::env::temp_dir().join(format!("arca-ssh-import-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, passphrase) in [("plain", ""), ("locked", "correct horse")] {
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        let made = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", name, "-f"])
            .arg(&path)
            .status();
        let Ok(made) = made else {
            eprintln!("ssh-keygen is not installed here; skipped");
            return;
        };
        assert!(made.success());
        let listed = Command::new("ssh-keygen")
            .arg("-lf")
            .arg(dir.join(format!("{name}.pub")))
            .output()
            .unwrap();
        let listed = String::from_utf8(listed.stdout).unwrap();
        let expected = listed.split_whitespace().nth(1).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(ssh::read_key_file(&text).unwrap().fingerprint, expected);
        let passphrase = (!passphrase.is_empty()).then_some(passphrase);
        let imported = ssh::import_key_file(&text, passphrase).unwrap();
        assert_eq!(imported.fingerprint, expected);
        assert_eq!(imported.comment, name);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
