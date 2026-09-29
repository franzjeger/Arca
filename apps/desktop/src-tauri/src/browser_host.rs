//! The browser host Arca carries, registered with the browsers at each launch.
//!
//! The extension reaches Arca through a native messaging host: a small program
//! a browser starts from the path its registration file names. That host used
//! to be installed and registered by a script, outside the app, where no update
//! of the app could reach it. The two halves of the bridge then drift apart,
//! and a message a newer app understands meets an older host that calls it
//! malformed. The host now lives in the bundle beside Arca's own executable,
//! and Arca points the registrations at it, so installing or updating the app
//! replaces both halves at once.
//!
//! Only the app in /Applications registers. The host starts Arca from there
//! (extension/native-host/src/launch.rs), and a copy run from a disk image,
//! Downloads or a build directory must not point browsers at a path that is
//! about to disappear.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;

const HOST_NAME: &str = "no.sybr.vault";
const HOST_BINARY: &str = "vault-native-host";
const INSTALLED_APP: &str = "/Applications/Arca.app";

/// The Chromium extension's ID, which the `key` in its manifest fixes.
const CHROMIUM_EXTENSION: &str = "joeolbejbmnhmgajgmidpnpnjahdiobc";
/// The Firefox extension's ID.
const FIREFOX_EXTENSION: &str = "sybr-passwords@sybr.no";

/// Chromium browsers, by their folder in ~/Library/Application Support. The
/// install scripts journal the same list (scripts/install-macos-support.py)
/// and check it (scripts/verify-installed-bridge.py).
const CHROMIUM_BROWSERS: [&str; 4] = [
    "Google/Chrome",
    "BraveSoftware/Brave-Browser",
    "Microsoft Edge",
    "Chromium",
];

/// A native messaging registration, fields in the order of the templates in
/// extension/native-host.
#[derive(Serialize)]
struct Registration<'a> {
    name: &'a str,
    description: &'a str,
    path: &'a Path,
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_origins: Option<[String; 1]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_extensions: Option<[&'a str; 1]>,
}

/// Points every installed browser at the host inside this app. Best effort: a
/// browser that cannot be registered has no bridge until the next launch.
pub(crate) fn register(home: &Path) {
    let Some(host) = std::env::current_exe()
        .ok()
        .and_then(|exe| host_beside(&exe))
    else {
        return;
    };
    // An app built without its host keeps whatever the browsers point at.
    if !host.is_file() {
        return;
    }
    for (path, contents) in registrations(home, &host) {
        match write_if_changed(&path, &contents) {
            Ok(true) => eprintln!("[arca] registered the browser host in {}", path.display()),
            Ok(false) => {}
            Err(e) => eprintln!(
                "[arca] could not register the browser host in {}: {e}",
                path.display()
            ),
        }
    }
}

/// Where the host is when `exe` is the installed app's executable.
fn host_beside(exe: &Path) -> Option<PathBuf> {
    let bundle = exe.parent()?.parent()?.parent()?;
    (bundle == Path::new(INSTALLED_APP)).then(|| exe.with_file_name(HOST_BINARY))
}

/// Each installed browser's registration file and what it should say.
fn registrations(home: &Path, host: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let support = home.join("Library/Application Support");
    let file = format!("{HOST_NAME}.json");
    let registration = |allowed_origins, allowed_extensions| {
        let mut json = serde_json::to_vec_pretty(&Registration {
            name: HOST_NAME,
            description: "Arca native messaging host",
            path: host,
            kind: "stdio",
            allowed_origins,
            allowed_extensions,
        })
        .expect("a registration is plain JSON");
        json.push(b'\n');
        json
    };
    let chromium = registration(
        Some([format!("chrome-extension://{CHROMIUM_EXTENSION}/")]),
        None,
    );
    let mut files: Vec<_> = CHROMIUM_BROWSERS
        .iter()
        .map(|browser| support.join(browser))
        .filter(|browser| browser.is_dir())
        .map(|browser| {
            (
                browser.join("NativeMessagingHosts").join(&file),
                chromium.clone(),
            )
        })
        .collect();
    let firefox = support.join("Mozilla");
    if firefox.is_dir() {
        files.push((
            firefox.join("NativeMessagingHosts").join(&file),
            registration(None, Some([FIREFOX_EXTENSION])),
        ));
    }
    files
}

/// Replaces `path` atomically, and only when it says something else, since
/// browsers read it every time they start a host. Whether it wrote.
fn write_if_changed(path: &Path, contents: &[u8]) -> io::Result<bool> {
    if fs::read(path).is_ok_and(|current| current == contents) {
        return Ok(false);
    }
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("a registration is always in a folder"))?;
    fs::create_dir_all(dir)?;
    let temporary = dir.join(format!(".{HOST_NAME}.json.{}", std::process::id()));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.map(|()| true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::os::unix::fs::PermissionsExt;

    const HOST: &str = "/Applications/Arca.app/Contents/MacOS/vault-native-host";

    #[test]
    fn only_the_installed_app_registers() {
        assert_eq!(
            host_beside(Path::new(
                "/Applications/Arca.app/Contents/MacOS/vault-desktop"
            )),
            Some(PathBuf::from(HOST))
        );
        for exe in [
            "/Volumes/Arca/Arca.app/Contents/MacOS/vault-desktop",
            "/Users/someone/Downloads/Arca.app/Contents/MacOS/vault-desktop",
            "/private/var/folders/x/T/AppTranslocation/1/d/Arca.app/Contents/MacOS/vault-desktop",
            "/Applications/Arca copy.app/Contents/MacOS/vault-desktop",
            "/Users/someone/target/release/vault-desktop",
            "/vault-desktop",
        ] {
            assert_eq!(host_beside(Path::new(exe)), None, "{exe}");
        }
    }

    #[test]
    fn each_installed_browser_is_registered_and_no_other() {
        let home = tempfile::tempdir().unwrap();
        let support = home.path().join("Library/Application Support");
        fs::create_dir_all(support.join("Google/Chrome")).unwrap();
        fs::create_dir_all(support.join("Mozilla")).unwrap();

        let files = registrations(home.path(), Path::new(HOST));
        let paths: Vec<_> = files
            .iter()
            .map(|(path, _)| path.strip_prefix(&support).unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                Path::new("Google/Chrome/NativeMessagingHosts/no.sybr.vault.json"),
                Path::new("Mozilla/NativeMessagingHosts/no.sybr.vault.json"),
            ]
        );

        let chrome: Value = serde_json::from_slice(&files[0].1).unwrap();
        assert_eq!(chrome["path"], HOST);
        assert_eq!(
            chrome["allowed_origins"],
            json!(["chrome-extension://joeolbejbmnhmgajgmidpnpnjahdiobc/"])
        );
        assert!(chrome.get("allowed_extensions").is_none());

        let firefox: Value = serde_json::from_slice(&files[1].1).unwrap();
        assert_eq!(firefox["path"], HOST);
        assert_eq!(
            firefox["allowed_extensions"],
            json!(["sybr-passwords@sybr.no"])
        );
        assert!(firefox.get("allowed_origins").is_none());
    }

    #[test]
    fn registrations_say_what_the_templates_say() {
        let chromium: Value = serde_json::from_str(include_str!(
            "../../../../extension/native-host/no.sybr.vault.json"
        ))
        .unwrap();
        let firefox: Value = serde_json::from_str(include_str!(
            "../../../../extension/native-host/no.sybr.vault.firefox.json"
        ))
        .unwrap();
        let home = tempfile::tempdir().unwrap();
        let support = home.path().join("Library/Application Support");
        fs::create_dir_all(support.join("Chromium")).unwrap();
        fs::create_dir_all(support.join("Mozilla")).unwrap();

        let files = registrations(home.path(), Path::new(HOST));
        assert_eq!(files.len(), 2);
        let ours: Vec<Value> = files
            .iter()
            .map(|(_, json)| serde_json::from_slice(json).unwrap())
            .collect();
        for (ours, template) in ours.iter().zip([&chromium, &firefox]) {
            for field in ["name", "description", "type"] {
                assert_eq!(ours[field], template[field], "{field}");
            }
        }
        assert_eq!(ours[1]["allowed_extensions"], firefox["allowed_extensions"]);
    }

    #[test]
    fn the_chromium_id_is_the_one_the_manifest_key_fixes() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let manifest: Value =
            serde_json::from_str(include_str!("../../../../extension/chromium/manifest.json"))
                .unwrap();
        let key = base64::engine::general_purpose::STANDARD
            .decode(manifest["key"].as_str().unwrap())
            .unwrap();
        // Chrome's rule: the first 128 bits of the key's SHA-256, one letter
        // a–p per hex digit.
        let id: String = Sha256::digest(&key)
            .iter()
            .take(16)
            .flat_map(|byte| [byte >> 4, byte & 0xf])
            .map(|digit| char::from(b'a' + digit))
            .collect();
        assert_eq!(id, CHROMIUM_EXTENSION);
    }

    #[test]
    fn a_stale_registration_is_replaced_and_a_current_one_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("NativeMessagingHosts/no.sybr.vault.json");

        assert!(write_if_changed(&path, b"current").unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!write_if_changed(&path, b"current").unwrap());

        fs::write(
            &path,
            br#"{"path":"/Users/someone/.local/lib/arca/vault-native-host"}"#,
        )
        .unwrap();
        assert!(write_if_changed(&path, b"current").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"current");
        // Nothing left over beside it.
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }
}
