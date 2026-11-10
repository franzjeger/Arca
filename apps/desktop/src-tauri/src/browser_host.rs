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
//! On macOS only the app in /Applications registers. The host starts Arca from
//! there (extension/native-host/src/launch.rs), and a copy run from a disk
//! image, Downloads or a build directory must not point browsers at a path
//! that is about to disappear.
//!
//! On Linux only an AppImage registers, and it cannot point the browsers at
//! the host inside itself: an AppImage runs from a mount that exists only
//! while it runs, and browsers start the host on their own. So it copies the
//! host out to ~/.local/lib/arca-appimage, beside a link back to the AppImage
//! that the host starts Arca from, and registers the copy. Every launch after
//! an in-app update copies the new host, so both halves still move together.
//! A `.deb`/`.rpm` registers system-wide when installed, and a source install
//! is registered by scripts/install-linux.sh; neither runs this.
//!
//! An AppImage takes over a registration that names another install's host.
//! The registration exists to reach a host built with the app that is running,
//! and the AppImage is the one running; leaving another install's host in
//! place is the drift this file exists to prevent. Running
//! scripts/install-linux.sh again takes the registrations back for a source
//! install. Each takeover is logged with the host it replaced.

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

/// Chromium browsers on Linux, by their folder in the config directory: the
/// list scripts/install-linux.py registers for a source install.
#[cfg(any(target_os = "linux", test))]
const LINUX_CHROMIUM_BROWSERS: [&str; 6] = [
    "google-chrome",
    "google-chrome-beta",
    "chromium",
    "BraveSoftware/Brave-Browser",
    "microsoft-edge",
    "vivaldi",
];

/// Where an AppImage puts the host the browsers start, relative to home. A
/// sibling of ~/.local/lib/arca, which scripts/install-linux.sh owns, not a
/// folder inside it.
#[cfg(any(target_os = "linux", test))]
const APPIMAGE_HOST_DIR: &str = ".local/lib/arca-appimage";

/// Beside that host, a link to the AppImage it came from: what launch.rs
/// starts when the extension asks for Arca. Only this host has one.
#[cfg(any(target_os = "linux", test))]
const APPIMAGE_LINK: &str = "Arca.AppImage";

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
        match write_if_changed(&path, &contents, 0o600) {
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
    let chromium = registration(host, false);
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
            registration(host, true),
        ));
    }
    files
}

/// What a registration for `host` says, to a Chromium browser or to Firefox.
fn registration(host: &Path, firefox: bool) -> Vec<u8> {
    let mut json = serde_json::to_vec_pretty(&Registration {
        name: HOST_NAME,
        description: "Arca native messaging host",
        path: host,
        kind: "stdio",
        allowed_origins: (!firefox).then(|| [format!("chrome-extension://{CHROMIUM_EXTENSION}/")]),
        allowed_extensions: firefox.then_some([FIREFOX_EXTENSION]),
    })
    .expect("a registration is plain JSON");
    json.push(b'\n');
    json
}

/// When Arca runs as an AppImage, points every installed browser at a copy of
/// the host from inside it. Best effort, like `register`.
#[cfg(target_os = "linux")]
pub(crate) fn register_appimage(home: &Path, config: &Path) {
    let Some((appimage, bundled)) = running_appimage() else {
        return;
    };
    let dir = home.join(APPIMAGE_HOST_DIR);
    match install_appimage_host(&appimage, &bundled, &dir, config, home) {
        Ok(changes) => {
            for change in changes {
                eprintln!("[arca] {change}");
            }
        }
        Err(e) => eprintln!("[arca] could not install the browser host: {e}"),
    }
}

/// The AppImage file and the host inside it, when Arca runs as an AppImage.
///
/// The bundle type is what the bundler stamped into this binary; `APPIMAGE` is
/// what the AppImage runtime sets to its own file. A binary extracted from an
/// AppImage and run by hand has the first without the second, and no file to
/// be started from again, so it does not register.
#[cfg(target_os = "linux")]
fn running_appimage() -> Option<(PathBuf, PathBuf)> {
    use tauri::utils::{config::BundleType, platform::bundle_type};
    if bundle_type() != Some(BundleType::AppImage) {
        return None;
    }
    let appimage = PathBuf::from(std::env::var_os("APPIMAGE")?);
    let host = std::env::current_exe().ok()?.with_file_name(HOST_BINARY);
    (appimage.is_absolute() && appimage.is_file() && host.is_file()).then_some((appimage, host))
}

/// Copies the host out of the AppImage into `dir`, links `dir` back to the
/// AppImage, and points the browsers at the copy, in that order, so no
/// registration ever names a host that is not there. What it changed, as
/// sentences for the log; an error only when the host itself could not be put
/// in place, since then nothing may point at it.
#[cfg(any(target_os = "linux", test))]
fn install_appimage_host(
    appimage: &Path,
    bundled: &Path,
    dir: &Path,
    config: &Path,
    home: &Path,
) -> io::Result<Vec<String>> {
    let mut changes = Vec::new();
    let host = dir.join(HOST_BINARY);
    if write_if_changed(&host, &fs::read(bundled)?, 0o755)? {
        changes.push(format!(
            "installed the browser host from this AppImage at {}",
            host.display()
        ));
    }
    if link_if_changed(&dir.join(APPIMAGE_LINK), appimage)? {
        changes.push(format!(
            "the browser host now starts {}",
            appimage.display()
        ));
    }
    for (path, contents) in linux_registrations(config, home, &host) {
        let previous = registered_host(&path);
        match write_if_changed(&path, &contents, 0o600) {
            Ok(false) => {}
            Ok(true) => changes.push(match previous {
                Some(other) if other != host => format!(
                    "pointed {} at this AppImage's host instead of {}",
                    path.display(),
                    other.display()
                ),
                _ => format!("registered the browser host in {}", path.display()),
            }),
            Err(e) => changes.push(format!(
                "could not register the browser host in {}: {e}",
                path.display()
            )),
        }
    }
    Ok(changes)
}

/// Each installed browser's per-user registration file on Linux, and what it
/// should say. The same files scripts/install-linux.py writes.
#[cfg(any(target_os = "linux", test))]
fn linux_registrations(config: &Path, home: &Path, host: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let file = format!("{HOST_NAME}.json");
    let mut files: Vec<_> = LINUX_CHROMIUM_BROWSERS
        .iter()
        .map(|browser| config.join(browser))
        .filter(|browser| browser.is_dir())
        .map(|browser| {
            (
                browser.join("NativeMessagingHosts").join(&file),
                registration(host, false),
            )
        })
        .collect();
    if home.join(".mozilla").is_dir() {
        files.push((
            home.join(".mozilla/native-messaging-hosts").join(&file),
            registration(host, true),
        ));
    }
    files
}

/// The host a registration file names, if it is one.
#[cfg(any(target_os = "linux", test))]
fn registered_host(path: &Path) -> Option<PathBuf> {
    let json: serde_json::Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    json.get("path")?.as_str().map(PathBuf::from)
}

/// Points the symbolic link `link` at `target`, atomically, unless it already
/// does. Whether it changed.
#[cfg(any(target_os = "linux", test))]
fn link_if_changed(link: &Path, target: &Path) -> io::Result<bool> {
    if fs::read_link(link).is_ok_and(|current| current == target) {
        return Ok(false);
    }
    let temporary = temporary_beside(link)?;
    let _ = fs::remove_file(&temporary);
    std::os::unix::fs::symlink(target, &temporary)?;
    if let Err(e) = fs::rename(&temporary, link) {
        let _ = fs::remove_file(&temporary);
        return Err(e);
    }
    Ok(true)
}

/// A name in `path`'s folder to build its replacement under, the folder made.
fn temporary_beside(path: &Path) -> io::Result<PathBuf> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::other("a file is always in a folder"));
    };
    fs::create_dir_all(dir)?;
    Ok(dir.join(format!(
        ".{}.{}",
        name.to_string_lossy(),
        std::process::id()
    )))
}

/// Replaces `path` atomically, and only when it says something else, since
/// browsers read a registration every time they start a host, and may be
/// running the host being replaced. Whether it wrote.
fn write_if_changed(path: &Path, contents: &[u8], mode: u32) -> io::Result<bool> {
    if fs::read(path).is_ok_and(|current| current == contents) {
        return Ok(false);
    }
    let temporary = temporary_beside(path)?;
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
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

        assert!(write_if_changed(&path, b"current", 0o600).unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!write_if_changed(&path, b"current", 0o600).unwrap());

        fs::write(
            &path,
            br#"{"path":"/Users/someone/.local/lib/arca/vault-native-host"}"#,
        )
        .unwrap();
        assert!(write_if_changed(&path, b"current", 0o600).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"current");
        // Nothing left over beside it.
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    /// A home with Chrome, Brave and Firefox set up, a stand-in AppImage, and
    /// the host inside it. Chromium is not installed, so it gets nothing.
    struct Linux {
        home: tempfile::TempDir,
        appimage: PathBuf,
        bundled: PathBuf,
    }

    impl Linux {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            for dir in [
                ".config/google-chrome",
                ".config/BraveSoftware/Brave-Browser",
                ".mozilla",
            ] {
                fs::create_dir_all(home.path().join(dir)).unwrap();
            }
            let appimage = home.path().join("Downloads/Arca_0.9.0_amd64.AppImage");
            fs::create_dir_all(appimage.parent().unwrap()).unwrap();
            fs::write(&appimage, "appimage").unwrap();
            // Where the AppImage runtime mounts it: gone once it exits.
            let bundled = home
                .path()
                .join("tmp/.mount_ArcaXY/usr/bin/vault-native-host");
            fs::create_dir_all(bundled.parent().unwrap()).unwrap();
            fs::write(&bundled, "host 0.9.0").unwrap();
            Self {
                home,
                appimage,
                bundled,
            }
        }

        fn install(&self) -> io::Result<Vec<String>> {
            install_appimage_host(
                &self.appimage,
                &self.bundled,
                &self.dir(),
                &self.home.path().join(".config"),
                self.home.path(),
            )
        }

        fn dir(&self) -> PathBuf {
            self.home.path().join(APPIMAGE_HOST_DIR)
        }

        fn registration(&self, path: &str) -> Value {
            serde_json::from_slice(&fs::read(self.home.path().join(path)).unwrap()).unwrap()
        }
    }

    const CHROME: &str = ".config/google-chrome/NativeMessagingHosts/no.sybr.vault.json";
    const BRAVE: &str =
        ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts/no.sybr.vault.json";
    const FIREFOX: &str = ".mozilla/native-messaging-hosts/no.sybr.vault.json";

    #[test]
    fn an_appimage_copies_its_host_out_and_points_each_browser_at_the_copy() {
        let linux = Linux::new();
        let changes = linux.install().unwrap();
        let host = linux.dir().join("vault-native-host");

        // The copy, not the file in the mount, which is gone once Arca exits.
        assert_eq!(fs::read(&host).unwrap(), b"host 0.9.0");
        assert_eq!(
            fs::metadata(&host).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::read_link(linux.dir().join("Arca.AppImage")).unwrap(),
            linux.appimage
        );

        for path in [CHROME, BRAVE] {
            let chromium = linux.registration(path);
            assert_eq!(chromium["path"], host.to_str().unwrap(), "{path}");
            assert_eq!(
                chromium["allowed_origins"],
                json!(["chrome-extension://joeolbejbmnhmgajgmidpnpnjahdiobc/"])
            );
            assert!(chromium.get("allowed_extensions").is_none());
        }
        let firefox = linux.registration(FIREFOX);
        assert_eq!(firefox["path"], host.to_str().unwrap());
        assert_eq!(
            firefox["allowed_extensions"],
            json!(["sybr-passwords@sybr.no"])
        );
        // A browser that is not installed is not registered.
        assert!(!linux.home.path().join(".config/chromium").exists());
        assert_eq!(changes.len(), 5, "{changes:#?}");
    }

    #[test]
    fn launching_again_changes_nothing() {
        let linux = Linux::new();
        linux.install().unwrap();
        assert_eq!(linux.install().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn an_update_replaces_the_host_and_the_registrations_stay() {
        let linux = Linux::new();
        linux.install().unwrap();
        let chrome_before = fs::read(linux.home.path().join(CHROME)).unwrap();

        // What the in-app updater does: the same AppImage file, a newer host.
        fs::write(&linux.bundled, "host 0.9.1").unwrap();
        let changes = linux.install().unwrap();

        assert_eq!(
            fs::read(linux.dir().join("vault-native-host")).unwrap(),
            b"host 0.9.1"
        );
        assert_eq!(
            fs::read(linux.home.path().join(CHROME)).unwrap(),
            chrome_before
        );
        assert_eq!(changes.len(), 1, "{changes:#?}");
        assert!(
            changes[0].starts_with("installed the browser host"),
            "{changes:#?}"
        );
        // Nothing left over beside the host.
        let mut names: Vec<_> = fs::read_dir(linux.dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["Arca.AppImage", "vault-native-host"]);
    }

    #[test]
    fn another_appimage_launched_later_takes_the_link() {
        let linux = Linux::new();
        linux.install().unwrap();
        let newer = linux.home.path().join("Applications/Arca.AppImage");
        fs::create_dir_all(newer.parent().unwrap()).unwrap();
        fs::write(&newer, "appimage").unwrap();

        install_appimage_host(
            &newer,
            &linux.bundled,
            &linux.dir(),
            &linux.home.path().join(".config"),
            linux.home.path(),
        )
        .unwrap();
        assert_eq!(
            fs::read_link(linux.dir().join("Arca.AppImage")).unwrap(),
            newer
        );
    }

    #[test]
    fn a_source_install_s_registration_is_taken_over_and_the_log_says_so() {
        let linux = Linux::new();
        let source = linux.home.path().join(".local/lib/arca/vault-native-host");
        let chrome = linux.home.path().join(CHROME);
        fs::create_dir_all(chrome.parent().unwrap()).unwrap();
        fs::write(&chrome, format!(r#"{{"path":"{}"}}"#, source.display())).unwrap();

        let changes = linux.install().unwrap();

        assert_eq!(
            linux.registration(CHROME)["path"],
            linux.dir().join("vault-native-host").to_str().unwrap()
        );
        assert!(
            changes
                .iter()
                .any(|change| change.contains(&format!("instead of {}", source.display()))),
            "{changes:#?}"
        );
    }

    #[test]
    fn no_browser_is_pointed_at_a_host_that_is_not_there() {
        let linux = Linux::new();
        fs::remove_file(&linux.bundled).unwrap();
        assert!(linux.install().is_err());
        for path in [CHROME, BRAVE, FIREFOX] {
            assert!(!linux.home.path().join(path).exists(), "{path}");
        }
    }

    #[test]
    fn linux_browsers_are_the_ones_the_source_installer_registers() {
        // scripts/install-linux.py registers a source install for the same
        // browsers; an AppImage that skipped one would leave that browser on
        // whichever host was there before.
        let installer = include_str!("../../../../scripts/install-linux.py");
        let line = installer
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("chromium = ["))
            .expect("install-linux.py lists its Chromium browsers");
        let theirs: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
        assert_eq!(theirs, LINUX_CHROMIUM_BROWSERS);
    }
}
