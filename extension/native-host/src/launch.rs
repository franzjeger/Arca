//! Start the installed desktop app only for an explicit unlock request.
//! Passive metadata/capability probes must never start it.
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn installed_app() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let candidates = vec![PathBuf::from("/Applications/Arca.app")];
    #[cfg(target_os = "linux")]
    let candidates = linux_candidates(std::env::current_exe().ok(), dirs::home_dir());
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let candidates: Vec<PathBuf> = Vec::new();
    candidates.into_iter().find(|path| path.exists())
}

/// Where Arca may be on Linux, in order, for a host at `exe`.
///
/// First the link an AppImage leaves beside the host it copies out of itself
/// (apps/desktop/src-tauri/src/browser_host.rs): that host belongs to that
/// AppImage, and only that host has the link. A link whose AppImage was moved
/// or deleted does not exist, and the next candidate is tried. Then a source
/// install's launcher, then a package's binary.
#[cfg(any(target_os = "linux", all(unix, test)))]
fn linux_candidates(exe: Option<PathBuf>, home: Option<PathBuf>) -> Vec<PathBuf> {
    exe.map(|exe| exe.with_file_name("Arca.AppImage"))
        .into_iter()
        .chain(home.map(|home| home.join(".local/bin/arca")))
        .chain([PathBuf::from("/usr/bin/vault-desktop")])
        .collect()
}

pub fn available() -> bool {
    installed_app().is_some()
}

#[cfg(not(test))]
pub fn ensure_running(probe: impl FnMut() -> bool) -> Result<(), String> {
    ensure_ready(probe, launch, std::thread::sleep, Duration::from_secs(15))
}

// Unit tests must never start or contact the user's actual vault.
#[cfg(test)]
pub fn ensure_running(_probe: impl FnMut() -> bool) -> Result<(), String> {
    Err("Arca is not running.".into())
}

#[cfg_attr(test, allow(dead_code))]
fn launch() -> Result<(), String> {
    let app = installed_app().ok_or("Install Arca in its standard location, then try again.")?;
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut cmd = Command::new("/usr/bin/open");
        cmd.arg("-g").arg("-a").arg(app);
        cmd
    };
    #[cfg(not(target_os = "macos"))]
    let mut command = Command::new(app);
    // Native messaging owns stdout. A child must not inherit its pipes or keep
    // Chrome's connection alive. No shell, PATH lookup, or page-supplied args.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Could not start Arca. Open the installed app and try again.")?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

fn ensure_ready(
    mut probe: impl FnMut() -> bool,
    launch: impl FnOnce() -> Result<(), String>,
    mut sleep: impl FnMut(Duration),
    timeout: Duration,
) -> Result<(), String> {
    if probe() {
        return Ok(());
    }
    launch()?;
    let start = Instant::now();
    loop {
        if probe() {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(
                "Arca started but did not become ready. Open the app and try again.".into(),
            );
        }
        sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Symbolic links, which the test makes, are a Unix thing.
    #[cfg(unix)]
    #[test]
    fn a_host_from_an_appimage_starts_that_appimage_and_others_fall_through() {
        let dir = tempfile::tempdir().unwrap();
        let host_dir = dir.path().join(".local/lib/arca-appimage");
        std::fs::create_dir_all(&host_dir).unwrap();
        let appimage = dir.path().join("Arca_0.9.0_amd64.AppImage");
        std::fs::write(&appimage, "appimage").unwrap();
        std::os::unix::fs::symlink(&appimage, host_dir.join("Arca.AppImage")).unwrap();
        let exe = Some(host_dir.join("vault-native-host"));
        let home = Some(dir.path().to_path_buf());

        let candidates = linux_candidates(exe.clone(), home.clone());
        assert_eq!(
            candidates,
            [
                host_dir.join("Arca.AppImage"),
                dir.path().join(".local/bin/arca"),
                PathBuf::from("/usr/bin/vault-desktop"),
            ]
        );
        let found = |candidates: Vec<PathBuf>| candidates.into_iter().find(|path| path.exists());
        assert_eq!(found(candidates), Some(host_dir.join("Arca.AppImage")));

        // The AppImage was deleted: its link leads nowhere, so the host goes
        // on to an install that is there.
        std::fs::remove_file(&appimage).unwrap();
        let launcher = dir.path().join(".local/bin/arca");
        std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        std::fs::write(&launcher, "launcher").unwrap();
        assert_eq!(found(linux_candidates(exe, home)), Some(launcher));

        // A source install's host has no link beside it at all.
        let source = Some(dir.path().join(".local/lib/arca/vault-native-host"));
        assert_eq!(
            linux_candidates(source, None),
            [
                dir.path().join(".local/lib/arca/Arca.AppImage"),
                PathBuf::from("/usr/bin/vault-desktop"),
            ]
        );
    }
    #[test]
    fn running_app_is_not_launched_again() {
        assert!(ensure_ready(
            || true,
            || panic!("already running"),
            |_| {},
            Duration::ZERO
        )
        .is_ok());
    }
    #[test]
    fn startup_waits_for_authenticated_probe_and_launches_once() {
        let mut probes = 0;
        let mut launches = 0;
        let mut sleeps = 0;
        assert!(ensure_ready(
            || {
                probes += 1;
                probes == 4
            },
            || {
                launches += 1;
                Ok(())
            },
            |_| sleeps += 1,
            Duration::from_secs(1)
        )
        .is_ok());
        assert_eq!((probes, launches, sleeps), (4, 1, 2));
    }
    #[test]
    fn missing_install_and_startup_timeout_are_errors() {
        assert_eq!(
            ensure_ready(
                || false,
                || Err("missing app".into()),
                |_| panic!(),
                Duration::ZERO
            ),
            Err("missing app".into())
        );
        assert!(
            ensure_ready(|| false, || Ok(()), |_| panic!(), Duration::ZERO)
                .unwrap_err()
                .contains("did not become ready")
        );
    }
}
