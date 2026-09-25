//! Start the installed desktop app only for an explicit unlock request.
//! Passive metadata/capability probes must never start it.
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn installed_app() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let candidates = vec![PathBuf::from("/Applications/Arca.app")];
    #[cfg(target_os = "linux")]
    let candidates = vec![
        dirs::home_dir()?.join(".local/bin/arca"),
        PathBuf::from("/usr/bin/vault-desktop"),
    ];
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let candidates: Vec<PathBuf> = Vec::new();
    candidates.into_iter().find(|path| path.exists())
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
