//! Whether this copy of Arca may replace itself with a newer release.

use serde::Serialize;
use tauri::utils::config::BundleType;

/// How this copy gets its updates, shown in Settings ▸ Updates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdateRoute {
    /// Settings downloads the signed release and installs it.
    InApp,
    /// A `.deb` or `.rpm`: the package manager owns the files.
    PackageManager,
    /// Built from a Git checkout by `scripts/install-linux.sh`.
    Source,
}

pub fn route() -> UpdateRoute {
    route_for(std::env::consts::OS, tauri::utils::platform::bundle_type())
}

/// On Linux the updater can replace a running AppImage and nothing else, yet
/// it takes the AppImage path for any binary it cannot place: a copy built
/// from source would be overwritten with the downloaded AppImage, outside the
/// installer's verification and rollback, and the browser extension's native
/// host would stay on the old version. So only an AppImage updates in place.
fn route_for(os: &str, bundle: Option<BundleType>) -> UpdateRoute {
    if os != "linux" {
        return UpdateRoute::InApp;
    }
    match bundle {
        Some(BundleType::AppImage) => UpdateRoute::InApp,
        Some(BundleType::Deb | BundleType::Rpm) => UpdateRoute::PackageManager,
        _ => UpdateRoute::Source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_appimage_replaces_itself_on_linux() {
        assert_eq!(
            route_for("linux", Some(BundleType::AppImage)),
            UpdateRoute::InApp
        );
        assert_eq!(
            route_for("linux", Some(BundleType::Deb)),
            UpdateRoute::PackageManager
        );
        assert_eq!(
            route_for("linux", Some(BundleType::Rpm)),
            UpdateRoute::PackageManager
        );
        // `install-linux.sh` builds with `--no-bundle`, which records no type.
        assert_eq!(route_for("linux", None), UpdateRoute::Source);
    }

    #[test]
    fn other_platforms_keep_updating_in_the_app() {
        assert_eq!(
            route_for("macos", Some(BundleType::App)),
            UpdateRoute::InApp
        );
        assert_eq!(route_for("windows", None), UpdateRoute::InApp);
    }
}
