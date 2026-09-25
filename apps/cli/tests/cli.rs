use std::process::Command;

#[test]
fn version_flag_reports_the_package_version_without_the_app_running() {
    let output = Command::new(env!("CARGO_BIN_EXE_arca"))
        .arg("--version")
        .output()
        .expect("arca binary runs");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version is UTF-8"),
        format!("arca {}\n", env!("CARGO_PKG_VERSION")),
    );
    assert!(output.stderr.is_empty());
}
