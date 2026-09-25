// Shared by the desktop and native-host build scripts.
fn git(args: &[&str]) -> Option<String> {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

pub fn emit_build_info() {
    for name in
        ["HEAD", "index"]
            .into_iter()
            .map(String::from)
            .chain(git(&["symbolic-ref", "-q", "HEAD"]))
    {
        if let Some(path) = git(&["rev-parse", "--git-path", &name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    println!("cargo:rerun-if-changed=src");
    let build = git(&["describe", "--always", "--dirty", "--abbrev=12"])
        .unwrap_or_else(|| "unknown".into());
    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=ARCA_BUILD={build}");
    println!("cargo:rustc-env=ARCA_COMMIT={commit}");
}
