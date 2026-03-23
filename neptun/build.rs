use std::process::Command;

fn main() {
    let git_sha = get_git_sha().unwrap_or_else(|| "unknown".to_string());

    // Output GIT_SHA as build time env variable
    println!("cargo:rustc-env=GIT_SHA={}", git_sha);

    // Re-run build script if git head changed
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
}

fn get_git_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["log", "-1", "--format=%h"])
        .output()
        .ok()?;

    if output.status.success() {
        let sha = String::from_utf8(output.stdout).ok()?.trim().to_string();
        if !sha.is_empty() {
            return Some(sha);
        }
    }

    None
}
