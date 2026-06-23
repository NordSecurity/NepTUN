use std::process::Command;

fn main() {
    let git_sha = get_git_sha().unwrap_or_else(|| "unknown".to_string());

    // Output GIT_SHA as build time env variable
    println!("cargo:rustc-env=GIT_SHA={}", git_sha);

    // Re-run build script if git head changed
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");

    // Re-run build script if the `neptun_keylog` cfg is changed via RUSTFLAGS,
    // so the display of the warning below is always handled correctly
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");

    if std::env::var_os("CARGO_CFG_NEPTUN_KEYLOG").is_some() {
        println!(
            "cargo:warning=neptun built with `--cfg neptun_keylog`: \
             ephemeral session keys can be dumped to the file named by \
             $NEPTUN_KEYLOG at runtime. DO NOT DISTRIBUTE this build."
        );
    }
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
