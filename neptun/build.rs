use std::error::Error;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    // Extract last commit sha using cli
    let git_sha = String::from_utf8(
        Command::new("git")
            .args(["log", "-1", "--format=%h"])
            .output()?
            .stdout,
    )?
    .trim()
    .to_string();

    // Output GIT_SHA as build time env variable
    println!("cargo:rustc-env=GIT_SHA={}", git_sha);

    // Re-run build script if git head changed
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");

    Ok(())
}
