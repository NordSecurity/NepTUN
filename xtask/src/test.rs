use clap::{Parser, ValueEnum};
use std::{
    io,
    process::{Command, ExitStatus},
};

#[derive(Debug, Clone, ValueEnum)]
enum Feature {
    /// Run tests with mock-instant feature enabled
    MockInstant,
    /// Run device integration tests with docker-tests feature enabled
    /// (require sudo privileges and Docker)
    DockerTests,
    /// Run tests with all features enabled
    /// (require sudo privileges and Docker)
    AllFeatures,
}

#[derive(Parser, Debug)]
pub struct Cmd {
    /// Feature to be tested (runs with all-features if none is specified)
    feature: Option<Feature>,
}

impl Cmd {
    pub fn run(&self) {
        let result = match &self.feature {
            Some(Feature::MockInstant) => run_mock_instant(),
            Some(Feature::DockerTests) => run_docker_tests(),
            Some(Feature::AllFeatures) | None => run_all_features(),
        };

        if let Err(e) = result {
            eprintln!("Failed to run cargo test: {e}");
            std::process::exit(1);
        }
    }
}

fn run_mock_instant() -> io::Result<ExitStatus> {
    Command::new("cargo")
        .args(["test", "--features", "mock-instant"])
        .status()
}

fn run_docker_tests() -> io::Result<ExitStatus> {
    let (runner_env_var, extra_args) = get_platform_cfg();

    Command::new("cargo")
        .args(["test", "--features", "docker-tests", "--test", "device"])
        .args(extra_args)
        .env(runner_env_var, "sudo -E")
        .status()
}

fn run_all_features() -> io::Result<ExitStatus> {
    let (runner_env_var, extra_args) = get_platform_cfg();

    Command::new("cargo")
        .args(["test", "--all-features"])
        .args(extra_args)
        .env(runner_env_var, "sudo -E")
        .status()
}

pub(crate) fn get_platform_cfg<'a>() -> (String, &'a [&'a str]) {
    let target_triple = env!("TARGET_TRIPLE").to_uppercase().replace('-', "_");

    let runner_env_var = format!("CARGO_TARGET_{target_triple}_RUNNER");

    let extra_args = if cfg!(target_os = "macos") {
        // Device integration tests are flaky when run in parallel in macOS
        ["--", "--test-threads=1"].as_slice()
    } else {
        [].as_slice()
    };

    (runner_env_var, extra_args)
}
