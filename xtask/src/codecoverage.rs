use clap::{Parser, ValueEnum};
use std::{
    io,
    process::{Command, ExitStatus},
};

use crate::test::get_platform_cfg;

#[derive(Parser, Debug)]
pub struct Cmd {
    /// Coverage run action (defaults to `local` if no action is specified)
    action: Option<Action>,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Action {
    /// Clean accumulated coverage data
    Clean,
    /// Run tests with `mock-instant` feature enabled and accumulate coverage data
    MockInstant,
    /// Run tests with `docker-tests` feature enabled and accumulate coverage data
    /// (requires sudo privileges and Docker)
    DockerTests,
    /// Emit an lcov report from accumulated coverage data
    ReportLcov,
    /// Emit an HTML report from accumulated coverage data and open it in a browser
    ReportHtml,
    /// Run the full code coverage pipeline, store the report and open it in a browser
    Local,
}

impl Cmd {
    pub fn run(&self) {
        let result = match self.action {
            Some(Action::Clean) => run_clean(),
            Some(Action::MockInstant) => run_mock_instant(),
            Some(Action::DockerTests) => run_docker_tests(),
            Some(Action::ReportLcov) => run_report_lcov(),
            Some(Action::ReportHtml) => run_report_html(),
            Some(Action::Local) | None => run_local(),
        };

        if let Err(e) = result {
            eprintln!("Failed to run cargo llvm-cov: {e}");
            std::process::exit(1);
        }
    }
}

fn run_clean() -> io::Result<ExitStatus> {
    Command::new("cargo")
        .args(["llvm-cov", "clean", "--workspace"])
        .status()
}

fn run_mock_instant() -> io::Result<ExitStatus> {
    Command::new("cargo")
        .args(["llvm-cov", "--features", "mock-instant", "--no-report"])
        .status()
}

fn run_docker_tests() -> io::Result<ExitStatus> {
    let (runner_env_var, extra_args) = get_platform_cfg();

    Command::new("cargo")
        .args([
            "llvm-cov",
            "--features",
            "docker-tests",
            "--test",
            "device",
            "--no-report",
        ])
        .args(extra_args)
        .env(&runner_env_var, "sudo -E")
        .status()
}

fn run_report_lcov() -> io::Result<ExitStatus> {
    Command::new("cargo")
        .args([
            "llvm-cov",
            "report",
            "--ignore-filename-regex",
            "xray|xtask|main",
            "--lcov",
            "--output-path",
            "target/lcov.info",
        ])
        .status()
}

fn run_report_html() -> io::Result<ExitStatus> {
    Command::new("cargo")
        .args([
            "llvm-cov",
            "report",
            "--ignore-filename-regex",
            "xray|xtask|main",
            "--html",
            "--open",
        ])
        .status()
}

fn run_local() -> io::Result<ExitStatus> {
    run_clean()?;
    run_mock_instant()?;
    run_docker_tests()?;
    run_report_html()
}
