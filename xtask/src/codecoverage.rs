use clap::{Parser, ValueEnum};
use std::process::Command;

#[derive(Parser, Debug)]
pub struct Cmd {
    /// Coverage run context ("local", "ci")
    #[arg(
        long,
        required = true,
        help = "Context of test run (\"local\" or \"ci\"). Defaults to \"local\""
    )]
    context: RunContext,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum RunContext {
    Local,
    Ci,
}

impl Cmd {
    pub fn run(&self) {
        let mut args = vec![
            "llvm-cov",
            "--all-features",
            "--workspace",
            "--ignore-filename-regex",
            "xray|integration|xtask|main",
        ];

        match self.context {
            RunContext::Local => {
                args.push("--html");
            }
            RunContext::Ci => {
                args.extend_from_slice(&["--lcov", "--output-path", "lcov.info"]);
            }
        }

        let mut cmd = Command::new("cargo");
        if let Err(e) = cmd.args(args).status() {
            eprintln!("Failed to run cargo llvm-cov: {e}");
            std::process::exit(1);
        }
    }
}
