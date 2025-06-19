use clap::Parser;
use xshell::{cmd, Shell};

#[derive(Parser, Debug)]
pub struct Cmd {
    /// Git ref of the benchmark base
    #[arg(short, long, help = "Git reference to use as the benchmark base")]
    base: String,
    /// Optional test type ("upload", "download")
    #[arg(
        short,
        long,
        help = "Type of test to run (\"upload\" or \"download\"). Defaults to \"upload\""
    )]
    test_type: Option<String>,
}

struct GitWorktree {
    name: String,
    sh: Shell,
}

impl GitWorktree {
    fn new(name: &str, base_ref: &str) -> Self {
        let sh = Shell::new().expect("Failed to create shell object");
        cmd!(sh, "git worktree add {name} {base_ref}")
            .run()
            .expect("Failed to create base worktree");
        GitWorktree {
            name: name.to_string(),
            sh,
        }
    }
}

impl Drop for GitWorktree {
    fn drop(&mut self) {
        let name = &self.name;
        _ = cmd!(self.sh, "git worktree remove {name}").run();
    }
}

fn build_neptun_cli(dir: &str) {
    let sh = Shell::new().expect("Failed to create shell object");
    sh.change_dir(dir);
    cmd!(sh, "cargo build --release -p neptun-cli")
        .run()
        .expect("Failed to build base version");
}

impl Cmd {
    pub fn run(&self) {
        let worktree = GitWorktree::new("base", &self.base);
        build_neptun_cli(".");
        build_neptun_cli(&worktree.name);

        if let Some(test_type) = &self.test_type {
            std::env::set_var("TEST_TYPE", test_type);
        }

        let sh = Shell::new().expect("Failed to create shell object");
        cmd!(
            sh,
            "docker compose -f xtask/perf/docker-compose.yml up --abort-on-container-exit"
        )
        .run()
        .expect("Failed to build base version");
    }
}
