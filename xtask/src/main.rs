mod perf;

use clap::Parser;

#[derive(Parser, Debug)]
enum Cmd {
    /// Run performance benchmark
    Perf(perf::Cmd),
}

fn main() {
    match Cmd::parse() {
        Cmd::Perf(perf) => perf.run(),
    }
}
