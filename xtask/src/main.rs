mod codecoverage;
mod perf;
mod xray;
use clap::Parser;

#[derive(Parser, Debug)]
enum Cmd {
    /// Run performance benchmark
    Perf(perf::Cmd),
    /// Run xray
    Xray(xray::Cmd),
    /// Run code coverage
    CodeCoverage(codecoverage::Cmd),
}

fn main() {
    match Cmd::parse() {
        Cmd::Perf(perf) => perf.run(),
        Cmd::Xray(xray) => xray.run(),
        Cmd::CodeCoverage(coverage) => coverage.run(),
    }
}
