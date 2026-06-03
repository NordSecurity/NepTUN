mod codecoverage;
mod perf;
mod test;
mod xray;
use clap::Parser;

#[derive(Parser, Debug)]
enum Cmd {
    /// Run performance benchmark
    Perf(perf::Cmd),
    /// Run xray
    Xray(xray::Cmd),
    /// Run tests
    Test(test::Cmd),
    /// Run code coverage
    CodeCoverage(codecoverage::Cmd),
}

fn main() {
    match Cmd::parse() {
        Cmd::Perf(perf) => perf.run(),
        Cmd::Xray(xray) => xray.run(),
        Cmd::Test(test) => test.run(),
        Cmd::CodeCoverage(coverage) => coverage.run(),
    }
}
