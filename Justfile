set shell := ["sh", "-c"]

# Aliases to be used only in interactive mode, please use full names when calling
# just in scripts or gitlab jobs.

[private]
alias t := test
[private]
alias c := clippy
[private]
alias u := udeps
[private]
alias d := deny
[private]
alias p := prepush

nightly := "nightly-2025-03-26"
rust_stable := "1.89.0"

# Run all rust tests
test:
    cargo test --all --quiet

# Run clippy
clippy: _clippy-install
    cargo clippy -p neptun --features device -- --deny warnings --allow unknown-lints -W clippy::expect_used -W clippy::panic -W clippy::unwrap_used -W clippy::indexing_slicing

# Run udeps
udeps: _udeps-install
    cargo +{{ nightly }} udeps --workspace --locked --output human --backend depinfo --release

# Run deny
deny: _deny-install
    cargo deny check

# Run rust pre-push checks
prepush: test clippy udeps deny

_udeps-install: _nightly-install
    cargo +{{ nightly }} install cargo-udeps@0.1.55 --locked

_deny-install:
    cargo install --locked cargo-deny@0.15.1

_nightly-install:
    rustup toolchain add {{ nightly }}

_clippy-install:
    rustup component add clippy
