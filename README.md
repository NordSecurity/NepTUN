# NepTUN

**NepTUN** is an implementation of the [WireGuard<sup>®</sup>](https://www.wireguard.com/) protocol designed for portability and speed.

The project consists of two parts:
* The executable `neptun-cli`, a [userspace WireGuard](https://www.wireguard.com/xplatform/) implementation for Linux and macOS.
* The library `neptun` that can be used to implement fast and efficient WireGuard client apps on various platforms, including iOS and Android. It implements the underlying WireGuard protocol, without the network or tunnel stacks, those can be implemented in a platform idiomatic way.

### Building

- Library only: `cargo build --lib --no-default-features --release [--target $(TARGET_TRIPLE)]`
- Executable: `cargo build --bin neptun-cli --release [--target $(TARGET_TRIPLE)]`

By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin neptun --path .`.

### Running

As per the specification, to start a tunnel use:

`neptun-cli [-f/--foreground] INTERFACE-NAME`

The tunnel can then be configured using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8), as a regular WireGuard tunnel, or any other tool.

It is also possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `neptun`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=neptun-cli WG_SUDO=1 wg-quick up CONFIGURATION`

### Testing

The project uses Cargo features to gate tests by their requirements.

#### Prerequisites

Running `device` module integration tests specifically needs:
- `sudo`: required to create tunnels.
- Docker: you can install it [here](https://www.docker.com/get-started). If you are on Ubuntu/Debian you can run `apt-get install docker.io`.

#### Default tests with no prerequisites

Runs all tests with the default feature set:

    cargo test

#### Full test suite — requires sudo + Docker

Runs the complete test suite with all features enabled. Handles platform-specific sudo configuration automatically.
Shortcut for `cargo xtask test all-features`. When run, you'll be prompted for your password.

    cargo xtask test

#### Targeted test subsets

Default tests plus timer-behavior unit tests using a mock clock:

    cargo xtask test mock-instant

Device module integration tests (requires sudo + Docker):

    cargo xtask test docker-tests

Explicit invocation for a full test suite with all features (requires sudo + Docker, same as `cargo xtask test`):

    cargo xtask test all-features

## Supported platforms

Target triple                 |Binary|Library|
------------------------------|:----:|------|
x86_64-unknown-linux-gnu      |  ✓   | ✓    |
aarch64-unknown-linux-gnu     |  ✓   | ✓    |
armv7-unknown-linux-gnueabihf |  ✓   | ✓    |
x86_64-apple-darwin           |  ✓   | ✓    |
x86_64-pc-windows-msvc        |      | ✓    |
aarch64-apple-ios             |      | ✓    |
armv7-apple-ios               |      | ✓    |
armv7s-apple-ios              |      | ✓    |
aarch64-linux-android         |      | ✓    |
arm-linux-androideabi         |      | ✓    |

<sub>Other platforms may be added in the future</sub>

#### Linux

`x86-64`, `aarch64` and `armv7` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`neptun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi neptun`. sudo is not needed.

#### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall be licensed as above, without any additional terms or conditions.

If you want to contribute to this project, please read our [`CONTRIBUTING.md`].

[`CONTRIBUTING.md`]: https://github.com/cloudflare/.github/blob/master/CONTRIBUTING.md

## Acknowledgements

This project is based on the [BoringTun](https://github.com/cloudflare/boringtun) project by Cloudflare.

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. NepTUN is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
