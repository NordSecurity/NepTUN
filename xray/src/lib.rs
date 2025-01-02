use clap::{builder::TypedValueParser as _, Parser};
use types::{TestType, Wg};

pub mod client;
pub mod event_loop;
pub mod key_pair;
pub mod path_generator;
pub mod pcap;
pub mod types;
pub mod utils;

pub const WG_NAME: &str = "xraywg1";

pub const WG_PORT: u16 = 41414;
pub const PLAINTEXT_PORT: u16 = 52525;
pub const CRYPTO_PORT: u16 = 63636;

#[derive(Debug, Parser)]
pub struct CliArgs {
    #[arg(
        long,
        default_value_t = Wg::NepTUN,
        value_parser = clap::builder::PossibleValuesParser::new(["neptun", "native", "wggo"])
            .map(|s| s.parse::<Wg>().unwrap()),
    )]
    pub wg: Wg,
    #[arg(
        long,
        default_value_t = TestType::Crypto,
        value_parser = clap::builder::PossibleValuesParser::new(["crypto", "plaintext", "bidir"])
            .map(|s| s.parse::<TestType>().unwrap()),
    )]
    pub test_type: TestType,
    #[arg(long, default_value_t = 10)]
    pub packet_count: usize,
}
