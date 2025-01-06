use std::{net::SocketAddrV4, time::SystemTimeError};

use neptun::noise::TunnResult;
use pcap::Error as PcapError;
use serde::Serialize;
use tokio::sync::mpsc::error::SendError;

pub type XRayResult<T> = Result<T, XRayError>;

#[derive(thiserror::Error, Debug)]
pub enum XRayError {
    #[error("IO error: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("CSV error: {0:?}")]
    Csv(#[from] csv::Error),
    #[error("Command error: {0}")]
    ShellCommand(String),
    #[error("Handshake timed out")]
    HandshakeTimedOut,
    #[error("Unexpected TunnResult: {0:?}")]
    UnexpectedTunnResult(String),
    #[error("Unexpected packet type: {0}")]
    UnexpectedPacketType(u8),
    #[error("IPv6 is currently not supported")]
    Ipv6,
    #[error("Could not parse packet")]
    PacketParse,
    #[error("SystemTimeError: {0:?}")]
    Time(#[from] SystemTimeError),
    #[error("Failed to send command over channel: {0:?}")]
    ChannelSend(#[from] SendError<TestCmd>),
    #[error("Pcap error: {0:?}")]
    Pcap(#[from] PcapError),
}

impl From<TunnResult<'_>> for XRayError {
    fn from(tunn_res: TunnResult<'_>) -> Self {
        Self::UnexpectedTunnResult(format!("{tunn_res:?}"))
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Wg {
    NepTUN,
    LinuxNative,
    WireguardGo,
    BoringTun,
}

impl std::fmt::Display for Wg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NepTUN => "neptun",
            Self::LinuxNative => "native",
            Self::WireguardGo => "wggo",
            Self::BoringTun => "boringtun",
        };
        s.fmt(f)
    }
}

impl std::str::FromStr for Wg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "neptun" => Ok(Self::NepTUN),
            "native" => Ok(Self::LinuxNative),
            "wggo" => Ok(Self::WireguardGo),
            "boringtun" => Ok(Self::BoringTun),
            _ => Err(format!("Unsupported adapter type '{s}'")),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum TestType {
    Crypto,
    Plaintext,
}

impl std::fmt::Display for TestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Crypto => "crypto",
            Self::Plaintext => "plaintext",
        };
        s.fmt(f)
    }
}

impl std::str::FromStr for TestType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "crypto" => Ok(Self::Crypto),
            "plaintext" => Ok(Self::Plaintext),
            _ => Err(format!("Unsupported test type '{s}'")),
        }
    }
}

#[derive(Debug)]
pub enum SendType {
    Plaintext,
    HandshakeInitiation,
    HandshakeResponse,
    Data,
    None,
}

#[derive(Debug)]
pub enum RecvType {
    HandshakeInitiation,
    HandshakeResponse,
    Data { length: usize },
}

/// A `send_index` is not stored in the packet since they are added, in order, to a vector when they're sent
/// so their index in that vector accurately represents the send index
#[derive(Copy, Clone, Default, Serialize)]
pub struct Packet {
    pub recv_index: Option<u64>,
    pub send_ts: u128,
    pub pre_wg_ts: Option<u128>,
    pub post_wg_ts: Option<u128>,
    pub recv_ts: Option<u128>,
}

impl Packet {
    pub fn new(send_ts: u128) -> Self {
        Self {
            send_ts,
            ..Default::default()
        }
    }

    pub const fn send_size() -> usize {
        std::mem::size_of::<u64>() + std::mem::size_of::<u128>()
    }

    pub const fn index_size() -> usize {
        std::mem::size_of::<u64>()
    }

    pub const fn ts_size() -> usize {
        std::mem::size_of::<u128>()
    }
}

pub enum TestCmd {
    SendEncrypted {
        sock_dst: SocketAddrV4,
        packet_dst: SocketAddrV4,
        send_index: u64,
    },
    SendPlaintext {
        dst: SocketAddrV4,
        send_index: u64,
    },
    Done,
}
