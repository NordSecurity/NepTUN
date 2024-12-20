use std::{fs::File, io::Write};

use base64::prelude::*;
use neptun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

use crate::XRayResult;

pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }
}

pub trait NepTUNKey {
    fn bytes(&self) -> &[u8];

    fn as_hex(&self) -> String {
        format_key(self.bytes())
    }

    fn as_b64(&self) -> String {
        BASE64_STANDARD.encode(self.bytes())
    }

    fn write_to_file(&self, path: &str) -> XRayResult<()> {
        let mut f = File::create(path)?;
        f.write_all(self.as_b64().as_bytes())?;
        Ok(())
    }
}

impl NepTUNKey for StaticSecret {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl NepTUNKey for PublicKey {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

fn format_key(key: &[u8]) -> String {
    let mut hex_key = String::with_capacity(key.len() * 2);
    for b in key {
        hex_key.push_str(&format!("{b:02x?}"));
    }
    hex_key
}
