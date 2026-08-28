use base64::{engine::general_purpose, Engine};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Number of leading/trailing base64 characters kept when masking a public key.
const MASK_KEEP: usize = 4;
/// base64 length of a 32 byte key: `4 * ceil(32 / 3)`.
const KEY_BASE64_LEN: usize = 44;

/// Masked public key wrapper.
///
/// `Display` and `Debug` both render only the first and last four base64
/// characters (`AQEB...AQE=`) — enough to tell which peer a log line belongs
/// to, without putting a whole key in a log sink.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PubKey([u8; 32]);

impl PubKey {
    /// Raw key material.
    // Only used by the firewall callbacks; gated to match `device` in lib.rs,
    // which is unix-only - otherwise this is dead code on Windows.
    #[cfg(all(unix, feature = "device"))]
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for PubKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<crate::x25519::PublicKey> for PubKey {
    fn from(key: crate::x25519::PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

impl From<&crate::x25519::PublicKey> for PubKey {
    fn from(key: &crate::x25519::PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

impl std::fmt::Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = general_purpose::STANDARD.encode(self.0);
        match (
            encoded.get(..MASK_KEEP),
            encoded.get(KEY_BASE64_LEN - MASK_KEEP..),
        ) {
            (Some(head), Some(tail)) => write!(f, "{}...{}", head, tail),
            _ => f.write_str("<unencodable key>"),
        }
    }
}

// Deliberately not derived: a derived Debug would print the raw bytes, and
// `?key` in a log statement is an easy mistake to make. Debug == Display, so
// both sigils are safe.
impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[allow(dead_code)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct KeyBytes([u8; 32]);

impl KeyBytes {
    #[allow(dead_code)]
    pub(crate) fn get_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_ascii() {
            return Err("Key must be ASCII encoded");
        }

        let mut internal = Zeroizing::new([0u8; 32]);

        match s.len() {
            64 => {
                // Try to parse as hex
                for (i, element) in internal.iter_mut().enumerate() {
                    *element = u8::from_str_radix(
                        s.get(i * 2..=i * 2 + 1)
                            .ok_or("String Index out of bounds")?,
                        16,
                    )
                    .map_err(|_| "Illegal character in key")?;
                }
            }
            44 => {
                // Try to parse as padded base64
                match general_purpose::STANDARD.decode_slice(s, &mut *internal) {
                    Ok(len) if len == internal.len() => {}
                    Ok(_) => return Err("Decoded key has wrong length"),
                    Err(_) => return Err("Failed to decode base64"),
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(KeyBytes(*internal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn pubkey_display_is_masked() {
        // Known keys and the exact fragment each must render as. The full
        // base64 is spelled out so the expected head and tail can be checked
        // by eye:
        //
        //   [1u8; 32]   AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
        //   1..=32      AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
        //   [0xff; 32]  //////////////////////////////////////////8=
        //
        // The sequential key has a head and tail that differ, so it cannot
        // pass by coincidence; the all-ones key covers the `/` end of the
        // base64 alphabet.
        let sequential: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);

        assert_eq!(PubKey::from([1u8; 32]).to_string(), "AQEB...AQE=");
        assert_eq!(PubKey::from(sequential).to_string(), "AQID...HyA=");
        assert_eq!(PubKey::from([0xffu8; 32]).to_string(), "////...//8=");

        // Debug is masked too, so `?key` is as safe as `%key`.
        assert_eq!(format!("{:?}", PubKey::from(sequential)), "AQID...HyA=");
    }

    #[test]
    fn invalid_base64_44_chars_should_return_error() {
        // 44 chars of garbage — not valid base64
        let invalid = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$";
        assert_eq!(invalid.len(), 44);

        let result = KeyBytes::from_str(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_base64_43_chars_should_return_error() {
        // 43 chars of garbage — not valid base64
        let invalid = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$";
        assert_eq!(invalid.len(), 43);

        let result = KeyBytes::from_str(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn valid_base64_key_should_succeed() {
        // 32 zero bytes encoded as base64
        let valid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(valid.len(), 44);

        let result = KeyBytes::from_str(valid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().get_bytes(), &[0u8; 32]);
    }

    #[test]
    fn valid_hex_should_succeed() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(hex.len(), 64);
        let result = KeyBytes::from_str(hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().get_bytes(), &[0u8; 32]);
    }

    #[test]
    fn valid_hex_with_nonzero_bytes_should_succeed() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert_eq!(hex.len(), 64);
        let result = KeyBytes::from_str(hex).unwrap();
        let expected: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        assert_eq!(result.get_bytes(), &expected);
    }

    #[test]
    fn valid_hex_uppercase_should_succeed() {
        let hex = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";
        assert_eq!(hex.len(), 64);
        let result = KeyBytes::from_str(hex).unwrap();
        let expected: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        assert_eq!(result.get_bytes(), &expected);
    }

    #[test]
    fn valid_hex_mixed_case_should_succeed() {
        let hex = "0102030405060708090a0B0c0D0e0F101112131415161718191A1b1C1d1E1f20";
        assert_eq!(hex.len(), 64);
        let result = KeyBytes::from_str(hex).unwrap();
        let expected: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        assert_eq!(result.get_bytes(), &expected);
    }

    #[test]
    fn invalid_hex_chars_should_return_error() {
        let invalid = "z".repeat(64);
        assert!(KeyBytes::from_str(&invalid).is_err());
    }

    #[test]
    fn hex_with_0x_prefix_should_return_error() {
        let hex = "0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert_eq!(hex.len(), 64);
        assert!(KeyBytes::from_str(hex).is_err());
    }

    #[test]
    fn empty_string_should_return_error() {
        assert!(KeyBytes::from_str("").is_err());
    }

    #[test]
    fn wrong_lengths_should_return_error() {
        assert!(KeyBytes::from_str("a").is_err());
        assert!(KeyBytes::from_str(&"a".repeat(42)).is_err());
        assert!(KeyBytes::from_str(&"a".repeat(45)).is_err());
        assert!(KeyBytes::from_str(&"a".repeat(63)).is_err());
        assert!(KeyBytes::from_str(&"a".repeat(65)).is_err());
    }

    #[test]
    fn multibyte_utf8_should_return_error() {
        let s = "ä".repeat(32); // 'ä' is 2 bytes in UTF-8, so 32 × 2 = 64 bytes
        assert_eq!(s.len(), 64);
        assert!(KeyBytes::from_str(&s).is_err());
    }

    #[test]
    fn base64_decoding_to_wrong_length_should_return_error() {
        let short_b64 = general_purpose::STANDARD.encode([0u8; 16]);
        assert!(short_b64.len() == 24);
        assert!(KeyBytes::from_str(&short_b64).is_err());

        let long_b64 = general_purpose::STANDARD.encode([0u8; 33]);
        assert_eq!(long_b64.len(), 44);
        assert!(KeyBytes::from_str(&long_b64).is_err());
    }

    #[test]
    fn unpadded_base64_43_chars_is_rejected() {
        let unpadded = general_purpose::STANDARD_NO_PAD.encode([0u8; 32]);
        assert_eq!(unpadded.len(), 43);
        assert!(KeyBytes::from_str(&unpadded).is_err());
    }

    #[test]
    fn padded_base64_44_chars_is_accepted() {
        let padded = general_purpose::STANDARD.encode([0u8; 32]);
        assert_eq!(padded.len(), 44);

        let result = KeyBytes::from_str(&padded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().get_bytes(), &[0u8; 32]);
    }
}
