// Copyright (c) 2024 Nord Security. All rights reserved.
// Copyright (c) 2019-2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::PacketData;
use crate::noise::errors::WireGuardError;
use aegis::aegis256x2::Aegis256X2;
use parking_lot::Mutex;
use std::convert::TryInto;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    // AEGIS-256X2 transport keys (32 bytes). A fresh Aegis256X2 state is built per packet, so we
    // keep the raw keys rather than a pre-expanded cipher object.
    receiving_key: [u8; 32],
    sending_key: [u8; 32],
    sending_key_counter: AtomicUsize,
    receiving_key_counter: Mutex<ReceivingKeyCounterValidator>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
pub(crate) const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone, Default)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    #[allow(clippy::indexing_slicing)]
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[allow(clippy::indexing_slicing)]
    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[allow(clippy::indexing_slicing)]
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[allow(clippy::indexing_slicing)]
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(WireGuardError::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while i % WORD_SIZE != 0 && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Result<Session, WireGuardError> {
        Ok(Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiving_key,
            sending_key,
            sending_key_counter: AtomicUsize::new(0),
            receiving_key_counter: Mutex::new(Default::default()),
        })
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    /// payload_len - length of data available in packet_buffer
    /// packet_buffer - pre-allocated space containing the payload, to be replaced by encrypted UDP packet to send over the network
    /// returns the size of the formatted packet
    pub(super) fn format_packet_data<'a>(
        &self,
        payload_len: usize,
        packet_buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if packet_buffer.len() < payload_len + super::DATA_OVERHEAD_SZ as usize {
            tracing::warn!(
                "Destination packet is too small: {} < {}",
                packet_buffer.len(),
                payload_len + super::DATA_OVERHEAD_SZ as usize
            );
            return Err(WireGuardError::IncorrectPacketLength);
        }

        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;

        let (message_type, rest) = packet_buffer.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        // Data packets carry NO suite byte — header is `04 00 00 00`, matching the NordLynx
        // kernel (send.c writes only `type = MESSAGE_DATA`). The suite is implicit from the
        // negotiated keypair; only handshake headers carry the suite byte (for negotiation).
        // `DATA.to_le_bytes()` already zeros bytes 1..4.
        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        // AEGIS-256X2: 32-byte nonce = LE64 counter at offset 0 (zeros after), empty AAD, 16-byte
        // tag appended inline. Matches the NordLynx kernel data-packet format.
        let n = {
            let mut nonce = [0u8; 32];
            nonce
                .get_mut(..8)
                .ok_or(WireGuardError::InvalidIndex)?
                .copy_from_slice(&sending_key_counter.to_le_bytes());
            let plaintext = data
                .get_mut(..payload_len)
                .ok_or(WireGuardError::InvalidLength)?;
            let tag =
                Aegis256X2::<16>::new(&self.sending_key, &nonce).encrypt_in_place(plaintext, &[]);
            #[allow(clippy::indexing_slicing)]
            {
                data[payload_len..payload_len + AEAD_SIZE].copy_from_slice(&tag);
            }
            payload_len + AEAD_SIZE
        };

        packet_buffer
            .get_mut(..DATA_OFFSET + n)
            .ok_or(WireGuardError::InvalidLength)
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub(super) fn receive_packet_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            return Err(WireGuardError::DestinationBufferTooSmall);
        }
        if packet.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(packet.counter)?;

        let ret = {
            let mut nonce = [0u8; 32];
            nonce
                .get_mut(..8)
                .ok_or(WireGuardError::InvalidIndex)?
                .copy_from_slice(&packet.counter.to_le_bytes());
            // encrypted_encapsulated_packet = ciphertext ‖ tag(16); decrypt the ciphertext into dst.
            let pt_len = ct_len
                .checked_sub(AEAD_SIZE)
                .ok_or(WireGuardError::InvalidLength)?;
            let (ct, tag) = packet.encrypted_encapsulated_packet.split_at(pt_len);
            let tag: [u8; AEAD_SIZE] = tag.try_into().map_err(|_| WireGuardError::InvalidLength)?;
            let out = dst.get_mut(..pt_len).ok_or(WireGuardError::InvalidLength)?;
            out.copy_from_slice(ct);
            Aegis256X2::<16>::new(&self.receiving_key, &nonce)
                .decrypt_in_place(out, &tag, &[])
                .map_err(|_| WireGuardError::InvalidAeadTag)?;
            out
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(packet.counter)?;
        Ok(ret)
    }

    /// Encrypt a data packet (off-lock data path). The plaintext payload must already be
    /// at `packet_buffer[DATA_OFFSET..DATA_OFFSET + payload_len]`; returns the full WireGuard
    /// data packet. Takes `&self` so it can run on a shared `Arc<Session>` without the Tunn lock.
    pub fn encrypt<'a>(
        &self,
        payload_len: usize,
        packet_buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        self.format_packet_data(payload_len, packet_buffer)
    }

    /// Decrypt a parsed data packet (off-lock data path). Takes `&self` so it can run on a
    /// shared `Arc<Session>` without the Tunn lock.
    pub fn decrypt<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        self.receive_packet_data(packet, dst)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }

    #[cfg(feature = "xray")]
    pub fn is_right_session(&self, packet_recv_index: u32) -> bool {
        self.receiving_index == packet_recv_index || self.sending_index == packet_recv_index
    }

    #[cfg(feature = "xray")]
    pub fn decrypt_data_packet<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            return Err(WireGuardError::DestinationBufferTooSmall);
        }
        let decrypt_key = if packet.receiver_idx == self.receiving_index {
            &self.receiving_key
        } else if packet.receiver_idx == self.sending_index {
            &self.sending_key
        } else {
            return Err(WireGuardError::WrongIndex);
        };

        let ret = {
            let mut nonce = [0u8; 32];
            nonce
                .get_mut(..8)
                .ok_or(WireGuardError::InvalidIndex)?
                .copy_from_slice(&packet.counter.to_le_bytes());
            let pt_len = ct_len
                .checked_sub(AEAD_SIZE)
                .ok_or(WireGuardError::InvalidLength)?;
            let (ct, tag) = packet.encrypted_encapsulated_packet.split_at(pt_len);
            let tag: [u8; AEAD_SIZE] = tag.try_into().map_err(|_| WireGuardError::InvalidLength)?;
            let out = dst.get_mut(..pt_len).ok_or(WireGuardError::InvalidLength)?;
            out.copy_from_slice(ct);
            Aegis256X2::<16>::new(decrypt_key, &nonce)
                .decrypt_in_place(out, &tag, &[])
                .map_err(|_| WireGuardError::InvalidAeadTag)?;
            out
        };

        Ok(ret)
    }
}

#[inline(always)]
pub fn message_data_len(plain_text_len: usize) -> usize {
    // See:
    // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireguard/messages.h?h=v6.1#n112
    plain_text_len + AEAD_SIZE + DATA_OFFSET
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Interop gate: prove `rust-aegis` (the cipher NepTUN uses) produces the AEGIS-256X2 output
    /// mandated by IETF draft-irtf-cfrg-aegis-aead. These are the draft's official AEGIS-256X2
    /// Test Vector 1 and Test Vector 2 tags. The NordLynx kernel module's *implementation* is
    /// standard and produces these same bytes (verified by running its VAES code directly), so a
    /// NepTUN↔kernel-AEGIS256X2 tunnel agrees on the wire. (NB: the kernel's bundled
    /// `crypto/zinc/selftest/aegis256x2.c` has a mis-transcribed TV2 constant — `94a3bd44…`
    /// instead of the correct `635d3918…` — which makes the kernel's own self-test fail at load;
    /// that is a kernel-side test-vector bug, not a cipher incompatibility.) We mirror the kernel
    /// selftest shape: assert the tag, then a decrypt round-trip recovers the plaintext.
    #[test]
    fn aegis256x2_matches_ietf_vectors() {
        use aegis::aegis256x2::Aegis256X2;

        // Common key/nonce: key = 0x00..=0x1f, nonce = 0x10..=0x2f (draft AEGIS-256X2 vectors).
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut nonce = [0u8; 32];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (0x10 + i) as u8;
        }

        // tv1: empty AD, empty message — tag only.
        let mut buf: [u8; 0] = [];
        let tag = Aegis256X2::<16>::new(&key, &nonce).encrypt_in_place(&mut buf, &[]);
        assert_eq!(
            tag,
            [
                0x62, 0xcd, 0xba, 0xb0, 0x84, 0xc8, 0x3d, 0xac, 0xdb, 0x94, 0x5b, 0xb4, 0x46, 0xf0,
                0x49, 0xc8
            ],
            "tv1 tag mismatch (rust-aegis vs kernel)"
        );

        // tv2: 8-byte AD = 0102030401020304, 120-byte message = repeated 0x04 0x05 0x06 0x07.
        let ad: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04];
        let mut msg = [0u8; 120];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = (0x04 + (i % 4)) as u8;
        }
        let plaintext = msg;
        let tag2 = Aegis256X2::<16>::new(&key, &nonce).encrypt_in_place(&mut msg, &ad);
        assert_eq!(
            tag2,
            [
                0x63, 0x5d, 0x39, 0x18, 0x28, 0x52, 0x0b, 0xf1, 0x51, 0x27, 0x63, 0xf0, 0xc8, 0xf5,
                0xcd, 0xbd
            ],
            "tv2 tag mismatch (rust-aegis vs IETF draft)"
        );
        // Round-trip: decrypting the ciphertext with the same key/nonce/AD recovers the plaintext.
        Aegis256X2::<16>::new(&key, &nonce)
            .decrypt_in_place(&mut msg, &tag2, &ad)
            .expect("tv2 decrypt failed");
        assert_eq!(msg, plaintext, "tv2 round-trip plaintext mismatch");
    }

    /// AEGIS-256X2 transport round-trip through a real `Session` pair (encrypt with one, decrypt
    /// with the matching key on the peer).
    #[test]
    fn aegis256x2_session_roundtrip() {
        let key_a = [0x11u8; 32]; // A's sending == B's receiving
        let key_b = [0x22u8; 32]; // B's sending == A's receiving
        let a = Session::new(1, 2, key_b, key_a).unwrap();
        let b = Session::new(2, 1, key_a, key_b).unwrap();

        let payload = b"hello aegis transport";
        let mut buf = [0u8; 256];
        buf[DATA_OFFSET..DATA_OFFSET + payload.len()].copy_from_slice(payload);
        let packet = a.format_packet_data(payload.len(), &mut buf).unwrap().to_vec();

        // Data packets carry NO suite byte — header is `04 00 00 00`, matching the kernel.
        assert_eq!(&packet[..4], &[super::super::DATA as u8, 0, 0, 0]);

        let parsed = match super::super::Tunn::parse_incoming_packet(&packet).unwrap() {
            super::super::Packet::PacketData(p) => p,
            _ => panic!("expected data packet"),
        };
        let mut out = [0u8; 256];
        let plain = b.receive_packet_data(parsed, &mut out).unwrap();
        assert_eq!(plain, payload);
    }

    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
