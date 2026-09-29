use crate::error::{Error, Result, require};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::protocol::{
    DATA_KEY_MATERIAL_BYTES, DATA_V2_OPCODE, GCM_TAG_BYTES, MAX_KEY_ID, REPLAY_WINDOW_BITS,
};

const CIPHER_KEY_BYTES: usize = 32;
const IV_BYTES: usize = 8;
const DATA_HEADER_BYTES: usize = 8;
const GCM_NONCE_BYTES: usize = 12;
const PEER_ID_BYTES: usize = 3;
const REKEY_PACKET_ID_THRESHOLD: u32 = 0xff00_0000;

pub const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

pub struct DataChannel {
    send: Aes256Gcm,
    recv: Aes256Gcm,
    send_iv: [u8; IV_BYTES],
    recv_iv: [u8; IV_BYTES],
    peer_id: u32,
    key_id: u8,
    next_id: u32,
    highest_received: u32,
    received_window: u64,
}

impl DataChannel {
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    pub fn peer_id(&self) -> u32 {
        self.peer_id
    }

    pub fn needs_rekey(&self) -> bool {
        self.next_id >= REKEY_PACKET_ID_THRESHOLD
            || self.highest_received >= REKEY_PACKET_ID_THRESHOLD
    }

    pub fn new(key: &[u8; DATA_KEY_MATERIAL_BYTES], peer_id: u32, key_id: u8) -> Result<Self> {
        require(key_id <= MAX_KEY_ID, "invalid data key ID")?;
        let mut send_iv = [0; IV_BYTES];
        let mut recv_iv = [0; IV_BYTES];
        send_iv.copy_from_slice(&key[2 * CIPHER_KEY_BYTES..2 * CIPHER_KEY_BYTES + IV_BYTES]);
        recv_iv.copy_from_slice(
            &key[DATA_KEY_MATERIAL_BYTES / 2 + 2 * CIPHER_KEY_BYTES
                ..DATA_KEY_MATERIAL_BYTES / 2 + 2 * CIPHER_KEY_BYTES + IV_BYTES],
        );
        Ok(Self {
            send: Aes256Gcm::new_from_slice(&key[..CIPHER_KEY_BYTES]).map_err(|_| Error::Crypto)?,
            recv: Aes256Gcm::new_from_slice(
                &key[DATA_KEY_MATERIAL_BYTES / 2..DATA_KEY_MATERIAL_BYTES / 2 + CIPHER_KEY_BYTES],
            )
            .map_err(|_| Error::Crypto)?,
            send_iv,
            recv_iv,
            peer_id,
            key_id,
            next_id: 0,
            highest_received: 0,
            received_window: 0,
        })
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(Error::PacketIdExhausted)?;
        let mut header = [0; DATA_HEADER_BYTES];
        header[0] = (DATA_V2_OPCODE << crate::protocol::OPCODE_SHIFT) | self.key_id;
        header[1..=PEER_ID_BYTES].copy_from_slice(&self.peer_id.to_be_bytes()[1..]);
        header[PEER_ID_BYTES + 1..DATA_HEADER_BYTES].copy_from_slice(&self.next_id.to_be_bytes());
        let mut nonce = [0; GCM_NONCE_BYTES];
        nonce[..4].copy_from_slice(&header[PEER_ID_BYTES + 1..DATA_HEADER_BYTES]);
        nonce[4..].copy_from_slice(&self.send_iv);
        let encrypted = self
            .send
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Crypto)?;
        let tag_start = encrypted.len() - GCM_TAG_BYTES;
        let mut wire = header.to_vec();
        wire.extend_from_slice(&encrypted[tag_start..]);
        wire.extend_from_slice(&encrypted[..tag_start]);
        Ok(wire)
    }

    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        require(
            wire.len() >= DATA_HEADER_BYTES + GCM_TAG_BYTES
                && wire[0] == (DATA_V2_OPCODE << crate::protocol::OPCODE_SHIFT) | self.key_id,
            "invalid data packet",
        )?;
        let incoming_peer_id = u32::from_be_bytes([0, wire[1], wire[2], wire[3]]);
        require(incoming_peer_id == self.peer_id, "wrong data peer ID")?;
        let id = u32::from_be_bytes(
            wire[PEER_ID_BYTES + 1..DATA_HEADER_BYTES]
                .try_into()
                .map_err(|_| Error::Protocol("short data packet ID"))?,
        );
        require(id > 0, "invalid data packet ID")?;
        if id <= self.highest_received {
            let distance = self.highest_received - id;
            require(
                distance < REPLAY_WINDOW_BITS && self.received_window & (1_u64 << distance) == 0,
                "data replay",
            )
            .map_err(|_| Error::Replay)?;
        }
        let mut nonce = [0; GCM_NONCE_BYTES];
        nonce[..4].copy_from_slice(&wire[PEER_ID_BYTES + 1..DATA_HEADER_BYTES]);
        nonce[4..].copy_from_slice(&self.recv_iv);
        let mut encrypted = wire[DATA_HEADER_BYTES + GCM_TAG_BYTES..].to_vec();
        encrypted.extend_from_slice(&wire[DATA_HEADER_BYTES..DATA_HEADER_BYTES + GCM_TAG_BYTES]);
        let plain = self
            .recv
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &encrypted,
                    aad: &wire[..DATA_HEADER_BYTES],
                },
            )
            .map_err(|_| Error::DataAuthenticationFailed)?;
        if id > self.highest_received {
            let shift = id - self.highest_received;
            self.received_window = if shift >= REPLAY_WINDOW_BITS {
                1
            } else {
                self.received_window << shift | 1
            };
            self.highest_received = id;
        } else {
            self.received_window |= 1_u64 << (self.highest_received - id);
        }
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_channel_round_trip_and_replay() {
        let key = [3; 256];
        let mut client = DataChannel::new(&key, 12, 0).unwrap();
        let mut server = DataChannel::new(&key, 12, 0).unwrap();
        std::mem::swap(&mut server.send, &mut server.recv);
        std::mem::swap(&mut server.send_iv, &mut server.recv_iv);
        let wire = client.encrypt(b"hello").unwrap();
        assert_eq!(server.decrypt(&wire).unwrap(), b"hello");
        assert!(server.decrypt(&wire).is_err());
        let mut rotated = DataChannel::new(&key, 12, 1).unwrap();
        assert!(rotated.decrypt(&wire).is_err());
        assert_eq!(rotated.encrypt(b"rotated").unwrap()[0] & 7, 1);
    }
}
