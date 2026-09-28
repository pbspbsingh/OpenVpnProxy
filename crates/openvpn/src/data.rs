use crate::error::{Error, Result, require};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

pub const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

pub struct DataChannel {
    send: Aes256Gcm,
    recv: Aes256Gcm,
    send_iv: [u8; 8],
    recv_iv: [u8; 8],
    peer_id: u32,
    next_id: u32,
    highest_received: u32,
    received_window: u64,
}

impl DataChannel {
    pub fn new(key: &[u8; 256], peer_id: u32) -> Result<Self> {
        let mut send_iv = [0; 8];
        let mut recv_iv = [0; 8];
        send_iv.copy_from_slice(&key[64..72]);
        recv_iv.copy_from_slice(&key[192..200]);
        Ok(Self {
            send: Aes256Gcm::new_from_slice(&key[..32]).map_err(|_| Error::Crypto)?,
            recv: Aes256Gcm::new_from_slice(&key[128..160]).map_err(|_| Error::Crypto)?,
            send_iv,
            recv_iv,
            peer_id,
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
        let mut header = [0; 8];
        header[0] = 9 << 3;
        header[1] = (self.peer_id >> 16) as u8;
        header[2] = (self.peer_id >> 8) as u8;
        header[3] = self.peer_id as u8;
        header[4..8].copy_from_slice(&self.next_id.to_be_bytes());
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&header[4..8]);
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
        let tag_start = encrypted.len() - 16;
        let mut wire = header.to_vec();
        wire.extend_from_slice(&encrypted[tag_start..]);
        wire.extend_from_slice(&encrypted[..tag_start]);
        Ok(wire)
    }

    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        require(wire.len() >= 24 && wire[0] == 9 << 3, "invalid data packet")?;
        let incoming_peer_id = u32::from_be_bytes([0, wire[1], wire[2], wire[3]]);
        require(incoming_peer_id == self.peer_id, "wrong data peer ID")?;
        let id = u32::from_be_bytes(
            wire[4..8]
                .try_into()
                .map_err(|_| Error::Protocol("short data packet ID"))?,
        );
        require(id > 0, "invalid data packet ID")?;
        if id <= self.highest_received {
            let distance = self.highest_received - id;
            require(
                distance < 64 && self.received_window & (1_u64 << distance) == 0,
                "data replay",
            )
            .map_err(|_| Error::Replay)?;
        }
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&wire[4..8]);
        nonce[4..].copy_from_slice(&self.recv_iv);
        let mut encrypted = wire[24..].to_vec();
        encrypted.extend_from_slice(&wire[8..24]);
        let plain = self
            .recv
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &encrypted,
                    aad: &wire[..8],
                },
            )
            .map_err(|_| Error::DataAuthenticationFailed)?;
        if id > self.highest_received {
            let shift = id - self.highest_received;
            self.received_window = if shift >= 64 {
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
        let mut client = DataChannel::new(&key, 12).unwrap();
        let mut server = DataChannel::new(&key, 12).unwrap();
        std::mem::swap(&mut server.send, &mut server.recv);
        std::mem::swap(&mut server.send_iv, &mut server.recv_iv);
        let wire = client.encrypt(b"hello").unwrap();
        assert_eq!(server.decrypt(&wire).unwrap(), b"hello");
        assert!(server.decrypt(&wire).is_err());
    }
}
