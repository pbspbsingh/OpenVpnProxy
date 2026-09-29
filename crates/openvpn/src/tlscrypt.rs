use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::protocol::{REPLAY_WINDOW_BITS, STATIC_KEY_BYTES};

const AES_KEY_BYTES: usize = 32;
const HMAC_KEY_BYTES: usize = 32;
const KEY_DIRECTION_STRIDE: usize = 128;
const HMAC_KEY_OFFSET: usize = 64;
const OPCODE_BYTES: usize = 1;
const SESSION_ID_BYTES: usize = 8;
const PACKET_ID_BYTES: usize = 4;
const TIMESTAMP_BYTES: usize = 4;
const AUTH_TAG_BYTES: usize = 32;
const CTR_IV_BYTES: usize = 16;
const PACKET_ID_START: usize = OPCODE_BYTES + SESSION_ID_BYTES;
const TIMESTAMP_START: usize = PACKET_ID_START + PACKET_ID_BYTES;
const AUTH_TAG_START: usize = TIMESTAMP_START + TIMESTAMP_BYTES;
const CIPHERTEXT_START: usize = AUTH_TAG_START + AUTH_TAG_BYTES;

type AesCtr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub struct TlsCrypt {
    send_cipher: [u8; AES_KEY_BYTES],
    send_mac: [u8; HMAC_KEY_BYTES],
    recv_cipher: [u8; AES_KEY_BYTES],
    recv_mac: [u8; HMAC_KEY_BYTES],
    next_packet_id: u32,
    largest_received: u32,
    received_window: u64,
}

impl TlsCrypt {
    pub fn client(key: &[u8; STATIC_KEY_BYTES]) -> Self {
        let mut send_cipher = [0; AES_KEY_BYTES];
        let mut send_mac = [0; HMAC_KEY_BYTES];
        let mut recv_cipher = [0; AES_KEY_BYTES];
        let mut recv_mac = [0; HMAC_KEY_BYTES];
        send_cipher
            .copy_from_slice(&key[KEY_DIRECTION_STRIDE..KEY_DIRECTION_STRIDE + AES_KEY_BYTES]);
        send_mac.copy_from_slice(
            &key[KEY_DIRECTION_STRIDE + HMAC_KEY_OFFSET
                ..KEY_DIRECTION_STRIDE + HMAC_KEY_OFFSET + HMAC_KEY_BYTES],
        );
        recv_cipher.copy_from_slice(&key[..AES_KEY_BYTES]);
        recv_mac.copy_from_slice(&key[HMAC_KEY_OFFSET..HMAC_KEY_OFFSET + HMAC_KEY_BYTES]);
        Self {
            send_cipher,
            send_mac,
            recv_cipher,
            recv_mac,
            next_packet_id: 0,
            largest_received: 0,
            received_window: 0,
        }
    }

    pub fn wrap(&mut self, opcode: u8, session_id: u64, plain: &[u8]) -> Result<Vec<u8>> {
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .ok_or(Error::PacketIdExhausted)?;
        let mut packet = Vec::with_capacity(CIPHERTEXT_START + plain.len());
        packet.push(opcode);
        packet.extend_from_slice(&session_id.to_be_bytes());
        packet.extend_from_slice(&self.next_packet_id.to_be_bytes());
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Protocol("system clock before epoch"))?
            .as_secs() as u32;
        packet.extend_from_slice(&seconds.to_be_bytes());
        let mut mac = HmacSha256::new_from_slice(&self.send_mac).map_err(|_| Error::Crypto)?;
        mac.update(&packet);
        mac.update(plain);
        let tag = mac.finalize().into_bytes();
        packet.extend_from_slice(&tag);
        let mut cipher = plain.to_vec();
        AesCtr::new_from_slices(&self.send_cipher, &tag[..CTR_IV_BYTES])
            .map_err(|_| Error::Crypto)?
            .apply_keystream(&mut cipher);
        packet.extend_from_slice(&cipher);
        Ok(packet)
    }

    pub fn unwrap(&mut self, packet: &[u8]) -> Result<(u8, u64, Vec<u8>)> {
        if packet.len() < CIPHERTEXT_START {
            return Err(Error::Protocol("tls-crypt packet too short"));
        }
        let packet_id = u32::from_be_bytes(
            packet[PACKET_ID_START..TIMESTAMP_START]
                .try_into()
                .map_err(|_| Error::Protocol("bad packet ID"))?,
        );
        if packet_id == 0
            || (packet_id <= self.largest_received
                && (self.largest_received - packet_id >= REPLAY_WINDOW_BITS
                    || self.received_window & (1_u64 << (self.largest_received - packet_id)) != 0))
        {
            return Err(Error::Replay);
        }
        let tag = &packet[AUTH_TAG_START..CIPHERTEXT_START];
        let mut plain = packet[CIPHERTEXT_START..].to_vec();
        AesCtr::new_from_slices(&self.recv_cipher, &tag[..CTR_IV_BYTES])
            .map_err(|_| Error::Crypto)?
            .apply_keystream(&mut plain);
        let mut mac = HmacSha256::new_from_slice(&self.recv_mac).map_err(|_| Error::Crypto)?;
        mac.update(&packet[..AUTH_TAG_START]);
        mac.update(&plain);
        mac.verify_slice(tag)
            .map_err(|_| Error::ControlAuthenticationFailed)?;
        if packet_id > self.largest_received {
            let shift = packet_id - self.largest_received;
            self.received_window = if shift >= REPLAY_WINDOW_BITS {
                1
            } else {
                (self.received_window << shift) | 1
            };
            self.largest_received = packet_id;
        } else {
            self.received_window |= 1_u64 << (self.largest_received - packet_id);
        }
        let session_id = u64::from_be_bytes(
            packet[OPCODE_BYTES..PACKET_ID_START]
                .try_into()
                .map_err(|_| Error::Protocol("bad session ID"))?,
        );
        Ok((packet[0], session_id, plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_directions_interoperate() {
        let key = [7; 256];
        let mut client = TlsCrypt::client(&key);
        let mut server = TlsCrypt::client(&key);
        std::mem::swap(&mut server.send_cipher, &mut server.recv_cipher);
        std::mem::swap(&mut server.send_mac, &mut server.recv_mac);
        let wire = client.wrap(56, 123, b"control packet").unwrap();
        assert_eq!(server.unwrap(&wire).unwrap().2, b"control packet");
        assert!(server.unwrap(&wire).is_err());
    }
}
