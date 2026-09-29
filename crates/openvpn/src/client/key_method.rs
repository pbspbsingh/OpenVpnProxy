use std::time::{Duration, Instant};

use crate::control::Link;
use crate::error::{Error, Result, require};
use crate::protocol::MAX_CONTROL_FIELD_BYTES;

const KM2_PREFIX: [u8; 5] = [0, 0, 0, 0, 2];
const CLIENT_RANDOM_BYTES: usize = 112;
const SERVER_RANDOM_BYTES: usize = 64;
const SERVER_KM2_FIELD_COUNT: usize = 4;
const FIELD_LENGTH_BYTES: usize = 2;
const KEY_METHOD_TIMEOUT: Duration = Duration::from_secs(20);
const OCC_LINK_MTU_BYTES: usize = 1559;
const OCC_TUN_MTU_BYTES: usize = 1500;
const IV_PROTOCOL_FLAGS: u32 = 15;
const IV_NCP_VERSION: u8 = 2;
const IV_MTU_BYTES: usize = 1500;

pub(super) fn client_km2(username: &str, password: &str) -> Result<Vec<u8>> {
    let mut message = KM2_PREFIX.to_vec();
    let mut random = [0; CLIENT_RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(Error::Randomness)?;
    message.extend_from_slice(&random);
    field(
        &mut message,
        &format!(
            "V4,dev-type tun,link-mtu {OCC_LINK_MTU_BYTES},tun-mtu {OCC_TUN_MTU_BYTES},proto UDPv4,cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-client"
        ),
    )?;
    field(&mut message, username)?;
    field(&mut message, password)?;
    let platform = if cfg!(target_os = "macos") {
        "mac"
    } else {
        "linux"
    };
    field(
        &mut message,
        &format!(
            "IV_VER=2.6.0\nIV_PLAT={platform}\nIV_PROTO={IV_PROTOCOL_FLAGS}\nIV_NCP={IV_NCP_VERSION}\nIV_CIPHERS=AES-256-GCM\nIV_MTU={IV_MTU_BYTES}\n"
        ),
    )?;
    random.fill(0);
    Ok(message)
}

pub(super) fn take_server_km2(link: &mut Link) -> Result<bool> {
    if link.application_data().starts_with(b"AUTH_FAILED") {
        return Err(Error::AuthenticationFailed);
    }
    if let Some(len) = server_km2_len(link.application_data())? {
        link.application_data().drain(..len);
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(super) async fn read_server_km2(link: &mut Link) -> Result<()> {
    let deadline = Instant::now() + KEY_METHOD_TIMEOUT;
    loop {
        if take_server_km2(link)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout("server KEY_METHOD 2"));
        }
        link.step().await?;
    }
}

fn field(output: &mut Vec<u8>, value: &str) -> Result<()> {
    require(
        !value.contains('\0') && value.len() < u16::MAX as usize,
        "invalid control field",
    )?;
    output.extend_from_slice(&((value.len() + 1) as u16).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    output.push(0);
    Ok(())
}

fn read_field(buffer: &[u8], offset: &mut usize) -> Result<Option<()>> {
    if buffer.len() < *offset + FIELD_LENGTH_BYTES {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]) as usize;
    require(
        len <= MAX_CONTROL_FIELD_BYTES,
        "server control field too large",
    )?;
    if buffer.len() < *offset + FIELD_LENGTH_BYTES + len {
        return Ok(None);
    }
    if len > 0 {
        require(
            buffer[*offset + FIELD_LENGTH_BYTES - 1 + len] == 0,
            "server control field missing terminator",
        )?;
    }
    *offset += FIELD_LENGTH_BYTES + len;
    Ok(Some(()))
}

fn server_km2_len(buffer: &[u8]) -> Result<Option<usize>> {
    const PREFIX: usize = KM2_PREFIX.len() + SERVER_RANDOM_BYTES;
    if buffer.len() < PREFIX {
        return Ok(None);
    }
    require(
        buffer[..KM2_PREFIX.len()] == KM2_PREFIX,
        "invalid server KEY_METHOD 2",
    )?;
    let mut offset = PREFIX;
    for _ in 0..SERVER_KM2_FIELD_COUNT {
        if read_field(buffer, &mut offset)?.is_none() {
            return Ok(None);
        }
    }
    Ok(Some(offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_km2_waits_for_complete_fields() {
        let mut message = vec![0, 0, 0, 0, 2];
        message.extend_from_slice(&[0; 64]);
        for _ in 0..4 {
            message.extend_from_slice(&[0, 0]);
        }
        assert_eq!(server_km2_len(&message).unwrap(), Some(message.len()));
        assert_eq!(server_km2_len(&message[..message.len() - 1]).unwrap(), None);
    }
}
