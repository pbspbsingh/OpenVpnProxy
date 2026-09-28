use std::time::{Duration, Instant};

use crate::control::Link;
use crate::error::{Error, Result, require};

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

pub(super) fn client_km2(username: &str, password: &str) -> Result<Vec<u8>> {
    let mut message = vec![0, 0, 0, 0, 2];
    let mut random = [0; 112];
    getrandom::fill(&mut random).map_err(Error::Randomness)?;
    message.extend_from_slice(&random);
    field(
        &mut message,
        "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth SHA256,keysize 256,key-method 2,tls-client",
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
            "IV_VER=2.6.0\nIV_PLAT={platform}\nIV_PROTO=15\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM\nIV_MTU=1500\n"
        ),
    )?;
    random.fill(0);
    Ok(message)
}

fn read_field(buffer: &[u8], offset: &mut usize) -> Result<Option<()>> {
    if buffer.len() < *offset + 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]) as usize;
    require(len <= 16384, "server control field too large")?;
    if buffer.len() < *offset + 2 + len {
        return Ok(None);
    }
    if len > 0 {
        require(
            buffer[*offset + 1 + len] == 0,
            "server control field missing terminator",
        )?;
    }
    *offset += 2 + len;
    Ok(Some(()))
}

fn server_km2_len(buffer: &[u8]) -> Result<Option<usize>> {
    const PREFIX: usize = 5 + 64;
    if buffer.len() < PREFIX {
        return Ok(None);
    }
    require(
        buffer[..5] == [0, 0, 0, 0, 2],
        "invalid server KEY_METHOD 2",
    )?;
    let mut offset = PREFIX;
    for _ in 0..4 {
        if read_field(buffer, &mut offset)?.is_none() {
            return Ok(None);
        }
    }
    Ok(Some(offset))
}

pub(super) async fn read_server_km2(link: &mut Link) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(len) = server_km2_len(link.application_data())? {
            link.application_data().drain(..len);
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout("server KEY_METHOD 2"));
        }
        link.step().await?;
    }
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
