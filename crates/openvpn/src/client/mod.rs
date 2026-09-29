mod key_method;
mod push;
mod tls;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use self::key_method::{client_km2, read_server_km2};
use self::push::{parse_push, read_push};
use self::tls::tls_client;
use crate::control::Link;
use crate::data::{DataChannel, PING};
use crate::error::{Error, Result, require};

pub struct ClientConfig<'a> {
    pub endpoint: SocketAddr,
    pub ca_pem: &'a str,
    pub tls_crypt_key: &'a [u8; 256],
}

pub struct SessionConfig {
    pub tunnel: TunnelSettings,
}

#[derive(Clone, Debug)]
pub struct TunnelSettings {
    pub local: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub mtu: usize,
}

pub struct Session {
    link: Link,
    data: DataChannel,
    config: SessionConfig,
    ping_interval: Duration,
    restart_interval: Duration,
    last_ping: Instant,
    last_data: Instant,
}

impl Session {
    pub async fn connect(
        profile: &ClientConfig<'_>,
        username: &str,
        password: &str,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(profile.endpoint).await?;
        let mut link = Link::new(socket, profile.tls_crypt_key, tls_client(profile)?).await?;
        link.handshake().await?;
        let mut km2 = client_km2(username, password)?;
        let send_result = link.write_app(&km2).await;
        km2.fill(0);
        send_result?;
        read_server_km2(&mut link).await?;
        link.write_app(b"PUSH_REQUEST\0").await?;
        let push = read_push(&mut link).await?;
        let (tunnel, peer_id, ping_interval, restart_interval) = parse_push(&push)?;
        let mut key = [0; 256];
        link.tls()
            .export_keying_material(&mut key, b"EXPORTER-OpenVPN-datakeys", None)?;
        let data_result = DataChannel::new(&key, peer_id);
        key.fill(0);
        let data = data_result?;
        tracing::info!("OpenVPN control and data channels established");
        Ok(Self {
            link,
            data,
            config: SessionConfig { tunnel },
            ping_interval,
            restart_interval,
            last_ping: Instant::now(),
            last_data: Instant::now(),
        })
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        let wire = self.data.encrypt(packet)?;
        let sent = self.link.socket().send(&wire).await?;
        require(sent == wire.len(), "short VPN UDP send")
    }

    pub async fn step(&mut self) -> Result<Option<Vec<u8>>> {
        if self.link.last_received().max(self.last_data).elapsed()
            >= self.restart_interval.max(Duration::from_secs(15))
        {
            return Err(Error::Timeout("server stopped responding"));
        }
        if self.last_ping.elapsed() >= self.ping_interval.max(Duration::from_secs(5)) {
            self.send_packet(&PING).await?;
            self.last_ping = Instant::now();
        }
        let packet = match self.link.step().await? {
            Some(wire) => match self.data.decrypt(&wire) {
                Ok(plain) => {
                    self.last_data = Instant::now();
                    if plain == PING { None } else { Some(plain) }
                }
                Err(Error::Replay | Error::DataAuthenticationFailed | Error::Protocol(_)) => None,
                Err(error) => return Err(error),
            },
            None => None,
        };
        if !self.link.application_data().is_empty() {
            return Err(Error::Protocol(
                "server sent a control event; reconnect required",
            ));
        }
        Ok(packet)
    }
}
