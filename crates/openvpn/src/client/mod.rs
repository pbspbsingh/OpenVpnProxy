mod key_method;
mod push;
mod tls;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use self::key_method::{client_km2, read_server_km2, take_server_km2};
use self::push::{parse_push, pushed_auth_token, read_push};
use self::tls::tls_client;
use crate::control::Link;
use crate::data::{DataChannel, PING};
use crate::error::{Error, Result, require};
use crate::protocol::{DATA_KEY_MATERIAL_BYTES, KEY_ID_MASK};

pub(crate) use self::tls::new_tls_connection;

const MIN_RESTART_INTERVAL: Duration = Duration::from_secs(15);
const MIN_PING_INTERVAL: Duration = Duration::from_secs(5);
const PEER_KEY_GRACE: Duration = Duration::from_secs(5);

/// Credentials and profile settings needed to open an OpenVPN session.
pub struct ClientConfig<'a> {
    pub endpoint: SocketAddr,
    pub ca_pem: &'a str,
    pub tls_crypt_key: &'a [u8; crate::protocol::STATIC_KEY_BYTES],
    pub require_server_certificate_purpose: bool,
    pub renegotiate_after: Option<Duration>,
    pub handshake_window: Duration,
    pub transition_window: Duration,
}

/// Settings negotiated with the VPN server for one session.
pub struct SessionConfig {
    pub tunnel: TunnelSettings,
}

/// IP settings pushed by the VPN server.
#[derive(Clone, Debug)]
pub struct TunnelSettings {
    pub local: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Vec<IpAddr>,
    pub mtu: usize,
    pub ipv6: Option<Ipv6TunnelSettings>,
}

/// IPv6 address and routes pushed by the VPN server.
#[derive(Clone, Debug)]
pub struct Ipv6TunnelSettings {
    pub local: Ipv6Addr,
    pub prefix_len: u8,
    pub routes: Vec<Ipv6Route>,
}

/// IPv6 route pushed by the VPN server.
#[derive(Clone, Debug)]
pub struct Ipv6Route {
    pub network: Ipv6Addr,
    pub prefix_len: u8,
    pub gateway: Ipv6Addr,
}

/// One encrypted OpenVPN control and data session.
pub struct Session {
    link: Link,
    data: DataChannel,
    previous_data: Option<(DataChannel, Instant)>,
    pending_data: Option<DataChannel>,
    peer_new_key_seen: bool,
    rekey: Option<RekeyState>,
    renegotiate_after: Option<Duration>,
    handshake_window: Duration,
    transition_window: Duration,
    key_established_at: Instant,
    username: String,
    password: String,
    auth_token: Option<String>,
    auth_token_user: Option<String>,
    config: SessionConfig,
    ping_interval: Duration,
    restart_interval: Duration,
    last_ping: Instant,
    last_data: Instant,
}

#[derive(Clone, Copy, Debug)]
enum RekeyState {
    Tls {
        started: Instant,
    },
    ServerKey {
        started: Instant,
    },
    ControlAck {
        started: Instant,
    },
    PeerKey {
        started: Instant,
        synchronized_at: Instant,
    },
}

impl RekeyState {
    fn started(self) -> Instant {
        match self {
            Self::Tls { started }
            | Self::ServerKey { started }
            | Self::ControlAck { started }
            | Self::PeerKey { started, .. } => started,
        }
    }
}

impl Session {
    /// Connects to the configured VPN endpoint and negotiates tunnel settings.
    pub async fn connect(
        profile: &ClientConfig<'_>,
        username: &str,
        password: &str,
    ) -> Result<Self> {
        tracing::debug!(endpoint = %profile.endpoint, "opening OpenVPN UDP session");
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(profile.endpoint).await?;
        let tls_config = tls_client(profile)?;
        let mut link = Link::new(
            socket,
            profile.tls_crypt_key,
            new_tls_connection(&tls_config)?,
            tls_config,
        )
        .await?;
        link.handshake(profile.handshake_window).await?;
        tracing::debug!("exchanging OpenVPN key method 2 messages");
        let mut km2 = client_km2(username, password)?;
        let send_result = link.write_app(&km2).await;
        km2.fill(0);
        send_result?;
        read_server_km2(&mut link).await?;
        link.write_app(b"PUSH_REQUEST\0").await?;
        let push = read_push(&mut link).await?;
        let (tunnel, peer_id, ping_interval, restart_interval) = parse_push(&push)?;
        let pushed_auth = pushed_auth_token(&push)?;
        tracing::debug!(peer_id, local = %tunnel.local, gateway = %tunnel.gateway, mtu = tunnel.mtu, dns_servers = tunnel.dns.len(), ipv6_routes = tunnel.ipv6.as_ref().map_or(0, |ipv6| ipv6.routes.len()), ?ping_interval, ?restart_interval, "OpenVPN server settings accepted");
        let mut key = [0; DATA_KEY_MATERIAL_BYTES];
        link.tls()
            .export_keying_material(&mut key, b"EXPORTER-OpenVPN-datakeys", None)?;
        let data_result = DataChannel::new(&key, peer_id, link.key_id());
        key.fill(0);
        let data = data_result?;
        tracing::info!("OpenVPN control and data channels established");
        Ok(Self {
            link,
            data,
            previous_data: None,
            pending_data: None,
            peer_new_key_seen: false,
            rekey: None,
            renegotiate_after: profile.renegotiate_after,
            handshake_window: profile.handshake_window,
            transition_window: profile.transition_window,
            key_established_at: Instant::now(),
            username: username.to_owned(),
            password: password.to_owned(),
            auth_token: pushed_auth.as_ref().map(|(token, _)| token.clone()),
            auth_token_user: pushed_auth.and_then(|(_, user)| user),
            config: SessionConfig { tunnel },
            ping_interval,
            restart_interval,
            last_ping: Instant::now(),
            last_data: Instant::now(),
        })
    }

    /// Returns settings negotiated with the VPN server.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Encrypts and sends an IP packet through the VPN session.
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.progress_rekey().await?;
        let wire = self.data.encrypt(packet)?;
        tracing::trace!(
            plain_bytes = packet.len(),
            wire_bytes = wire.len(),
            "sending encrypted OpenVPN data"
        );
        let sent = self.link.socket().send(&wire).await?;
        require(sent == wire.len(), "short VPN UDP send")
    }

    /// Advances the session and returns a decrypted IP packet when available.
    pub async fn step(&mut self) -> Result<Option<Vec<u8>>> {
        self.progress_rekey().await?;
        if self.link.last_received().max(self.last_data).elapsed()
            >= self.restart_interval.max(MIN_RESTART_INTERVAL)
        {
            return Err(Error::Timeout("server stopped responding"));
        }
        if self.last_ping.elapsed() >= self.ping_interval.max(MIN_PING_INTERVAL) {
            tracing::debug!("sending OpenVPN keepalive ping");
            self.send_packet(&PING).await?;
            self.last_ping = Instant::now();
        }
        let packet = match self.link.step().await? {
            Some(wire) => match self.decrypt_packet(&wire) {
                Ok(plain) => {
                    self.last_data = Instant::now();
                    tracing::trace!(
                        key_id = wire[0] & KEY_ID_MASK,
                        plain_bytes = plain.len(),
                        "decrypted OpenVPN data"
                    );
                    if plain == PING { None } else { Some(plain) }
                }
                Err(
                    error @ (Error::Replay | Error::DataAuthenticationFailed | Error::Protocol(_)),
                ) => {
                    tracing::debug!(%error, "discarded invalid OpenVPN data packet");
                    None
                }
                Err(error) => return Err(error),
            },
            None => None,
        };
        self.progress_rekey().await?;
        self.read_control_events()?;
        Ok(packet)
    }

    fn decrypt_packet(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        let key_id = wire
            .first()
            .map(|op| op & KEY_ID_MASK)
            .ok_or(Error::Protocol("empty data packet"))?;
        if key_id == self.data.key_id() {
            self.data.decrypt(wire)
        } else if let Some(next) = &mut self.pending_data {
            if key_id == next.key_id() {
                let plain = next.decrypt(wire)?;
                self.peer_new_key_seen = true;
                Ok(plain)
            } else if let Some((old, _)) = &mut self.previous_data {
                if key_id == old.key_id() {
                    old.decrypt(wire)
                } else {
                    Err(Error::Protocol("inactive data key ID"))
                }
            } else {
                Err(Error::Protocol("inactive data key ID"))
            }
        } else if let Some((old, _)) = &mut self.previous_data {
            if key_id == old.key_id() {
                old.decrypt(wire)
            } else {
                Err(Error::Protocol("inactive data key ID"))
            }
        } else {
            Err(Error::Protocol("inactive data key ID"))
        }
    }

    async fn progress_rekey(&mut self) -> Result<()> {
        if self
            .previous_data
            .as_ref()
            .is_some_and(|(_, expires)| Instant::now() >= *expires)
        {
            self.previous_data = None;
        }
        if self.link.next().is_none()
            && self.rekey.is_none()
            && (self.data.needs_rekey()
                || self
                    .renegotiate_after
                    .is_some_and(|interval| self.key_established_at.elapsed() >= interval))
        {
            self.link.begin_renegotiation().await?;
        }
        if self.link.next().is_some() && self.rekey.is_none() {
            self.rekey = Some(RekeyState::Tls {
                started: Instant::now(),
            });
        }
        let Some(state) = self.rekey else {
            return Ok(());
        };
        if !matches!(state, RekeyState::PeerKey { .. })
            && state.started().elapsed() >= self.handshake_window
        {
            return Err(Error::Timeout("OpenVPN key renegotiation"));
        }
        match state {
            RekeyState::Tls { started } => {
                let next = self
                    .link
                    .next()
                    .ok_or(Error::Protocol("missing renegotiating control channel"))?;
                if next.tls().is_handshaking() {
                    return Ok(());
                }
                next.activate_tls()?;
                let mut km2 = client_km2(
                    self.auth_token_user.as_deref().unwrap_or(&self.username),
                    self.auth_token.as_deref().unwrap_or(&self.password),
                )?;
                let sent = next.write_app(&km2).await;
                km2.fill(0);
                sent?;
                self.rekey = Some(RekeyState::ServerKey { started });
                tracing::debug!(
                    key_id = next.key_id(),
                    "OpenVPN replacement TLS channel established"
                );
            }
            RekeyState::ServerKey { .. } => {
                let next = self
                    .link
                    .next()
                    .ok_or(Error::Protocol("missing renegotiating control channel"))?;
                if !take_server_km2(next)? {
                    return Ok(());
                }
                let mut key = [0; DATA_KEY_MATERIAL_BYTES];
                let key_result =
                    next.tls()
                        .export_keying_material(&mut key, b"EXPORTER-OpenVPN-datakeys", None);
                if let Err(error) = key_result {
                    key.fill(0);
                    return Err(Error::Tls(error));
                }
                let data_result = DataChannel::new(&key, self.data.peer_id(), next.key_id());
                key.fill(0);
                self.pending_data = Some(data_result?);
                self.rekey = Some(RekeyState::ControlAck {
                    started: state.started(),
                });
                tracing::debug!(
                    key_id = next.key_id(),
                    "OpenVPN replacement key material accepted"
                );
            }
            RekeyState::ControlAck { .. } => {
                let next = self
                    .link
                    .next()
                    .ok_or(Error::Protocol("missing renegotiating control channel"))?;
                if !next.control_synchronized() {
                    return Ok(());
                }
                let key_id = next.key_id();
                let wire = self
                    .pending_data
                    .as_mut()
                    .ok_or(Error::Protocol("missing replacement data key"))?
                    .encrypt(&PING)?;
                let sent = self.link.socket().send(&wire).await?;
                require(sent == wire.len(), "short VPN UDP send")?;
                self.rekey = Some(RekeyState::PeerKey {
                    started: state.started(),
                    synchronized_at: Instant::now(),
                });
                tracing::debug!(key_id, "waiting for server to use replacement data key");
            }
            RekeyState::PeerKey {
                synchronized_at, ..
            } => {
                let wait = self
                    .ping_interval
                    .saturating_add(PEER_KEY_GRACE)
                    .min(self.handshake_window)
                    .min(self.transition_window);
                if !self.peer_new_key_seen && synchronized_at.elapsed() < wait {
                    return Ok(());
                }
                let replacement = self
                    .pending_data
                    .take()
                    .ok_or(Error::Protocol("missing replacement data key"))?;
                let old = std::mem::replace(&mut self.data, replacement);
                let expires = state
                    .started()
                    .checked_add(self.transition_window)
                    .ok_or(Error::Protocol("invalid OpenVPN transition window"))?;
                self.previous_data = Some((old, expires));
                self.link.promote_next()?;
                self.rekey = None;
                self.peer_new_key_seen = false;
                self.key_established_at = Instant::now();
                tracing::info!(key_id = self.link.key_id(), "OpenVPN data key rotated");
            }
        }
        Ok(())
    }

    fn read_control_events(&mut self) -> Result<()> {
        while let Some(index) = self
            .link
            .application_data()
            .iter()
            .position(|byte| *byte == 0)
        {
            let message = self
                .link
                .application_data()
                .drain(..=index)
                .collect::<Vec<_>>();
            let message = std::str::from_utf8(&message[..index])
                .map_err(|_| Error::Protocol("invalid control event text"))?;
            if message.starts_with("AUTH_FAILED") {
                return Err(Error::AuthenticationFailed);
            }
            if message.starts_with("PUSH_REPLY,") {
                require(
                    message.split(',').skip(1).all(|item| {
                        let item = item.trim();
                        item.starts_with("auth-token ") || item.starts_with("auth-token-user ")
                    }),
                    "unsupported in-session PUSH_REPLY",
                )?;
                if let Some((token, user)) = pushed_auth_token(message)? {
                    self.auth_token = Some(token);
                    self.auth_token_user = user;
                }
            } else {
                return Err(Error::Protocol("server sent unsupported control event"));
            }
        }
        Ok(())
    }
}
