//! Authenticated DNS over TLS over either host or tunneled TCP streams.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::Instrument;

pub const DEFAULT_SERVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const QUERY_TIMEOUT: Duration = Duration::from_secs(12);
// VPN discovery accepts up to 64 endpoints; destination policy can retain fewer.
const MAX_ANSWERS: usize = 64;
const CONNECTIONS_PER_FAMILY: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

/// An explicit IP avoids plaintext bootstrap DNS. TLS verifies the supplied
/// hostname, or the IP certificate identity when no hostname is supplied.
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    address: Ipv4Addr,
    server_name: ServerName<'static>,
}

impl ResolverConfig {
    pub fn new(address: Option<Ipv4Addr>, tls_name: Option<&str>) -> Result<Self, Error> {
        let address = address.unwrap_or(DEFAULT_SERVER);
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            return Err(Error::InvalidConfig);
        }
        let server_name = match tls_name {
            Some(name) => {
                ServerName::try_from(name.to_owned()).map_err(|_| Error::InvalidConfig)?
            }
            None => ServerName::IpAddress(IpAddr::V4(address).into()),
        };
        Ok(Self {
            address,
            server_name,
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        SocketAddr::new(self.address.into(), 853)
    }
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self::new(None, None).expect("valid default DNS resolver")
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid DNS resolver IP or TLS server name")]
    InvalidConfig,
    #[error("DNS over TLS timed out")]
    Timeout,
    #[error("DNS over TLS I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("DNS protocol error: {0}")]
    Protocol(String),
    #[error("DNS returned no address")]
    NoAddress,
}

struct ConnectionPool<S> {
    idle: Mutex<Vec<TlsStream<S>>>,
    permits: Semaphore,
}

impl<S> Default for ConnectionPool<S> {
    fn default() -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
            permits: Semaphore::new(CONNECTIONS_PER_FAMILY),
        }
    }
}

/// Bounded TLS pools keep concurrent lookups and A/AAAA independent.
/// The caller supplies TCP creation, so this client cannot bypass tunnel policy.
pub struct Client<S> {
    config: ResolverConfig,
    tls: TlsConnector,
    connections: [ConnectionPool<S>; 2],
    next_id: AtomicU16,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    pub fn new(config: ResolverConfig) -> Self {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self::with_tls(config, tls)
    }

    fn with_tls(config: ResolverConfig, tls: ClientConfig) -> Self {
        Self {
            config,
            tls: TlsConnector::from(Arc::new(tls)),
            connections: [ConnectionPool::default(), ConnectionPool::default()],
            next_id: AtomicU16::new(0),
        }
    }

    pub async fn resolve<F, Fut>(
        &self,
        host: &str,
        version: IpVersion,
        connect: F,
    ) -> Result<Vec<IpAddr>, Error>
    where
        F: Fn(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<S>>,
    {
        let query_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let span = tracing::info_span!("dns_query", query_id, host, ?version,
            resolver = %self.config.endpoint(), tls_name = ?self.config.server_name);
        self.resolve_query(host, version, connect, query_id)
            .instrument(span)
            .await
    }

    async fn resolve_query<F, Fut>(
        &self,
        host: &str,
        version: IpVersion,
        connect: F,
        query_id: u16,
    ) -> Result<Vec<IpAddr>, Error>
    where
        F: Fn(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<S>>,
    {
        let mut progress = QueryProgress {
            stage: "encode",
            started: Instant::now(),
            finished: false,
        };
        tracing::info!(
            timeout_ms = QUERY_TIMEOUT.as_millis() as u64,
            "DNS over TLS query started"
        );
        let result = tokio::time::timeout(QUERY_TIMEOUT, async {
            let record_type = match version {
                IpVersion::V4 => RecordType::A,
                IpVersion::V6 => RecordType::AAAA,
            };
            let mut name = Name::from_utf8(host).map_err(protocol)?;
            name.set_fqdn(true);
            let mut request = Message::new(
                query_id,
                MessageType::Query,
                OpCode::Query,
            );
            request.metadata.recursion_desired = true;
            request.queries.push(Query::query(name, record_type));
            let pool = &self.connections[usize::from(version == IpVersion::V6)];
            progress.stage = "pool_wait";
            let queued = Instant::now();
            let _permit = pool.permits.acquire().await.expect("DNS pool stays open");
            tracing::info!(pool_wait_ms = queued.elapsed().as_millis() as u64,
                available_connections = pool.permits.available_permits(), "DNS connection pool acquired");
            // Taking the stream out ensures cancellation drops partially read/written
            // messages instead of returning a desynchronized connection to the pool.
            let mut stream = pool.idle.lock().await.pop();
            let reused = stream.is_some();
            tracing::info!(reused, "DNS TLS connection selected");
            for attempt in 0..2 {
                let mut stream = match stream.take() {
                    Some(stream) => stream,
                    None => {
                        progress.stage = "tcp_connect";
                        let connected = Instant::now();
                        tracing::info!("DoT TCP connection starting");
                        let tcp = connect(self.config.endpoint()).await?;
                        tracing::info!(elapsed_ms = connected.elapsed().as_millis() as u64, "DoT TCP connected");
                        progress.stage = "tls_handshake";
                        let handshake = Instant::now();
                        tracing::info!("DoT TLS handshake starting");
                        let tls = self.tls
                            .connect(self.config.server_name.clone(), tcp)
                            .await?;
                        tracing::info!(elapsed_ms = handshake.elapsed().as_millis() as u64,
                            protocol = ?tls.get_ref().1.protocol_version(), "DoT TLS certificate verified");
                        tls
                    }
                };
                match exchange(&mut stream, &request, &mut progress).await {
                    Ok(response) => {
                        progress.stage = "validate_response";
                        tracing::info!(response_code = %response.metadata.response_code,
                            answer_records = response.answers.len(), "DNS response received");
                        let result = addresses(&request, &response);
                        if result.is_ok() || matches!(result, Err(Error::NoAddress)) {
                            pool.idle.lock().await.push(stream);
                        }
                        return result;
                    }
                    Err(Error::Io(error)) if reused && attempt == 0 => {
                        tracing::warn!(%error, stage = progress.stage, "Stale DoT connection discarded; reconnecting once");
                    }
                    Err(error) => return Err(error),
                }
            }
            unreachable!("a fresh connection is never retried")
        })
        .await
        .map_err(|_| Error::Timeout).and_then(|result| result);
        progress.finished = true;
        match &result {
            Ok(addresses) => tracing::info!(
                ?addresses,
                elapsed_ms = progress.started.elapsed().as_millis() as u64,
                "DNS query completed"
            ),
            Err(error) => tracing::warn!(%error, error_chain = ?error, stage = progress.stage,
                elapsed_ms = progress.started.elapsed().as_millis() as u64, "DNS query failed"),
        }
        result
    }
}

struct QueryProgress {
    stage: &'static str,
    started: Instant,
    finished: bool,
}

impl Drop for QueryProgress {
    fn drop(&mut self) {
        if !self.finished {
            tracing::info!(
                stage = self.stage,
                elapsed_ms = self.started.elapsed().as_millis() as u64,
                "DNS query cancelled"
            );
        }
    }
}

fn protocol(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &Message,
    progress: &mut QueryProgress,
) -> Result<Message, Error> {
    let message = request.to_vec().map_err(protocol)?;
    let length = u16::try_from(message.len()).map_err(protocol)?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&message);
    progress.stage = "write_query";
    stream.write_all(&frame).await?;
    stream.flush().await?;
    progress.stage = "read_response_length";
    let length = stream.read_u16().await? as usize;
    if length < 12 {
        return Err(protocol("short DNS response"));
    }
    let mut response = vec![0; length];
    progress.stage = "read_response_body";
    stream.read_exact(&mut response).await?;
    progress.stage = "decode_response";
    Message::from_vec(&response).map_err(protocol)
}

fn addresses(request: &Message, response: &Message) -> Result<Vec<IpAddr>, Error> {
    if response.metadata.id != request.metadata.id
        || response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.metadata.truncation
        || response.queries != request.queries
    {
        return Err(protocol("DNS response does not match query"));
    }
    match response.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Err(Error::NoAddress),
        code => return Err(protocol(format!("DNS response code {code}"))),
    }
    let query = &request.queries[0];
    let mut names = vec![query.name().clone()];
    // Follow only aliases rooted in the question; reject unrelated answer records.
    for _ in 0..response.answers.len() {
        let mut changed = false;
        for record in &response.answers {
            if record.dns_class == DNSClass::IN
                && names.contains(&record.name)
                && let RData::CNAME(alias) = &record.data
                && !names.contains(&alias.0)
            {
                if names.len() == 32 {
                    return Err(protocol("DNS alias chain is too long"));
                }
                names.push(alias.0.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut answers = Vec::new();
    for record in &response.answers {
        if record.dns_class != DNSClass::IN || !names.contains(&record.name) {
            continue;
        }
        let address = match (&record.data, query.query_type()) {
            (RData::A(address), RecordType::A) => IpAddr::V4(address.0),
            (RData::AAAA(address), RecordType::AAAA) => IpAddr::V6(address.0),
            _ => continue,
        };
        if !answers.contains(&address) {
            answers.push(address);
        }
        if answers.len() == MAX_ANSWERS {
            break;
        }
    }
    if answers.is_empty() {
        Err(Error::NoAddress)
    } else {
        Ok(answers)
    }
}

#[cfg(test)]
mod tests;
