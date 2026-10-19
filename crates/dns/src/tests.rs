use super::*;
use hickory_proto::rr::{
    Record,
    rdata::{A, AAAA, CNAME},
};
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::sync::atomic::AtomicUsize;
use tokio::io::{DuplexStream, duplex};
use tokio_rustls::TlsAcceptor;

fn fixture(name: &str) -> (Client<DuplexStream>, TlsAcceptor) {
    let key = rcgen::generate_simple_self_signed(vec!["resolver.test".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(key.cert.der().clone()).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    (
        Client::with_tls(ResolverConfig::new(None, Some(name)).unwrap(), client),
        TlsAcceptor::from(Arc::new(server)),
    )
}

async fn read_query<S: AsyncRead + Unpin>(stream: &mut S) -> Message {
    let length = stream.read_u16().await.unwrap() as usize;
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.unwrap();
    Message::from_vec(&bytes).unwrap()
}

fn answer(request: &Message) -> Message {
    let mut response = request.clone();
    response.metadata.message_type = MessageType::Response;
    let query = &request.queries[0];
    for index in 1..=2 {
        let data = match query.query_type() {
            RecordType::AAAA => RData::AAAA(AAAA(format!("2001:db8::{index}").parse().unwrap())),
            _ => RData::A(A(Ipv4Addr::new(192, 0, 2, index))),
        };
        response
            .answers
            .push(Record::from_rdata(query.name().clone(), 60, data));
    }
    response
}

async fn write_answer<S: AsyncWrite + Unpin>(stream: &mut S, response: &Message) {
    let bytes = response.to_vec().unwrap();
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();
}

#[tokio::test]
async fn verified_tls_reuses_connections_and_retains_multiple_answers() {
    let (client, acceptor) = fixture("resolver.test");
    let connections = AtomicUsize::new(0);
    for host in ["example.com", "other.example"] {
        let result = client
            .resolve(host, IpVersion::V4, |address| {
                assert_eq!(address, "1.1.1.1:853".parse().unwrap());
                connections.fetch_add(1, Ordering::Relaxed);
                let (client, server) = duplex(4096);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut tls = acceptor.accept(server).await.unwrap();
                    for _ in 0..2 {
                        let request = read_query(&mut tls).await;
                        write_answer(&mut tls, &answer(&request)).await;
                    }
                });
                async move { Ok(client) }
            })
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse().unwrap()
            ]
        );
    }
    assert_eq!(connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn wrong_certificate_identity_fails_without_fallback() {
    let (client, acceptor) = fixture("wrong.test");
    let connections = AtomicUsize::new(0);
    let result = client
        .resolve("example.com", IpVersion::V4, |_| {
            connections.fetch_add(1, Ordering::Relaxed);
            let (client, server) = duplex(4096);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(server).await;
            });
            async move { Ok(client) }
        })
        .await;
    assert!(matches!(result, Err(Error::Io(_))));
    assert_eq!(connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn untrusted_certificate_is_rejected() {
    let (_, acceptor) = fixture("resolver.test");
    let client =
        Client::<DuplexStream>::new(ResolverConfig::new(None, Some("resolver.test")).unwrap());
    let result = client
        .resolve("example.com", IpVersion::V4, |_| {
            let (client, server) = duplex(4096);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(server).await;
            });
            async move { Ok(client) }
        })
        .await;
    assert!(matches!(result, Err(Error::Io(_))));
}

#[tokio::test]
async fn cancellation_discards_partial_response_and_next_query_reconnects() {
    let (client, acceptor) = fixture("resolver.test");
    let (seen, received) = tokio::sync::oneshot::channel();
    let (tcp, server) = duplex(4096);
    let first = acceptor.clone();
    let server = tokio::spawn(async move {
        let mut tls = first.accept(server).await.unwrap();
        let _request = read_query(&mut tls).await;
        // Send only the length: cancellation must discard this partial frame.
        tls.write_u16(100).await.unwrap();
        tls.flush().await.unwrap();
        seen.send(()).unwrap();
        let mut byte = [0];
        assert!(matches!(tls.read(&mut byte).await, Ok(0) | Err(_)));
    });
    let tcp = std::sync::Mutex::new(Some(tcp));
    let query = client.resolve("example.com", IpVersion::V4, |_| async {
        Ok(tcp.lock().unwrap().take().unwrap())
    });
    let mut query = Box::pin(query);
    tokio::select! {
        result = &mut query => panic!("query returned early: {result:?}"),
        _ = received => {}
    }
    drop(query);
    server.await.unwrap();
    let result = client
        .resolve("example.com", IpVersion::V4, |_| {
            let (client, server) = duplex(4096);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(server).await.unwrap();
                let request = read_query(&mut tls).await;
                write_answer(&mut tls, &answer(&request)).await;
            });
            async move { Ok(client) }
        })
        .await
        .unwrap();
    assert_eq!(result.len(), 2);
}

#[tokio::test]
async fn stale_pooled_connection_is_replaced_once() {
    let (client, acceptor) = fixture("resolver.test");
    let connections = AtomicUsize::new(0);
    for _ in 0..2 {
        let result = client
            .resolve("example.com", IpVersion::V4, |_| {
                connections.fetch_add(1, Ordering::Relaxed);
                let (client, server) = duplex(4096);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut tls = acceptor.accept(server).await.unwrap();
                    let request = read_query(&mut tls).await;
                    write_answer(&mut tls, &answer(&request)).await;
                    tls.shutdown().await.unwrap();
                });
                async move { Ok(client) }
            })
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
    }
    assert_eq!(connections.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn timeout_covers_connect_without_plaintext_fallback() {
    let client = Client::<DuplexStream>::new(ResolverConfig::default());
    let result = client
        .resolve("example.com", IpVersion::V4, |_| std::future::pending())
        .await;
    assert!(matches!(result, Err(Error::Timeout)));
}

#[tokio::test]
async fn stalled_query_does_not_block_other_queries_or_address_families() {
    let (client, acceptor) = fixture("resolver.test");
    let mut stalled =
        Box::pin(client.resolve("slow.example", IpVersion::V4, |_| std::future::pending()));
    for version in [IpVersion::V4, IpVersion::V6] {
        let other = client.resolve("example.com", version, |_| {
            let (client, server) = duplex(4096);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(server).await.unwrap();
                let request = read_query(&mut tls).await;
                write_answer(&mut tls, &answer(&request)).await;
            });
            async move { Ok(client) }
        });
        tokio::select! {
            result = &mut stalled => panic!("stalled query returned: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), other) => {
                let answers = result.unwrap().unwrap();
                assert_eq!(answers.len(), 2);
                assert_eq!(answers[0].is_ipv6(), version == IpVersion::V6);
            }
        }
    }
}

#[test]
fn answers_follow_aliases_filter_unrelated_records_and_enforce_limits() {
    let mut request = Message::new(10, MessageType::Query, OpCode::Query);
    request.queries.push(Query::query(
        Name::from_ascii("example.com.").unwrap(),
        RecordType::AAAA,
    ));
    let mut response = answer(&request);
    response.answers.clear();
    let alias = Name::from_ascii("alias.example.").unwrap();
    response.answers.push(Record::from_rdata(
        request.queries[0].name().clone(),
        60,
        RData::CNAME(CNAME(alias.clone())),
    ));
    for index in 1..=70 {
        response.answers.push(Record::from_rdata(
            alias.clone(),
            60,
            RData::AAAA(AAAA(format!("2001:db8::{index}").parse().unwrap())),
        ));
    }
    response.answers.insert(
        0,
        Record::from_rdata(
            Name::from_ascii("unrelated.example.").unwrap(),
            60,
            RData::AAAA(AAAA("::1".parse().unwrap())),
        ),
    );
    let result = addresses(&request, &response).unwrap();
    assert_eq!(result.len(), 64);
    assert_eq!(result[0], "2001:db8::1".parse::<IpAddr>().unwrap());
    response.metadata.id += 1;
    assert!(matches!(
        addresses(&request, &response),
        Err(Error::Protocol(_))
    ));
    response.metadata.id -= 1;
    response.queries[0] = Query::query(
        Name::from_ascii("other.example.").unwrap(),
        RecordType::AAAA,
    );
    assert!(matches!(
        addresses(&request, &response),
        Err(Error::Protocol(_))
    ));
    response.queries = request.queries.clone();
    response.metadata.truncation = true;
    assert!(matches!(
        addresses(&request, &response),
        Err(Error::Protocol(_))
    ));
    response.metadata.truncation = false;
    response.metadata.response_code = ResponseCode::ServFail;
    assert!(matches!(
        addresses(&request, &response),
        Err(Error::Protocol(_))
    ));
    response.metadata.response_code = ResponseCode::NXDomain;
    assert!(matches!(
        addresses(&request, &response),
        Err(Error::NoAddress)
    ));
}

#[tokio::test]
#[ignore = "requires network access to Cloudflare TCP port 853"]
async fn cloudflare_live_dot() {
    let client = Client::<tokio::net::TcpStream>::new(ResolverConfig::default());
    for version in [IpVersion::V4, IpVersion::V6] {
        let answers = client
            .resolve("example.com", version, tokio::net::TcpStream::connect)
            .await
            .unwrap();
        assert!(!answers.is_empty());
    }
}
