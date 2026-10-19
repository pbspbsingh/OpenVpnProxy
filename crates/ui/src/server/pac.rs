use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::http::header::{CONTENT_TYPE, HOST};
use axum::http::uri::Authority;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

pub(super) fn router(socks5_address: SocketAddr) -> Router {
    if socks5_address.ip().is_loopback() {
        return Router::new();
    }

    Router::new().route(
        "/proxy.pac",
        get(move |headers: HeaderMap| async move { pac(socks5_address, headers) }),
    )
}

fn pac(socks5_address: SocketAddr, headers: HeaderMap) -> Response {
    let host = if socks5_address.ip().is_unspecified() {
        // A wildcard bind address is not a destination clients can connect to.
        // Use the host they used to reach this HTTP server, without its HTTP port.
        match request_host(&headers) {
            Some(host) => host,
            None => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else {
        match socks5_address.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        }
    };
    let proxy = format!("SOCKS5 {host}:{}", socks5_address.port());
    let proxy = serde_json::to_string(&proxy).expect("a string is always JSON serializable");
    let script = format!("function FindProxyForURL(url, host) {{\n    return {proxy};\n}}\n");
    (
        [(CONTENT_TYPE, "application/x-ns-proxy-autoconfig")],
        script,
    )
        .into_response()
}

fn request_host(headers: &HeaderMap) -> Option<String> {
    let authority: Authority = headers.get(HOST)?.to_str().ok()?.parse().ok()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host();
    let ip_host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = ip_host.parse::<IpAddr>() {
        return (!ip.is_unspecified()).then(|| host.to_owned());
    }
    // Exclude JavaScript and PAC directive delimiters as well as URI userinfo.
    (!host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
    .then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn request(socks_address: &str, method: &str, host: Option<&str>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = router(socks_address.parse().unwrap())
            .layer(axum::middleware::map_response(super::super::no_cache));
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let host = host
            .map(|host| format!("Host: {host}\r\n"))
            .unwrap_or_default();
        stream
            .write_all(
                format!("{method} /proxy.pac HTTP/1.0\r\n{host}Connection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        server.abort();
        let _ = server.await;
        response
    }

    #[tokio::test]
    async fn endpoint_is_absent_for_loopback_binds() {
        for address in ["127.0.0.1:1080", "127.42.0.1:1080", "[::1]:1080"] {
            assert!(
                request(address, "GET", Some("proxy.example:8080"))
                    .await
                    .starts_with("HTTP/1.0 404")
            );
        }
    }

    #[tokio::test]
    async fn fixed_bind_advertises_its_address_and_configured_port() {
        let response = request("192.0.2.10:1150", "GET", Some("other.example:8080")).await;
        assert!(response.starts_with("HTTP/1.0 200"));
        assert!(response.contains("content-type: application/x-ns-proxy-autoconfig\r\n"));
        assert!(response.contains("cache-control: no-cache, no-store\r\n"));
        assert!(response.ends_with(
            "function FindProxyForURL(url, host) {\n    return \"SOCKS5 192.0.2.10:1150\";\n}\n"
        ));
        let head = request("192.0.2.10:1150", "HEAD", None).await;
        assert!(head.starts_with("HTTP/1.0 200"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn wildcard_bind_uses_each_request_host_without_its_http_port() {
        for host in ["proxy.example", "192.0.2.20", "[2001:db8::1]"] {
            let response = request("0.0.0.0:1150", "GET", Some(&format!("{host}:8080"))).await;
            assert!(response.starts_with("HTTP/1.0 200"));
            assert!(response.contains(&format!("return \"SOCKS5 {host}:1150\";")));
            assert!(!response.contains("DIRECT"));
        }
    }

    #[tokio::test]
    async fn wildcard_bind_rejects_missing_or_unsafe_hosts() {
        for host in [
            None,
            Some("0.0.0.0:8080"),
            Some("user@proxy.example"),
            Some("proxy.example;DIRECT"),
            Some("proxy\"example"),
        ] {
            assert!(
                request("0.0.0.0:1080", "GET", host)
                    .await
                    .starts_with("HTTP/1.0 400")
            );
        }
    }
}
