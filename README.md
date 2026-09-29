# Rootless OpenVPN SOCKS5 workspace

This workspace contains a userspace OpenVPN SOCKS5 proof of concept. It creates no TUN device, changes no system routes, and needs no root permissions. The Linux tunnel has been tested with a real VPN profile. macOS support still needs a build and live test on macOS.

## Crates

| Crate | Responsibility |
| --- | --- |
| `ovpn-profile` | Parse a supported `.ovpn` profile. No runtime or network dependencies. |
| `ovpn-client` | OpenVPN control and data channels, TLS, and typed tunnel settings. |
| `ovpn-netstack` | Userspace IPv4 TCP and DNS over decrypted VPN packets. |
| `ovpn-socks5` | SOCKS5 CONNECT server using the packet stack. |
| `openvpn-proxy-app` | TOML configuration, async orchestration, and future Web UI. |

The app is the composition root. The OpenVPN client, profile parser, and packet stack do not depend on each other. Reusable crates use `thiserror` for typed failures; the app uses `anyhow` for contextual errors. Tokio runs network I/O; the `smoltcp` engine is polled by one task. `tracing` provides logs (`RUST_LOG=debug` for connection details and protocol retries, `RUST_LOG=trace` for packet sizes).

## Build and run

The non-FIPS `aws-lc-rs` TLS provider needs a C compiler. It does not require an OpenVPN installation. Build with a Rust toolchain:

```sh
cargo build --release -p openvpn-proxy-app
cp config.toml.example config.toml
# Edit config.toml with your profile path and credentials.
cargo run --release -p openvpn-proxy-app
```

`config.toml` contains `profile_path`, `username`, `password`, and `socks5_address`; `dns_override` is optional. Relative profile paths resolve from the config file's directory. Set `socks5_address = "0.0.0.0:1080"` to accept connections from other machines. The SOCKS5 proxy does not authenticate clients. `config.toml` and `*.ovpn` are ignored by Git. Keep the config file private because it contains credentials. To use a different file, pass its path as the only argument.

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

If the server provides no DNS address, or you need a different resolver, set `dns_override = "1.1.1.1"` in `config.toml`. SOCKS domain lookups go through the VPN. The app may use system DNS once to locate the VPN server before connecting.

## Current limits

The supported profile subset is UDP/IPv4 with inline CA, `tls-crypt` v1, optional username/password, and AES-256-GCM. SOCKS5 supports IPv4 TCP CONNECT and tunneled domain lookup. The app exits and closes proxy connections if the VPN or packet stack fails; it does not reconnect or renegotiate keys. The Web UI, configuration editing, and charts are not implemented yet.

Only traffic explicitly sent through the SOCKS proxy is protected. Applications that ignore the proxy can use the normal network. Do not commit real profiles or credentials.
