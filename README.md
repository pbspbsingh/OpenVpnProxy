# Rootless OpenVPN SOCKS5 proxy

This Rust workspace is a userspace OpenVPN SOCKS5 app. An application connects to its SOCKS5 listener, and the proxy carries that application's TCP traffic through a selected OpenVPN server. It creates no TUN device, changes no system routes, and needs no root permissions. The current host selection and routing behavior has been built and exercised with a real VPN profile on Linux. Idle shutdown and failover still need live tests. macOS also needs a build and live test.

## The networking model

There are **two distinct TCP connections** in a proxied HTTPS request:

1. The application opens a normal OS TCP connection to the local SOCKS5 listener. SOCKS5 is a short negotiation in which the application asks the proxy to connect to a destination. The application then sends its ordinary HTTPS bytes over that connection.
2. `smoltcp` creates a separate, virtual TCP connection to the destination. It turns those bytes into TCP segments inside IPv4 or IPv6 packets. The OpenVPN client encrypts those IP packets and sends them as UDP datagrams to the VPN server. The server forwards them to the destination.

The OS handles the first TCP connection and the UDP sockets to VPN servers. `smoltcp` handles the destination TCP connection. No OS socket connects directly to the requested website. HTTPS encryption remains between the application and the website; this proxy forwards its bytes and does not terminate HTTPS.

```text
Application ── local TCP / SOCKS5 ──> Proxy
                                      │
                                      ▼
                              smoltcp: DNS + TCP/IP
                                      │ IPv4 or IPv6 packets
                                      ▼
                              OpenVPN data channel
                                      │ encrypted UDP
                                      ▼
                              VPN server ──> Website
```

Only applications configured to use this SOCKS5 proxy follow this path. The project does not install a system-wide VPN. DNS lookup of a **VPN server hostname** may use the OS resolver before the tunnel exists; lookup of a **SOCKS destination hostname** uses DNS inside the tunnel.

## Workspace architecture

| Crate | What it owns | Main boundary |
| --- | --- | --- |
| `ovpn-profile` | Parses the supported `.ovpn` directives into remotes, CA, `tls-crypt` key, and timing settings. | Profile text in; typed `Profile` out. No network runtime. |
| `ovpn-client` | OpenVPN UDP session, protected control channel, TLS, authentication exchange, pushed settings, encrypted data packets, keepalives, and key rotation. | Plain IP packets in/out through `Session`; no knowledge of SOCKS5 or `smoltcp`. |
| `ovpn-netstack` | Virtual IP interface, DNS queries, TCP connections, and IP packet production/consumption using `smoltcp`. | `Stack` commands and `StreamEvent`s for callers; plain IPv4 or IPv6 packets for the app. |
| `ovpn-socks5` | SOCKS5 negotiation and forwarding between a client socket and its assigned `Stack`. | One async handler per accepted client; it asks a routing provider to select a stack before DNS. No OpenVPN dependency. |
| `ovpn-ui` | Embedded read-only dashboard, WebSocket feed, and in-memory one-minute chart history. | Receives typed snapshots; no VPN or SOCKS dependency. |
| `openvpn-proxy-app` | TOML config, host discovery, connection manager, sticky routing, tunnel supervision, SOCKS and dashboard listeners, and shutdown. | Executable and composition root. |

The dependency direction is `app → profile/client/netstack/socks5/ui` and `socks5 → netstack`. The app owns one OpenVPN session and one packet stack **per active VPN host**, and connects their plain IP packet streams. Reusable crates expose typed errors with `thiserror`; the app adds context with `anyhow` and logs through `tracing`.

### Connection manager and sticky routing

The app resolves every profile `remote` to IPv4 endpoints, deduplicates them, and groups ports under each server IP. Before accepting SOCKS connections, it probes every candidate with at most four probes running concurrently. Each baseline tunnel closes after measurement. The fastest healthy `max_active_vpn_hosts` (default: 16) become the selected pool; the remaining scored hosts stay dormant as failover candidates. The first client request wakes all selected hosts together. Each worker tries its host's ports in turn, establishes a VPN session and packet stack, obtains a fresh tunneled score, then becomes available for routing. A failed selected host yields its slot to a dormant candidate, preferring candidates that have not failed during the current wake. If none remains, the failed host retries with bounded exponential backoff.

The initial score is the median of three tunneled TCP connection times to `1.1.1.1:443`; at least two must succeed. Logs report tunnel setup time, time spent obtaining the score, and total time for each host. Connected hosts refresh the score every minute on staggered schedules, smoothing new samples with the previous score; probes do not count as client activity. A dormant replacement gets a fresh score before receiving traffic. Scores remain in memory only and are measured again on app restart.

For a SOCKS hostname, the handler asks the manager for a route **before DNS**. The manager uses the Public Suffix List to group a registrable domain and its subdomains: `abc.com` and `xyz.abc.com` share an assignment for the same client source IP. Direct IP requests use `(source IP, destination IP)` as the sticky key. A new group chooses among ready selected hosts using latency and current connection count. IPv6 requests require a matching IPv6 route on the selected tunnel. Existing assignments remain fixed until their host fails or they have no TCP connections for 30 minutes. On failure, the manager removes that host's assignments and resets its stack, closing existing proxied TCP connections. When the entire pool has no client routes for 30 minutes, all VPN sessions close and sticky state clears. The next request reopens the selected pool.

The sticky table is bounded. If it fills, new groups fail closed rather than silently losing their assignment. DNS for a hostname runs through its assigned host's packet stack, so DNS and TCP use the same VPN.

### Inside the OpenVPN client

- `control.rs` implements reliable OpenVPN control packets over UDP: reset, acknowledgments, ordering, retries, and TLS record transport. `tlscrypt.rs` protects those control packets before TLS sees them.
- `client/tls.rs` builds `rustls` and validates the certificate against the profile CA. When the profile specifies `remote-cert-tls server`, it also requires an explicit key usage extension and server authentication extended key usage.
- `client/key_method.rs` exchanges credentials and key method messages inside TLS. `client/push.rs` parses the server's tunnel address, gateway, DNS servers, peer ID, cipher, and keepalive settings.
- `data.rs` encrypts and authenticates IP packets with AES-256-GCM. It checks packet IDs to reject replays. `client/mod.rs` coordinates the session and rekey states.

The control channel establishes trust and derives data keys. The data channel carries the actual IP packets. They share one UDP socket, but use different packet types and cryptographic state.

### Inside the packet stack

`Stack` is a cloneable async handle. Its commands go to one `smoltcp` engine task; callers receive connection events through channels. The engine polls a virtual IP device, runs DNS and TCP state machines, and emits IPv4 or IPv6 packets to the app according to the VPN server's routes. The device is an in-memory packet queue, not a TUN interface. The engine wakes for commands, consumed connection events, and the next TCP or application deadline; it does not need a dedicated OS thread for `smoltcp`.

`smoltcp` supplies the TCP behavior a SOCKS client expects: connection setup, sequencing, acknowledgments, retransmission, and teardown. The SOCKS handler works with byte streams and connection events; it does not construct TCP or IP headers.

## Startup sequence

The listener opens after profile validation, VPN host discovery, and a baseline measurement round. Baseline tunnels close after measurement; serving tunnels start when requests arrive.

```mermaid
sequenceDiagram
    participant App as App
    participant Profile as Profile parser
    participant Manager as Connection manager
    participant Listener as SOCKS listener

    App->>Profile: Read config.toml and parse .ovpn
    Profile-->>App: Remotes, CA, keys, options
    App->>Manager: Resolve all remotes; group endpoints by server IP
    Manager->>Manager: Probe all candidates, four at a time
    Manager->>Manager: Rank healthy hosts; select configured active limit
    Manager-->>App: Scored host pool ready; tunnels dormant
    App->>Listener: Bind socks5_address
    Listener-->>App: Accept SOCKS5 clients
```

Profile or host discovery errors prevent startup. A candidate that fails its baseline probe is ineligible; startup fails if none pass. The manager does not benchmark throughput or refresh remote DNS records after startup yet.

## One proxied HTTPS request

This diagram uses `curl --socks5-hostname`, so curl sends the hostname to the proxy. For a direct IP address request, the DNS step is skipped. IPv6 uses the same packet path when the selected VPN host has an IPv6 route. The reverse path follows the same components in reverse order.

```mermaid
sequenceDiagram
    participant Client as Application
    participant Socks as SOCKS5 handler
    participant Manager as Connection manager
    participant Stack as smoltcp engine
    participant App as Host worker packet loop
    participant VPN as OpenVPN session
    participant Server as VPN server
    participant Site as Website

    Client->>Socks: Local TCP; SOCKS5 CONNECT example.com:443
    Socks->>Manager: Select sticky host for (source IP, example.com)
    Manager->>VPN: Wake selected pool; start sessions if dormant
    VPN->>Server: Protected reset, TLS handshake, credentials, PUSH_REQUEST
    Server-->>VPN: Tunnel settings
    VPN-->>Manager: Session established; activate stack and probe latency
    Manager-->>Socks: Lease for one ready host and its stack
    opt Destination is a hostname
        Socks->>Stack: Resolve A or AAAA record
        Stack->>App: DNS query as IP packet
        App->>VPN: Encrypt packet
        VPN->>Server: UDP data packet
        Server-->>VPN: Encrypted DNS response
        VPN-->>App: Plain IP packet
        App-->>Stack: Deliver DNS response
        Stack-->>Socks: Destination IP address
    end
    Socks->>Stack: Open virtual TCP connection to address:443
    Stack->>App: TCP SYN as IP packet
    App->>VPN: Encrypt packet
    VPN->>Server: UDP data packet
    Server->>Site: Forward TCP connection
    Site-->>Server: TCP response
    Server-->>VPN: Encrypted IP packet
    VPN-->>App: Decrypt packet
    App-->>Stack: Deliver TCP response
    Stack-->>Socks: Connected event
    Socks-->>Client: SOCKS5 success
    loop HTTPS byte stream
        Client->>Socks: TLS / HTTP bytes
        Socks->>Stack: Write virtual TCP stream
        Stack->>App: IP packets
        App->>VPN: Encrypt and send over UDP
        VPN->>Server: Encrypted data
        Server->>Site: Forward TCP data
        Site-->>Server: TCP data
        Server-->>VPN: Encrypted data
        VPN-->>App: Decrypted IP packets
        App-->>Stack: Deliver packets
        Stack-->>Socks: Stream data event
        Socks-->>Client: TLS / HTTP bytes
    end
```

The app's serving loop accepts SOCKS clients and handles shutdown. Each accepted client gets an async task. Each active VPN host worker multiplexes outbound stack packets, inbound OpenVPN packets, keepalive/status work, probes, and shutdown. A pool coordinator handles the shared idle timeout and sticky expiry. Each packet stack has one owning task for its TCP and DNS state.

## Key rotation and failure behavior

OpenVPN may request a new data key, or the client may start renegotiation when its configured interval or packet ID threshold is reached. The client opens a replacement control/TLS state under the next key ID, exchanges key material, and briefly accepts data under old and new keys during the transition. It sends a probe with the new key and retains the old outbound key until it sees authenticated new-key data or a bounded grace period ends. This handoff has had a live test against one server; it is not a complete interoperability test.

The design fails closed for **traffic handled by this proxy**:

- The SOCKS listener starts after baseline probing but before serving tunnels connect. A request waits for a selected host up to the profile handshake window plus 30 seconds for control setup (60 seconds with the default 30-second handshake window). A failed host clears its assignment; a scored standby may take its slot after a fresh probe. If no host becomes ready, the proxy returns a SOCKS5 network failure. A profile's `hand-window` setting overrides the default handshake window and also limits key renegotiation.
- During a session, SOCKS requests can select only a ready host. A VPN or stack error marks that host unhealthy, clears its sticky assignments, resets its stack, and closes its client connections. Other hosts continue serving. Full queues mark the affected stack failed instead of bypassing it.
- There is no direct-to-destination fallback in the SOCKS or stack crates. If every selected host is unavailable, new requests fail. The manager can activate a scored standby, retries failed hosts when no standby remains, and tries alternate ports; automatic DNS rediscovery and migration of existing TCP connections are not implemented.

This guarantee applies only to traffic sent to the proxy. An application that ignores its proxy setting can still use the ordinary network connection.

## Build and run

The OpenVPN protocol code is Rust. `rustls` uses the `aws-lc-rs` crypto provider, whose build needs a C compiler; an OpenVPN installation is not required.

```sh
cargo build --release -p openvpn-proxy-app
cp config.toml.example config.toml
# Set profile_path, username, password, and socks5_address in config.toml.
cargo run --release -p openvpn-proxy-app
```

Pass a path as the sole argument to use a config file other than `config.toml`. Relative `profile_path` values resolve from that file's directory. `max_active_vpn_hosts` defaults to 16. Set `webui_address` to enable the dashboard; omitting it starts no web server. When enabled, the dashboard binds before profile loading, SOCKS binding, and VPN probing. A failed dashboard bind stops startup; a later proxy startup or listener failure appears in the dashboard, which stays available until shutdown. `dns_override` is optional; it replaces the server-pushed resolver for SOCKS destination lookups and still sends those queries through the assigned VPN. Without a usable DNS server, hostname requests fail; direct IP address requests can still work.

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
RUST_LOG=debug cargo run --release -p openvpn-proxy-app
```

With `webui_address = "127.0.0.1:8080"`, open `http://127.0.0.1:8080` for the read-only dashboard. Overview, Hosts, and Routing status update through a WebSocket every five seconds. System and per-host TX/RX and latency charts show the latest 60 one-minute buckets. The Hosts tab shows the selected host's assigned groups in a panel with its own scrollbar; entries load in pages and show source IP, destination group, and active or idle state. Assignment changes reach a separate dashboard copy through an async channel, so group counts and pages can briefly trail routing without making route selection wait for dashboard scans. The Profile tab shows loaded remotes, authentication policy, certificate checks, IPv6 policy, and timing settings. The current chart minute is partial; history and counters reset when the app restarts. The page does not expose credentials or allow configuration changes. The dashboard has no authentication and binds only to loopback when configured with a loopback address.

`RUST_LOG=info` shows discovered hosts, connection attempts, ready/down transitions, idle closures, and new domain assignments. `RUST_LOG=debug` adds route requests, retries, and per-host activity. `RUST_LOG=trace` adds packet flow details. `socks5_address = "0.0.0.0:1080"` accepts clients from other machines. The proxy has **no SOCKS authentication**, so choose the bind address and network exposure accordingly. `config.toml` contains credentials; it and `*.ovpn` are ignored by Git.

For a browser speed test, run the release build with `RUST_LOG=debug`. `stack_id` links route, SOCKS, VPN host, and packet stack logs. A `SOCKS5 transfer summary` reports route, DNS, TCP connect, and transfer times plus bytes in each direction; `first_response` measures the first tunneled bytes after the SOCKS connection, which may be a TLS handshake. Active transfers and packet stacks also report 10-second traffic windows. `packet stack activity` includes command, timer, and consumer wakeups, timer lateness, time spent per pass, full 4 KiB reads, event queue stalls, and the largest queued TCP write. Share these summaries and the matching `VPN host traffic` lines when investigating a slow request; debug logs also contain destination names.

## Current scope

Supported profiles use UDP/IPv4 to reach the VPN server, an inline CA, `tls-crypt` v1, and AES-256-GCM. Username/password is supported when required. The SOCKS5 listener stays on the configured IPv4 address and supports unauthenticated TCP CONNECT to IPv4, IPv6, and hostnames. IPv6 destinations work only when the chosen VPN server pushes an IPv6 tunnel address and route and neither the profile nor server blocks IPv6; otherwise the request fails closed. Hostnames use tunneled A and AAAA queries on IPv6-capable hosts and can fall back to IPv4. UDP ASSOCIATE, throughput-based host selection, and dashboard configuration editing are not implemented. macOS behavior remains unverified.
