# Dashboard development

The dashboard uses Alpine.js components and native JavaScript modules. There is
no Node, npm, transpiler, or frontend build step. Alpine 3.17.4 and Chart.js 4.5.1
load from pinned CDN URLs in `assets/app.js`.

- `assets/index.html`: application shell and tabs.
- `assets/views/`: one HTML fragment per screen, with declarative Alpine bindings.
- `assets/components/`: each screen's state and behavior; `chart.js` owns chart instances.
- `assets/dashboard.js`: shared snapshots, rates, and selection state.
- `assets/lib/`: WebSocket lifecycle, history calculations, and formatting.
- `assets/style.css`: shared layout and theme.

Rust embeds the **entire** assets tree with `include_dir!`. The server composes
the shell's `{{name}}` markers from matching `views/name.html` fragments once and
serves assets by path. Adding a module requires no Rust routing changes.
`build.rs` tracks directory changes, so rebuilding Cargo refreshes embedded assets.
The executable needs no external asset directory at runtime. Browsers need CDN access.

Keep wire data in the dashboard store; keep screen-specific state in its component.
Keep Chart.js instances, sockets, abort controllers, and timer handles outside
reactive objects. Components release these resources in `destroy()`.
Use `x-text` for data from APIs and logs, and stable keys for `x-for` collections.

The header's Shut down button confirms the action, then sends a same-origin
`POST /api/shutdown`. This requests the application's normal graceful shutdown;
the app stops accepting clients, closes VPN hosts, and stops the dashboard.
The request channel is separate from the dashboard's stop notification so the
HTTP response can finish while the application cleans up. The UI stops its feeds
and polling once the request is accepted.

## Checks

```sh
cargo test --locked -p ovpn-ui
cargo build --locked -p ovpn-ui --example dashboard_fixture
cargo build --locked -p openvpn-proxy-app
python3 crates/ui/tests/browser.py --fixture target/debug/examples/dashboard_fixture --app target/debug/openvpn-proxy-app
```

The browser check needs Chrome (`--chrome` can override its path), Python 3,
CDN access, and permission to bind loopback sockets. It uses Python's standard
library and Chrome DevTools directly. The fixture exercises real Rust HTTP and
WebSocket handlers without a VPN or credentials.
`--app` also checks that the real application accepts shutdown after a profile
loading failure, using a temporary configuration.
