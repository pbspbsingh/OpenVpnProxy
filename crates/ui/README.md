# Dashboard development

The dashboard uses Alpine.js components and native JavaScript modules. There is
no Node, npm, transpiler, or frontend build step. Alpine 3.17.4 and Chart.js 4.5.1
load from pinned CDN URLs in `assets/app.js`.

- `assets/index.html`: application shell and tabs.
- `assets/views/`: one HTML fragment per screen, with declarative Alpine bindings.
- `assets/components/`: each screen's state and behavior; `chart.js` owns chart instances and `configuration.js` owns configuration forms.
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
Configuration uses a separate `ConfigurationControl` interface implemented by the app.
Its API supports listing, creating, editing, deleting, and activating saved entries. Saves and
activation require same-origin requests; responses exclude passwords and profile contents.
The Default entry is read-only, and no default is required when the dashboard is enabled.
Saving leaves traffic running; activation restarts the proxy while retaining HTTP and logs.
A failed activation remains visible and can be retried. Successful activation records the
configuration ID for startup; restart loads its latest saved settings. Missing selected
files produce a prominent red alert and ERROR logs. Default and running entries cannot
be deleted.

The request channel is separate from the dashboard's stop notification so the
HTTP response can finish while the application cleans up. The UI stops its feeds
and polling once the request is accepted.

The application dashboard actor owns status aggregation and chart history. The Rust
HTTP server consumes `DashboardSource`: a watch receiver of serialized frames,
assignment page queries, and safe profile settings. It does not poll routing or
run a snapshot sampler. `DashboardHistory` builds the wire frame and minute buckets;
production uses it inside the actor, while the browser fixture supplies its own feed.

## Checks

```sh
cargo test --locked -p ovpn-ui
cargo build --locked -p ovpn-ui --example dashboard_fixture
cargo build --locked -p openvpn-proxy-app
python3 crates/ui/tests/browser.py --fixture target/debug/examples/dashboard_fixture --app target/debug/openvpn-proxy-app
python3 crates/ui/tests/configurations.py --app target/debug/openvpn-proxy-app
```

The browser check needs Chrome (`--chrome` can override its path), Python 3,
CDN access, and permission to bind loopback sockets. It uses Python's standard
library and Chrome DevTools directly. The fixture exercises real Rust HTTP and
WebSocket handlers without a VPN or credentials.
`--app` also checks that the real application accepts shutdown after a profile
loading failure, using a temporary configuration.

The configuration check launches the real app in temporary directories. It tests optional
defaults, browser add/edit forms, password/profile retention, activation failure and retry,
deleting entries, latest saved startup settings, missing-file alerts and logs, persistence
across process restarts, default protection, and mobile layout.
Its synthetic profile fails CA loading locally and never establishes a VPN connection.
