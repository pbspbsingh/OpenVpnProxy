#!/usr/bin/env python3
"""Browser regression checks using Chrome DevTools and Python's standard library."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class DevTools:
    def __init__(self, url):
        parsed = urlsplit(url)
        self.socket = socket.create_connection((parsed.hostname, parsed.port), timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        self.socket.sendall((
            f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        headers = bytearray()
        while not headers.endswith(b"\r\n\r\n"):
            chunk = self.socket.recv(1)
            if not chunk:
                raise RuntimeError("Chrome closed the DevTools handshake")
            headers.extend(chunk)
        assert headers.split(b"\r\n", 1)[0].split()[1] == b"101", headers
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert accept in headers
        self.sequence = 0
        self.errors = []
        self.requests = []

    def read(self, length):
        result = bytearray()
        while len(result) < length:
            chunk = self.socket.recv(length - len(result))
            if not chunk:
                raise RuntimeError("Chrome closed DevTools")
            result.extend(chunk)
        return bytes(result)

    def send_frame(self, payload, opcode=1):
        mask = os.urandom(4)
        length = len(payload)
        header = bytes([0x80 | opcode])
        header += bytes([0x80 | length]) if length < 126 else (
            bytes([0x80 | 126]) + struct.pack("!H", length) if length < 65536
            else bytes([0x80 | 127]) + struct.pack("!Q", length)
        )
        self.socket.sendall(header + mask + bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload)))

    def message(self):
        payload = bytearray()
        while True:
            first, second = self.read(2)
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", self.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.read(8))[0]
            mask = self.read(4) if second & 128 else None
            data = self.read(length)
            if mask:
                data = bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
            opcode = first & 15
            if opcode == 8:
                raise RuntimeError("DevTools WebSocket closed")
            if opcode == 9:
                self.send_frame(data, 10)
                continue
            if opcode == 10:
                continue
            payload.extend(data)
            if first & 128:
                return json.loads(payload)

    def call(self, method, **params):
        self.sequence += 1
        self.send_frame(json.dumps({"id": self.sequence, "method": method, "params": params}).encode())
        while True:
            message = self.message()
            if message.get("id") == self.sequence:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message.get("result", {})
            event, details = message.get("method"), message.get("params", {})
            if event == "Runtime.exceptionThrown":
                self.errors.append(details["exceptionDetails"])
            elif event == "Runtime.consoleAPICalled" and details.get("type") == "error":
                self.errors.append(details)
            elif event == "Network.requestWillBeSent":
                self.requests.append(details["request"]["url"])
            elif event == "Network.loadingFailed" and not details.get("canceled"):
                self.errors.append(details)

    def evaluate(self, expression):
        result = self.call("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in result:
            raise AssertionError(result["exceptionDetails"])
        return result["result"].get("value")

    def wait(self, expression, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.evaluate(expression):
                return
            time.sleep(0.1)
        raise AssertionError(f"Timed out: {expression}\nBrowser errors: {self.errors}")


def check(cdp, expression):
    assert cdp.evaluate(expression), expression


def check_failed_app_shutdown(binary):
    """A failed proxy must still accept shutdown through its real application loop."""
    with tempfile.TemporaryDirectory(prefix="ovpn-shutdown-app-") as directory:
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        config = Path(directory) / "config.toml"
        config.write_text(
            f'socks5_address = "127.0.0.1:0"\nwebui_address = "127.0.0.1:{port}"\n'
            '[openvpn_config]\nprofile_path = "missing-profile.ovpn"\nusername = ""\npassword = ""\n'
        )
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen([str(binary.resolve()), str(config)], cwd=directory, stdout=output, stderr=output, env={**os.environ, "RUST_LOG": "info"})
            try:
                deadline = time.monotonic() + 10
                while True:
                    log = os.pread(output.fileno(), 1_048_576, 0)
                    if b"proxy unavailable; dashboard remains active" in log:
                        break
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError(f"Failed-state dashboard did not start: {log.decode(errors='replace')}")
                    time.sleep(0.1)
                request = Request(url + "/api/shutdown", method="POST", headers={"Origin": url})
                with urlopen(request, timeout=5) as response:
                    assert response.status == 202
                assert process.wait(timeout=5) == 1  # Original startup error is preserved.
                assert b"dashboard stopped unexpectedly" not in os.pread(output.fileno(), 1_048_576, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def exercise(cdp, url):
    cdp.call("Runtime.enable")
    cdp.call("Network.enable")
    cdp.call("Page.enable")
    cdp.call("Page.addScriptToEvaluateOnNewDocument", source="""
        window.testSockets = [];
        const NativeSocket = WebSocket;
        window.WebSocket = class extends NativeSocket {
            constructor(...args) { super(...args); window.testSockets.push(this); }
        };
        window.confirm = () => false;
    """)
    cdp.call("Page.navigate", url=url)
    cdp.wait("document.querySelector('#pool-phase')?.textContent === 'Ready'")
    cdp.wait("Object.keys(window.Chart?.instances ?? {}).length === 2")
    check(cdp, "!document.querySelector('.shell').hasAttribute('x-cloak')")
    check(cdp, "document.querySelector('#active-routes').textContent === '3'")
    check(cdp, "document.querySelectorAll('#host-list button').length === 2")
    cdp.evaluate("document.querySelector('[data-tab=hosts]').click()")
    cdp.wait("document.querySelectorAll('#groups-rows tr:not([style*=none])').length >= 100")
    cdp.wait("Object.keys(Chart.instances).length === 4")
    cdp.evaluate("document.querySelector('#groups-more').click()")
    cdp.wait("document.querySelector('#groups-status').textContent.startsWith('Showing 101 of 101')")
    check(cdp, "document.querySelector('#groups-more').hidden")
    cdp.evaluate("document.querySelector('[data-tab=routing]').click()")
    cdp.wait("document.querySelector('#hosts').hidden")
    cdp.evaluate("document.querySelector('[data-tab=hosts]').click()")
    time.sleep(0.3)
    check(cdp, "document.querySelector('#groups-status').textContent.startsWith('Showing 101 of 101')")

    # Switching away during a delayed fetch must not display the old host's groups.
    cdp.evaluate("document.querySelector('#groups-refresh').click(); document.querySelector('[data-host-id=\"1\"]').click()")
    cdp.wait("document.querySelector('#groups-status').textContent.startsWith('Showing 1 of 1')")
    time.sleep(0.3)
    check(cdp, "document.querySelector('#groups-rows td').textContent === '198.51.100.2'")
    cdp.evaluate("window.savedHost = document.querySelector('[data-host-id=\"1\"]'); savedHost.focus()")
    last = cdp.evaluate("document.querySelector('#last-update').textContent")
    cdp.wait(f"document.querySelector('#last-update').textContent !== {json.dumps(last)}")
    check(cdp, "window.savedHost === document.querySelector('[data-host-id=\"1\"]') && document.activeElement === savedHost")
    check(cdp, "document.querySelector('#system-rx-rate').textContent !== '0 B/s'")

    cdp.evaluate("document.querySelector('[data-tab=routing]').click()")
    check(cdp, "document.querySelectorAll('#routing-hosts tr').length === 2")
    cdp.evaluate("document.querySelector('[data-tab=profile]').click()")
    cdp.wait("document.querySelector('#profile-status').textContent === '1 configured remote'")
    check(cdp, "document.querySelector('#profile-handshake').textContent === '30 sec'")
    check(cdp, "document.querySelector('#profile-renegotiation').textContent === '1 hr'")

    check(cdp, "testSockets.filter(s => s.url.endsWith('/ws/logs')).length === 0")
    cdp.evaluate("document.querySelector('[data-tab=logs]').click()")
    cdp.wait("document.querySelectorAll('#log-rows .log-row').length === 2000")
    check(cdp, "Number(document.querySelector('#log-count').textContent.split(' · ')[1].replace(/[^0-9]/g, '')) > 2100")
    check(cdp, "!window.injected && !document.querySelector('#log-rows img')")
    check(cdp, "testSockets.filter(s => s.url.endsWith('/ws/logs') && s.readyState === 1).length === 1")
    cdp.evaluate("document.querySelector('#logs-older').click()")
    cdp.wait("document.querySelectorAll('#log-rows .log-row').length > 2000")
    cdp.evaluate("const select = document.querySelector('#log-level'); select.value = 'ERROR'; select.dispatchEvent(new Event('change', { bubbles: true }))")
    cdp.wait("[...document.querySelectorAll('#log-rows .log-level')].every(n => n.textContent === 'ERROR') && document.querySelectorAll('#log-rows .log-row').length > 1000")
    # Live WARN events are filtered out; they must not republish the unchanged list.
    cdp.evaluate("""(async () => {
        const { default: Alpine } = await import('https://cdn.jsdelivr.net/npm/alpinejs@3.17.4/dist/module.esm.min.js');
        window.filteredLogs = Alpine.$data(document.querySelector('#logs'));
        window.savedRows = filteredLogs.rows;
        window.savedBuffered = filteredLogs.buffered;
    })()""")
    cdp.wait("filteredLogs.buffered > savedBuffered")
    check(cdp, "filteredLogs.rows === savedRows")
    cdp.evaluate("document.querySelector('[data-tab=overview]').click()")
    cdp.wait("testSockets.filter(s => s.url.endsWith('/ws/logs')).every(s => s.readyState === 3)")
    # Evicting a matching entry must update the filtered view even for a WARN arrival.
    cdp.evaluate("""
        filteredLogs.receive({ type: 'reset', capacity: 2, dropped: 0 });
        filteredLogs.receive({ type: 'batch', entries: [
            { sequence: 1, timestamp_ms: 0, level: 'ERROR', target: 'test', message: 'expired error' },
            { sequence: 2, timestamp_ms: 0, level: 'WARN', target: 'test', message: 'retained warn' },
        ] });
    """)
    cdp.wait("filteredLogs.matching === 1 && filteredLogs.buffered === 2")
    cdp.evaluate("filteredLogs.receive({ type: 'entry', entry: { sequence: 3, timestamp_ms: 0, level: 'WARN', target: 'test', message: 'new warn' } })")
    cdp.wait("filteredLogs.matching === 0 && filteredLogs.buffered === 2 && filteredLogs.rows.length === 0")
    cdp.evaluate("document.querySelector('[data-tab=overview]').dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }))")
    cdp.wait("document.activeElement?.dataset.tab === 'hosts'")
    check(cdp, "document.querySelectorAll('[role=tab][tabindex=\"0\"]').length === 1")

    cdp.call("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=1, mobile=True)
    cdp.evaluate("document.querySelector('[data-tab=overview]').click()")
    cdp.wait("document.documentElement.clientWidth === 390")
    check(cdp, "document.documentElement.scrollWidth <= 390")

    # Exercise counter resets and gaps through the actual shipped ES modules.
    check(cdp, """(async () => {
        const { ratesBetween, minuteSeries } = await import('/lib/history.js');
        const old = { sampled_at_ms: 1000, pool: { rx_bytes: 100, tx_bytes: 50 }, hosts: [] };
        const current = { sampled_at_ms: 6000, pool: { rx_bytes: 600, tx_bytes: 40 }, hosts: [] };
        const rates = ratesBetween(current, old);
        const stale = ratesBetween({ ...current, sampled_at_ms: 22000 }, old);
        const series = minuteSeries([{ minute_start_ms: 60000, value: 7 }], 60000, b => b.value);
        return rates.pool.rx === 100 && rates.pool.tx === 0 && stale.pool.rx === 0 && series.length === 60 && series.at(-1) === 7 && series[0] === null;
    })()""")

    # Cancellation leaves the server running; failed requests allow a retry.
    cdp.evaluate("document.querySelector('#shutdown-button').click()")
    check(cdp, "!document.querySelector('#shutdown-button').disabled")
    check(cdp, "document.querySelector('#feed-label').textContent === 'Live'")
    cdp.evaluate("""
        window.confirm = () => true;
        window.savedFetch = window.fetch;
        window.fetch = (url, options) => url === '/api/shutdown'
            ? Promise.resolve(new Response('', { status: 503 })) : savedFetch(url, options);
        document.querySelector('#shutdown-button').click();
    """)
    cdp.wait("document.querySelector('#shutdown-error').textContent.includes('HTTP 503')")
    check(cdp, "!document.querySelector('#shutdown-button').disabled")
    cdp.evaluate("window.fetch = savedFetch; document.querySelector('[data-tab=logs]').click()")
    cdp.wait("testSockets.some(s => s.url.endsWith('/ws/logs') && s.readyState === 1)")
    cdp.evaluate("document.querySelector('#shutdown-button').click()")
    cdp.wait("document.querySelector('#shutdown-button').textContent === 'Shutdown requested'")
    check(cdp, "document.querySelector('#shutdown-button').disabled")
    check(cdp, "document.querySelector('#feed-label').textContent === 'Shutdown requested'")
    check(cdp, "document.documentElement.scrollWidth <= 390")
    cdp.wait("testSockets.every(s => s.readyState === 3)")
    check(cdp, """(async () => {
        const { default: Alpine } = await import('https://cdn.jsdelivr.net/npm/alpinejs@3.17.4/dist/module.esm.min.js');
        Alpine.destroyTree(document.querySelector('.shell'));
        return Object.keys(Chart.instances).length === 0;
    })()""")
    cdp.wait("testSockets.every(s => s.readyState === 3)")
    assert not cdp.errors, cdp.errors
    external = [request for request in cdp.requests if not request.startswith((url, url.replace('http:', 'ws:')))]
    allowed = {
        "https://cdn.jsdelivr.net/npm/alpinejs@3.17.4/dist/module.esm.min.js",
        "https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js",
    }
    assert set(external) <= allowed, external


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True, help="compiled dashboard_fixture example")
    parser.add_argument("--app", type=Path, help="also verify shutdown of the app after startup failure")
    parser.add_argument("--chrome", default="google-chrome")
    args = parser.parse_args()
    fixture = subprocess.Popen([str(args.fixture.resolve())], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        url = fixture.stdout.readline().strip()
        if not url.startswith("http://127.0.0.1:"):
            raise RuntimeError(f"Fixture failed to start: {fixture.stderr.read()}")
        for method, origin, expected in [("GET", url, 405), ("POST", None, 403), ("POST", "http://other.example", 403)]:
            headers = {"Origin": origin} if origin else {}
            try:
                with urlopen(Request(url + "/api/shutdown", method=method, headers=headers), timeout=10):
                    raise AssertionError("Shutdown accepted without a same-origin POST")
            except HTTPError as error:
                assert error.code == expected, (method, origin, error.code)
        assert fixture.poll() is None
        with tempfile.TemporaryDirectory(prefix="ovpn-ui-browser-") as profile:
            with tempfile.TemporaryFile() as chrome_log:
                chrome = subprocess.Popen([
                    args.chrome, "--headless=new", "--disable-gpu", "--disable-dev-shm-usage",
                    "--no-first-run", "--no-default-browser-check", "--remote-debugging-port=0",
                    f"--user-data-dir={profile}", "about:blank",
                ], stdout=chrome_log, stderr=chrome_log, start_new_session=True)
                cdp = None
                try:
                    port_file = Path(profile) / "DevToolsActivePort"
                    deadline = time.monotonic() + 20
                    while not port_file.exists():
                        if chrome.poll() is not None or time.monotonic() >= deadline:
                            chrome_log.seek(0)
                            raise RuntimeError(chrome_log.read().decode(errors="replace"))
                        time.sleep(0.1)
                    port = port_file.read_text().splitlines()[0]
                    with urlopen(f"http://127.0.0.1:{port}/json", timeout=10) as response:
                        page = next(page for page in json.load(response) if page["type"] == "page")
                    cdp = DevTools(page["webSocketDebuggerUrl"])
                    exercise(cdp, url)
                    assert fixture.wait(timeout=5) == 0, "Shutdown did not stop the fixture cleanly"
                finally:
                    if cdp is not None:
                        try:
                            cdp.call("Browser.close")
                        except (OSError, RuntimeError):
                            pass
                        finally:
                            cdp.socket.close()
                    elif chrome.poll() is None:
                        os.killpg(chrome.pid, signal.SIGTERM)
                    try:
                        chrome.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(chrome.pid, signal.SIGKILL)
                        chrome.wait()
    finally:
        fixture.terminate()
        fixture.wait(timeout=10)
    if args.app:
        check_failed_app_shutdown(args.app)
    print("PASS: five screens, charts, live updates, hosts, logs, mobile layout, history, shutdown cancellation/retry, origin checks, and graceful process exit", flush=True)


if __name__ == "__main__":
    main()
