#!/usr/bin/env python3
"""Exercise configuration persistence, API, and real dashboard without a VPN."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from browser import DevTools, check


PROFILE = (
    "client\nproto udp\nremote 127.0.0.1 9\nauth-user-pass\n"
    "<ca>\nCERT\n</ca>\n<tls-crypt>\n" + "00" * 256 + "\n</tls-crypt>\n"
)
SECRET = "configuration-test-private-password"


def api(url, path="/api/configurations", method="GET", body=None, expected=200, origin=True):
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = url if origin is True else origin
    data = json.dumps(body).encode() if body is not None else None
    try:
        response = urlopen(Request(url + path, data=data, method=method, headers=headers), timeout=10)
    except HTTPError as error:
        response = error
    with response:
        payload = response.read().decode()
        assert response.code == expected, (method, path, response.code, payload)
    assert SECRET not in payload and "profile_text" not in payload, "API returned a secret"
    return json.loads(payload) if payload else None


def wait_for(condition, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = condition()
            if result:
                return result
        except (URLError, ConnectionError):
            pass
        time.sleep(0.05)
    raise AssertionError("Condition did not complete")


@contextmanager
def application(binary, directory, default=False):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    config = directory / "application.toml"
    text = f'socks5_address = "127.0.0.1:0"\nwebui_address = "127.0.0.1:{port}"\n'
    if default:
        text += '[openvpn_config]\nprofile_path = "missing.ovpn"\nusername = "default-user"\npassword = "default-secret"\n'
    config.write_text(text)
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([str(binary), str(config)], cwd=directory, stdout=output, stderr=output,
                                   env={**os.environ, "RUST_LOG": "info"})
        try:
            wait_for(lambda: api(url))
            yield url, process, output
            assert config.read_text() == text, "UI changed the application TOML file"
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            assert SECRET.encode() not in os.pread(output.fileno(), 1_048_576, 0), "Logs exposed a password"


@contextmanager
def browser(chrome_binary):
    with tempfile.TemporaryDirectory(prefix="ovpn-config-browser-") as profile:
        with tempfile.TemporaryFile() as output:
            chrome = subprocess.Popen([
                chrome_binary, "--headless=new", "--disable-gpu", "--disable-dev-shm-usage",
                "--no-first-run", "--no-default-browser-check", "--remote-debugging-port=0",
                f"--user-data-dir={profile}", "about:blank",
            ], stdout=output, stderr=output, start_new_session=True)
            cdp = None
            try:
                port_file = Path(profile) / "DevToolsActivePort"
                wait_for(lambda: port_file.exists())
                port = port_file.read_text().splitlines()[0]
                with urlopen(f"http://127.0.0.1:{port}/json", timeout=10) as response:
                    page = next(item for item in json.load(response) if item["type"] == "page")
                cdp = DevTools(page["webSocketDebuggerUrl"])
                yield cdp
            finally:
                if cdp is not None:
                    try:
                        cdp.call("Browser.close")
                    except (OSError, RuntimeError):
                        pass
                    cdp.socket.close()
                elif chrome.poll() is None:
                    os.killpg(chrome.pid, signal.SIGTERM)
                try:
                    chrome.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(chrome.pid, signal.SIGKILL)
                    chrome.wait()


def fill(cdp, selector, value):
    cdp.evaluate(f"""(() => {{ const input = document.querySelector({json.dumps(selector)});
        input.value = {json.dumps(value)}; input.dispatchEvent(new Event('input', {{ bubbles: true }})); }})()""")


def element(attribute, identifier):
    return f"document.querySelector({json.dumps(f'[{attribute}={json.dumps(identifier)}]')})"


def exercise(cdp, url, directory):
    cdp.call("Runtime.enable")
    cdp.call("Network.enable")
    cdp.call("Page.enable")
    cdp.call("Page.navigate", url=url)
    cdp.wait("document.querySelector('#pool-phase')?.textContent === 'Unconfigured'")
    check(cdp, "document.querySelectorAll('[role=tab]').length === 6")
    cdp.evaluate("document.querySelector('[data-tab=configuration]').click()")
    cdp.wait("!document.querySelector('#configuration').hidden && document.querySelector('#configuration-state').textContent === 'No configuration active'")
    profile = directory / "test.ovpn"
    profile.write_text(PROFILE)
    cdp.call("DOM.enable")
    root = cdp.call("DOM.getDocument")["root"]["nodeId"]
    node = cdp.call("DOM.querySelector", nodeId=root, selector="#configuration-file")["nodeId"]
    cdp.call("DOM.setFileInputFiles", nodeId=node, files=[str(profile)])
    cdp.wait("document.querySelector('#configuration-file-status').textContent === 'Selected: test.ovpn'")
    fill(cdp, "#configuration-name", "Ireland")
    fill(cdp, "#configuration-username", "test-user")
    fill(cdp, "#configuration-password", SECRET)
    cdp.evaluate("document.querySelector('#configuration-save').click()")
    cdp.wait("document.querySelector('[data-configuration-id]') && document.querySelector('#configuration-notice').textContent.startsWith('Saved.')")
    identifier = api(url)["configurations"][0]["id"]
    row = element("data-configuration-id", identifier)
    edit_button = element("data-edit-config", identifier)
    activate_button = element("data-activate-config", identifier)
    check(cdp, "document.querySelector('#configuration-password').value === ''")
    assert api(url)["status"]["phase"] == "unconfigured", "Save activated a configuration"
    cdp.evaluate(f"{edit_button}.click()")
    cdp.wait("document.querySelector('#configuration-password').placeholder.includes('leave blank')")
    fill(cdp, "#configuration-name", "Ireland edited")
    fill(cdp, "#configuration-username", "edited-user")
    fill(cdp, "#configuration-dns", "1.1.1.1")
    fill(cdp, "#configuration-dns-tls-name", "cloudflare-dns.com")
    cdp.evaluate("document.querySelector('#configuration-save').click()")
    cdp.wait(f"{row}.querySelector('strong').textContent === 'Ireland edited'")
    stored = tomllib.loads((directory / "configs" / f"{identifier}.toml").read_text())
    assert stored["revision"] == 2
    assert stored["openvpn_config"]["dns_override"] == "1.1.1.1"
    assert stored["openvpn_config"]["dns_tls_name"] == "cloudflare-dns.com"
    assert api(url)["configurations"][0]["dns_tls_name"] == "cloudflare-dns.com"
    check(cdp, "document.querySelector('#configuration-dns-tls-name').value === 'cloudflare-dns.com'")
    assert stored["openvpn_config"]["password"] == SECRET
    assert stored["openvpn_config"]["profile_text"] == PROFILE
    cdp.evaluate(f"window.confirm = () => false; {activate_button}.click()")
    assert api(url)["status"]["phase"] == "unconfigured"
    cdp.evaluate(f"window.confirm = () => true; {activate_button}.click()")
    # Invalid fixture CA fails locally, before sending an OpenVPN handshake.
    wait_for(lambda: api(url)["status"]["phase"] == "failed")
    cdp.wait("document.querySelector('#configuration-state').textContent === 'Failed: Ireland edited'")
    cdp.wait("document.querySelector('#pool-phase').textContent === 'Failed'")
    check(cdp, "document.querySelector('#feed-label').textContent === 'Live'")
    check(cdp, "document.querySelector('#configuration-password').value === ''")
    cdp.evaluate(f"{activate_button}.click()")
    wait_for(lambda: api(url)["status"]["generation"] == 2 and api(url)["status"]["phase"] == "failed")
    value = {"name": "Delete me", "username": "user", "password": SECRET,
             "profile": {"name": "other.ovpn", "content": PROFILE}}
    temporary = api(url, method="POST", body=value, expected=201)
    temporary_row = element("data-configuration-id", temporary["id"])
    delete_button = element("data-delete-config", temporary["id"])
    cdp.wait(f"{temporary_row} !== null")
    cdp.evaluate(f"window.confirm = () => false; {delete_button}.click()")
    assert any(entry["id"] == temporary["id"] for entry in api(url)["configurations"])
    cdp.evaluate(f"window.confirm = () => true; {delete_button}.click()")
    cdp.wait(f"{temporary_row} === null")
    assert not (directory / "configs" / f"{temporary['id']}.toml").exists()
    cdp.call("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=1, mobile=True)
    cdp.wait("document.documentElement.clientWidth === 390")
    check(cdp, "document.documentElement.scrollWidth <= 390")
    assert not cdp.errors, cdp.errors
    return identifier


def missing_file_warning(cdp, url, other_id):
    cdp.call("Runtime.enable")
    cdp.call("Network.enable")
    cdp.call("Page.enable")
    cdp.call("Page.navigate", url=url)
    cdp.wait("document.querySelector('#configuration-missing-warning')?.getBoundingClientRect().height > 80")
    check(cdp, "document.querySelector('#configuration-missing-warning').getAttribute('role') === 'alert'")
    check(cdp, "getComputedStyle(document.querySelector('#configuration-missing-warning')).borderTopWidth === '2px'")
    check(cdp, "parseFloat(getComputedStyle(document.querySelector('#configuration-missing-warning strong')).fontSize) >= 20")
    cdp.wait("document.querySelector('#configuration-missing-warning p').textContent.includes('missing')")
    cdp.call("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=1, mobile=True)
    cdp.wait("document.documentElement.clientWidth === 390")
    check(cdp, "document.documentElement.scrollWidth <= 390")
    cdp.evaluate("document.querySelector('#configuration-missing-warning button').click()")
    cdp.wait("!document.querySelector('#configuration').hidden")
    default_delete = element("data-delete-config", "default")
    cdp.wait(f"{default_delete} !== null")
    check(cdp, f"getComputedStyle({default_delete}).display === 'none'")
    activate_button = element("data-activate-config", other_id)
    cdp.evaluate(f"window.confirm = () => true; {activate_button}.click()")
    wait_for(lambda: api(url)["status"]["id"] == other_id and api(url)["status"]["phase"] == "failed")
    cdp.wait("getComputedStyle(document.querySelector('#configuration-missing-warning')).display === 'none'")
    delete_button = element("data-delete-config", other_id)
    cdp.wait(f"{delete_button} && !{delete_button}.disabled")
    cdp.evaluate(f"{delete_button}.click()")
    cdp.wait(f"{element('data-configuration-id', other_id)} === null")
    cdp.wait("document.querySelector('#configuration-state').textContent === 'No configuration active'")
    cdp.wait("document.querySelector('#pool-phase').textContent === 'Unconfigured'")
    check(cdp, "document.querySelector('#feed-label').textContent === 'Live'")
    cdp.call("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=1, mobile=True)
    check(cdp, "document.documentElement.scrollWidth <= 390")
    assert not cdp.errors, cdp.errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--chrome", default="google-chrome")
    args = parser.parse_args()
    binary = args.app.resolve()
    with tempfile.TemporaryDirectory(prefix="ovpn-config-app-") as root:
        directory = Path(root)
        with application(binary, directory) as (url, _, _output):
            assert api(url)["configurations"] == []
            assert not (directory / "configs").exists()
            with browser(args.chrome) as cdp:
                identifier = exercise(cdp, url, directory)
            value = {"name": "Other", "username": "u", "password": SECRET,
                     "profile": {"name": "other.ovpn", "content": PROFILE}}
            api(url, method="POST", body=value, expected=403, origin="http://other.example")
            api(url, method="POST", body=value, expected=403, origin=False)
            api(url, f"/api/configurations/{identifier}", "PUT", value, expected=403, origin="http://other.example")
            api(url, f"/api/configurations/{identifier}", "DELETE", {"revision": 2}, expected=403, origin=False)
            value["profile"]["content"] = "PRIVATE_PROFILE invalid"
            error = api(url, method="POST", body=value, expected=422)
            assert "PRIVATE_PROFILE" not in error["error"]
            value["profile"]["content"] = PROFILE
            other = api(url, method="POST", body=value, expected=201)
            api(url, f"/api/configurations/{identifier}/activate", "POST", {"revision": 1}, expected=409)
            assert len(api(url)["configurations"]) == 2
            assert not (directory / "configs" / "active.toml").exists(), "Failed activation replaced startup selection"

        # A failed activation is not remembered. Saved settings still survive restart.
        with application(binary, directory) as (url, _, _output):
            listing = api(url)
            assert len(listing["configurations"]) == 2
            assert listing["status"]["phase"] == "unconfigured"
            api(url, f"/api/configurations/{identifier}", "PUT",
                {"name": "Latest saved", "username": "latest-user", "revision": 2})

        # Seed only the ID, as a previously successful activation would do. Unit tests
        # separately verify the success commit; this exercises real process startup.
        active_path = directory / "configs" / "active.toml"
        active_path.write_text(f'id = "{identifier}"\n')
        with application(binary, directory, default=True) as (url, _, _output):
            wait_for(lambda: api(url)["status"]["phase"] == "failed")
            listing = api(url)
            assert listing["status"]["id"] == identifier
            assert listing["status"]["name"] == "Latest saved"
            assert listing["status"]["revision"] == 3
            assert listing["configurations"][0]["id"] == "default"
            assert listing["configurations"][0]["read_only"]
            api(url, "/api/configurations/default", "PUT", value, expected=403)
            api(url, "/api/configurations/default", "DELETE", {"revision": 1}, expected=403)
            api(url, f"/api/configurations/{identifier}", "DELETE", {"revision": 3}, expected=204)
            assert not active_path.exists()
            assert api(url)["status"]["phase"] == "unconfigured"

        # A file removed outside the app must produce the prominent warning and ERROR log.
        active_path.write_text(f'id = "{identifier}"\n')
        with application(binary, directory, default=True) as (url, _, output):
            wait_for(lambda: api(url)["status"]["file_missing"])
            log = os.pread(output.fileno(), 1_048_576, 0)
            assert b"ERROR" in log and b"configuration file is missing" in log
            with browser(args.chrome) as cdp:
                missing_file_warning(cdp, url, other["id"])

        # Headless startup also reports a missing last active configuration.
        active_path.write_text('id = "default"\n')
        headless = directory / "headless.toml"
        headless.write_text('socks5_address = "127.0.0.1:0"\n')
        result = subprocess.run([str(binary), str(headless)], cwd=directory, capture_output=True,
                                env={**os.environ, "RUST_LOG": "info"}, timeout=10)
        assert result.returncode != 0 and b"last active Default configuration is missing" in result.stderr
        assert b"ERROR" in result.stdout + result.stderr
        assert SECRET.encode() not in result.stdout + result.stderr

    print("PASS: latest startup selection, failed-switch protection, add/edit/delete, missing-file banner and ERROR logs, recovery, persistence, read-only default, and mobile layout", flush=True)


if __name__ == "__main__":
    main()
