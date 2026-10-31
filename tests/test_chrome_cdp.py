"""Live Chrome checks for focused-page capture.

These tests drive a real Chrome process through the debugging port. They do
not replace the permission and expiry tests; they check that the adapter
reads only the focused ordinary page.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from steward import ChromeCdpExtractor, ManualClock, Steward
from steward.chrome_cdp import CdpBrowser

FOCUSED_TITLE = "FOCUSED_LIVE_TITLE"
FOCUSED_BODY = "FOCUSED_LIVE_BODY"
BACKGROUND_TITLE = "BACKGROUND_LIVE_TITLE"
BACKGROUND_BODY = "BACKGROUND_LIVE_BODY"
OTHER_TITLE = "OTHER_WINDOW_LIVE_TITLE"
OTHER_BODY = "OTHER_WINDOW_LIVE_BODY"
REVOKED_TITLE = "REVOKED_LIVE_TITLE"
REVOKED_BODY = "REVOKED_LIVE_BODY"
UNAPPROVED_TITLE = "UNAPPROVED_LIVE_TITLE"
UNAPPROVED_BODY = "UNAPPROVED_LIVE_BODY"
PRIVATE_TITLE = "PRIVATE_LIVE_TITLE"
PRIVATE_BODY = "PRIVATE_LIVE_BODY"
NOTITLE_BODY = "NOTITLE_LIVE_BODY"
LIVE_PATH_SECRET = "LIVE_PATH_SECRET"
LIVE_QUERY_SECRET = "LIVE_QUERY_SECRET"

_PAGES = {
    "/focused": (FOCUSED_TITLE, FOCUSED_BODY),
    "/background": (BACKGROUND_TITLE, BACKGROUND_BODY),
    "/other": (OTHER_TITLE, OTHER_BODY),
    "/revoked": (REVOKED_TITLE, REVOKED_BODY),
    "/unapproved": (UNAPPROVED_TITLE, UNAPPROVED_BODY),
    "/private": (PRIVATE_TITLE, PRIVATE_BODY),
    f"/{LIVE_PATH_SECRET}": ("", NOTITLE_BODY),
}


def _html(title: str, body: str) -> str:
    title_tag = f"<title>{title}</title>" if title else ""
    return _document(title_tag, body)


def _document(title_tag: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">{title_tag}
<script>
window.__contentReads = 0;
window.__cookieReads = 0;
(function () {{
  function arm(prop, proto) {{
    var desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get) return;
    Object.defineProperty(proto, prop, {{
      configurable: true,
      get: function () {{
        window.__contentReads += 1;
        return desc.get.call(this);
      }}
    }});
  }}
  arm("innerText", HTMLElement.prototype);
  arm("innerHTML", Element.prototype);
  arm("textContent", Node.prototype);
  var cookie = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
  if (cookie && cookie.get) {{
    Object.defineProperty(Document.prototype, "cookie", {{
      configurable: true,
      get: function () {{
        window.__cookieReads += 1;
        return cookie.get.call(this);
      }}
    }});
  }}
}})();
</script></head><body><p>{body}</p></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        page = _PAGES.get(urlsplit(self.path).path)
        if page is None:
            self.send_response(404)
            self.end_headers()
            return
        payload = _html(*page).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        """Drop request logs so URLs are not copied into the test output."""


class _Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class _Chrome:
    def __init__(self, debugger_url: str, chrome: subprocess.Popen[bytes], display: subprocess.Popen[bytes]) -> None:
        self.debugger_url = debugger_url
        self._chrome = chrome
        self._display = display

    def close(self) -> None:
        _stop_process(self._chrome)
        _stop_process(self._display)


@pytest.fixture
def pages() -> Iterator[str]:
    server = _Server(("::", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


@pytest.fixture
def chrome(tmp_path: Path) -> Iterator[_Chrome]:
    binary = shutil.which("google-chrome")
    if binary is None:
        raise AssertionError("google-chrome is not installed")
    display_number = 120 + (os.getpid() % 200)
    display_name = f":{display_number}"
    display = subprocess.Popen(
        ["Xvfb", display_name, "-screen", "0", "1280x800x24"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    port = _free_port()
    profile = tmp_path / "chrome-profile"
    env = os.environ.copy()
    env["DISPLAY"] = display_name
    process = subprocess.Popen(
        [
            binary,
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-sync",
            f"--remote-debugging-port={port}",
            f"--user-data-dir={profile}",
            "--window-size=1280,800",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )
    session = _Chrome(f"http://127.0.0.1:{port}", process, display)
    try:
        _wait_for_debugger(session.debugger_url)
        yield session
    finally:
        session.close()


def test_debugger_connection_failure_is_an_error() -> None:
    extractor = ChromeCdpExtractor("http://127.0.0.1:1", timeout=0.4)
    with pytest.raises(OSError):
        extractor.capture()


def test_live_chrome_reads_only_the_focused_page(
    chrome: _Chrome, pages: str, tmp_path: Path
) -> None:
    with CdpBrowser(chrome.debugger_url) as browser:
        background = _open_page(browser, f"{pages}/background")
        other = _open_page(browser, f"{pages}/other", new_window=True)
        focused = _open_page(browser, f"{pages}/focused", new_window=True)
        browser.call("Target.activateTarget", {"targetId": focused})
        _wait_for_title(browser, focused, FOCUSED_TITLE)
        _wait_for_title(browser, background, BACKGROUND_TITLE)
        _wait_for_title(browser, other, OTHER_TITLE)
        before = {target: _counter(browser, target, "__contentReads") for target in (focused, background, other)}
        cookies = {target: _counter(browser, target, "__cookieReads") for target in (focused, background, other)}

    observation = _capture_title(chrome.debugger_url, FOCUSED_TITLE)
    assert observation.focused is True
    assert observation.incognito is False
    assert [page.title for page in observation.pages] == [FOCUSED_TITLE]
    assert observation.pages[0].active is True
    assert observation.pages[0].body is not None
    assert FOCUSED_BODY in observation.pages[0].body
    rendered = repr(observation)
    assert BACKGROUND_BODY not in rendered
    assert BACKGROUND_TITLE not in rendered
    assert OTHER_BODY not in rendered
    assert OTHER_TITLE not in rendered

    with CdpBrowser(chrome.debugger_url) as browser:
        assert _counter(browser, focused, "__contentReads") == before[focused] + 1
        assert _counter(browser, background, "__contentReads") == before[background]
        assert _counter(browser, other, "__contentReads") == before[other]
        for target, count in cookies.items():
            assert _counter(browser, target, "__cookieReads") == count

    app = Steward(clock=ManualClock(datetime(2026, 3, 1, tzinfo=timezone.utc)), data_dir=tmp_path / "pc")
    app.approve_site("127.0.0.1")
    app.start_observation()
    app.observe(observation)
    records = app.activity_records()
    assert len(records) == 1
    assert records[0]["domain"] == "127.0.0.1"
    assert records[0]["title"] == FOCUSED_TITLE
    assert records[0]["page_content"] == "available"
    assert app.read_body(str(records[0]["id"])).text == observation.pages[0].body
    stored = _stored_text(tmp_path / "pc")
    assert BACKGROUND_BODY not in stored
    assert OTHER_BODY not in stored


def test_live_chrome_revocation_and_unapproved_host(
    chrome: _Chrome, pages: str, tmp_path: Path
) -> None:
    app = Steward(clock=ManualClock(datetime(2026, 3, 1, tzinfo=timezone.utc)), data_dir=tmp_path / "pc")
    app.approve_site("127.0.0.1")
    app.start_observation()
    with CdpBrowser(chrome.debugger_url) as browser:
        focused = _open_page(browser, f"{pages}/focused", new_window=True)
        browser.call("Target.activateTarget", {"targetId": focused})
        _wait_for_title(browser, focused, FOCUSED_TITLE)
    first = _capture_title(chrome.debugger_url, FOCUSED_TITLE)
    app.observe(first)
    first_id = str(app.activity_records()[0]["id"])
    app.revoke_site("127.0.0.1")

    with CdpBrowser(chrome.debugger_url) as browser:
        session = browser.attach(focused)
        browser.call("Page.navigate", {"url": f"{pages}/revoked"}, session_id=session)
        _wait_for_title(browser, focused, REVOKED_TITLE)
    revoked = _capture_title(chrome.debugger_url, REVOKED_TITLE)
    app.observe(revoked)
    assert REVOKED_BODY not in _stored_text(app.data_dir)
    assert app.read_body(first_id).text == first.pages[0].body
    assert app.activity_records()[-1]["page_content"] == "not_permitted"

    with CdpBrowser(chrome.debugger_url) as browser:
        unapproved = _open_page(browser, f"http://localhost:{urlsplit(pages).port}/unapproved", new_window=True)
        browser.call("Target.activateTarget", {"targetId": unapproved})
        _wait_for_title(browser, unapproved, UNAPPROVED_TITLE)
    ordinary = _capture_title(chrome.debugger_url, UNAPPROVED_TITLE)
    app.observe(ordinary)
    record = app.activity_records()[-1]
    assert record["domain"] == "localhost"
    assert record["title"] == UNAPPROVED_TITLE
    assert record["page_content"] == "not_permitted"
    assert UNAPPROVED_BODY not in _stored_text(app.data_dir)
    assert "unapproved" not in _stored_text(app.data_dir)


def test_live_chrome_incognito_window_keeps_no_page_identity(
    chrome: _Chrome, pages: str, tmp_path: Path
) -> None:
    app = Steward(clock=ManualClock(datetime(2026, 3, 1, tzinfo=timezone.utc)), data_dir=tmp_path / "pc")
    app.approve_site("127.0.0.1")
    app.start_observation()
    with CdpBrowser(chrome.debugger_url) as browser:
        context = browser.call("Target.createBrowserContext")
        context_id = context["browserContextId"]
        assert isinstance(context_id, str)
        private = _open_page(
            browser,
            f"{pages}/private",
            new_window=True,
            browser_context_id=context_id,
        )
        browser.call("Target.activateTarget", {"targetId": private})
        _wait_for_title(browser, private, PRIVATE_TITLE)
        reads_before = _counter(browser, private, "__contentReads")

    observation = _capture_incognito(chrome.debugger_url)
    assert observation.focused is True
    assert observation.incognito is True
    assert observation.pages == ()
    rendered = repr(observation)
    assert PRIVATE_TITLE not in rendered
    assert PRIVATE_BODY not in rendered
    assert "/private" not in rendered

    with CdpBrowser(chrome.debugger_url) as browser:
        assert _counter(browser, private, "__contentReads") == reads_before

    app.observe(observation)
    records = app.activity_records()
    assert len(records) == 1
    assert records[0]["application"] == "chrome"
    assert records[0]["title"] is None
    assert records[0]["domain"] is None
    assert records[0]["page_content"] == "not_captured"
    stored = _stored_text(app.data_dir)
    assert PRIVATE_TITLE not in stored
    assert PRIVATE_BODY not in stored
    assert "/private" not in stored


def test_live_chrome_untitled_page_does_not_keep_the_address(
    chrome: _Chrome, pages: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    app = Steward(clock=ManualClock(datetime(2026, 3, 1, tzinfo=timezone.utc)), data_dir=tmp_path / "pc")
    app.approve_site("127.0.0.1")
    app.start_observation()
    target_url = f"{pages}/{LIVE_PATH_SECRET}?token={LIVE_QUERY_SECRET}#LIVE_FRAG_SECRET"
    with CdpBrowser(chrome.debugger_url) as browser:
        opened = _open_page(browser, target_url, new_window=True)
        browser.call("Target.activateTarget", {"targetId": opened})
        _wait_until(
            lambda: browser.evaluate(browser.attach(opened), "document.body && document.body.innerText")
            == NOTITLE_BODY,
            "untitled page did not load",
        )
    extractor = ChromeCdpExtractor(chrome.debugger_url)
    found = None

    def captured() -> bool:
        nonlocal found
        observation = extractor.capture()
        if (
            observation.focused
            and len(observation.pages) == 1
            and observation.pages[0].title == ""
            and observation.pages[0].body is not None
            and NOTITLE_BODY in observation.pages[0].body
        ):
            found = observation
            return True
        return False

    _wait_until(captured, "untitled focused page was not captured")
    assert found is not None
    observation = found
    assert LIVE_PATH_SECRET not in observation.pages[0].title
    assert LIVE_QUERY_SECRET not in observation.pages[0].title
    app.observe(observation)
    record = app.activity_records()[0]
    assert record["domain"] == "127.0.0.1"
    assert record["title"] is None
    assert NOTITLE_BODY in (app.read_body(str(record["id"])).text or "")
    backup = tmp_path / "backup.zip"
    app.write_default_backup(backup)
    with zipfile.ZipFile(backup) as archive:
        backup_text = archive.read("activity-export.json").decode()
    stored = _stored_text(app.data_dir)
    for blob in (stored, json.dumps(app.export_records()), json.dumps(app.phone_sync_payload()), backup_text, caplog.text):
        assert LIVE_PATH_SECRET not in blob
        assert LIVE_QUERY_SECRET not in blob
        assert "LIVE_FRAG_SECRET" not in blob


def _open_page(
    browser: CdpBrowser,
    url: str,
    *,
    new_window: bool = False,
    browser_context_id: str | None = None,
) -> str:
    params: dict[str, object] = {"url": url}
    if new_window:
        params["newWindow"] = True
    if browser_context_id is not None:
        params["browserContextId"] = browser_context_id
    target_id = browser.call("Target.createTarget", params)["targetId"]
    if not isinstance(target_id, str):
        raise AssertionError("Chrome did not return a page id")
    return target_id


def _wait_for_title(browser: CdpBrowser, target_id: str, title: str) -> None:
    session = browser.attach(target_id)

    def loaded() -> bool:
        return browser.evaluate(session, "document.title") == title

    _wait_until(loaded, f"page title did not become {title}")


def _counter(browser: CdpBrowser, target_id: str, name: str) -> int:
    session = browser.attach(target_id)
    value = browser.evaluate(session, f"window.{name} || 0")
    if not isinstance(value, int):
        raise AssertionError("page counter was not a number")
    return value


def _capture_title(debugger_url: str, title: str) -> object:
    extractor = ChromeCdpExtractor(debugger_url)
    last = None

    def matched() -> bool:
        nonlocal last
        last = extractor.capture()
        return bool(
            last.focused
            and not last.incognito
            and len(last.pages) == 1
            and last.pages[0].title == title
            and last.pages[0].body is not None
            and title.split("_LIVE_")[0] in last.pages[0].body
        )

    _wait_until(matched, f"focused page {title} was not captured")
    assert last is not None
    return last


def _capture_incognito(debugger_url: str) -> object:
    extractor = ChromeCdpExtractor(debugger_url)
    last = None

    def matched() -> bool:
        nonlocal last
        last = extractor.capture()
        return bool(last.focused and last.incognito and last.pages == ())

    _wait_until(matched, "incognito window was not the focused capture")
    assert last is not None
    return last


def _wait_until(predicate: object, message: str) -> None:
    if not callable(predicate):
        raise AssertionError("predicate must be callable")
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(message)


def _stored_text(root: Path) -> str:
    chunks: list[str] = []
    for path in root.rglob("*"):
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def _wait_for_debugger(debugger_url: str) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{debugger_url}/json/version", timeout=0.3) as response:
                payload = json.load(response)
            if isinstance(payload, dict) and isinstance(payload.get("webSocketDebuggerUrl"), str):
                return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.1)
    raise AssertionError("Chrome debugging port did not open")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return int(port)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)
