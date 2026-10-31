# The component responsible for reading the focused Chrome page.
#
# It connects to a local Chrome debugging port, chooses the one visible page
# that Chrome reports as focused, and reads that page's body text. Other tabs
# are only asked whether they are focused. Incognito-style browser contexts
# contribute no page address and no body text.

"""Read the focused Chrome page through the DevTools debugging port."""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
from typing import cast
from urllib.parse import urlsplit
from urllib.request import urlopen

from steward.models import ChromeObservation, ChromePage


class ChromeCdpExtractor:
    """Capture the focused page from a Chrome instance with remote debugging."""

    def __init__(self, debugger_url: str, *, timeout: float = 5) -> None:
        """Store the debugging endpoint. Nothing is read until capture.

        Args:
            debugger_url: HTTP URL of Chrome's debugging port, such as
                http://127.0.0.1:9222.
            timeout: Seconds for each socket operation.
        """
        self._debugger_url = debugger_url.rstrip("/")
        self._timeout = timeout

    def capture(self) -> ChromeObservation:
        """Return the focused page, or an unfocused observation when focus is ambiguous."""
        with CdpBrowser(self._debugger_url, timeout=self._timeout) as browser:
            return _focused_observation(browser)


class CdpBrowser:
    """Small DevTools client used to set up and read a local Chrome."""

    def __init__(self, debugger_url: str, *, timeout: float = 5) -> None:
        self._debugger_url = debugger_url.rstrip("/")
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buffer = bytearray()
        self._next_id = 0

    def __enter__(self) -> CdpBrowser:
        try:
            self._connect()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the debugging socket."""
        sock = self._sock
        self._sock = None
        if sock is not None:
            sock.close()

    def call(
        self,
        method: str,
        params: dict[str, object] | None = None,
        *,
        session_id: str | None = None,
    ) -> dict[str, object]:
        """Send one DevTools command and return its result object."""
        self._next_id += 1
        message_id = self._next_id
        payload: dict[str, object] = {"id": message_id, "method": method}
        if params:
            payload["params"] = params
        if session_id is not None:
            payload["sessionId"] = session_id
        self._send_text(json.dumps(payload))
        while True:
            message = self._read_message()
            if message.get("id") != message_id:
                continue
            error = message.get("error")
            if isinstance(error, dict):
                detail = error.get("message")
                if isinstance(detail, str) and detail:
                    raise ConnectionError(detail)
                raise ConnectionError("chrome debugging command failed")
            return _object_dict(message.get("result"))

    def attach(self, target_id: str) -> str:
        """Attach to one page and return the flattened session id."""
        result = self.call("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        session_id = result.get("sessionId")
        if not isinstance(session_id, str):
            raise ConnectionError("chrome did not attach to the page")
        return session_id

    def evaluate(self, session_id: str, expression: str) -> object:
        """Evaluate one expression in an attached page."""
        result = self.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True},
            session_id=session_id,
        )
        if "exceptionDetails" in result:
            raise ConnectionError("chrome page evaluation failed")
        inner = result.get("result")
        if not isinstance(inner, dict) or "value" not in inner:
            raise ConnectionError("chrome page evaluation failed")
        return cast(object, inner["value"])

    def _connect(self) -> None:
        with urlopen(f"{self._debugger_url}/json/version", timeout=self._timeout) as response:
            version = _object_dict(json.loads(response.read().decode()))
        websocket_url = version.get("webSocketDebuggerUrl")
        if not isinstance(websocket_url, str):
            raise ConnectionError("chrome debugging socket was not available")
        parts = urlsplit(websocket_url)
        if parts.hostname is None or parts.port is None:
            raise ConnectionError("chrome debugging socket was not available")
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        sock = socket.create_connection((parts.hostname, parts.port), timeout=self._timeout)
        self._sock = sock
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parts.hostname}:{parts.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(request.encode())
        header = self._read_until(b"\r\n\r\n")
        status = header.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise ConnectionError("chrome debugging handshake failed")

    def _send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode())

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        sock = self._sock
        if sock is None:
            raise ConnectionError("chrome debugging socket is closed")
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        mask = os.urandom(4)
        header.extend(mask)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        sock.sendall(bytes(header) + masked)

    def _read_message(self) -> dict[str, object]:
        fragments = bytearray()
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x8:
                raise ConnectionError("chrome closed the debugging connection")
            if opcode in {0x0, 0x1}:
                if opcode == 0x1:
                    fragments = bytearray()
                fragments.extend(payload)
                if fin:
                    return _object_dict(json.loads(fragments.decode()))
                continue
            raise ConnectionError("chrome debugging frame was not text")

    def _read_frame(self) -> tuple[bool, int, bytes]:
        first, second = self._read_exact(2)
        fin = (first & 0x80) != 0
        opcode = first & 0x0F
        masked = (second & 0x80) != 0
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else b""
        payload = self._read_exact(length)
        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return fin, opcode, payload

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self._buffer:
            self._buffer.extend(self._recv())
        index = self._buffer.index(marker) + len(marker)
        found = bytes(self._buffer[:index])
        del self._buffer[:index]
        return found

    def _read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            self._buffer.extend(self._recv())
        found = bytes(self._buffer[:size])
        del self._buffer[:size]
        return found

    def _recv(self) -> bytes:
        sock = self._sock
        if sock is None:
            raise ConnectionError("chrome debugging socket is closed")
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("chrome closed the debugging connection")
        return chunk


def _focused_observation(browser: CdpBrowser) -> ChromeObservation:
    contexts = browser.call("Target.getBrowserContexts")
    default_context = contexts.get("defaultBrowserContextId")
    targets = browser.call("Target.getTargets").get("targetInfos")
    if not isinstance(default_context, str) or not isinstance(targets, list):
        return ChromeObservation(focused=False, incognito=False)
    focused: list[tuple[dict[str, object], str]] = []
    for item in targets:
        info = _maybe_dict(item)
        if info is None or info.get("type") != "page":
            continue
        target_id = info.get("targetId")
        if not isinstance(target_id, str):
            continue
        try:
            session = browser.attach(target_id)
            # Focus only. This expression must not read the page body.
            probe = browser.evaluate(
                session,
                "({visibility: document.visibilityState, focus: document.hasFocus()})",
            )
        except OSError:
            continue
        if not isinstance(probe, dict):
            continue
        if probe.get("focus") is True and probe.get("visibility") == "visible":
            focused.append((info, session))
    if len(focused) != 1:
        return ChromeObservation(focused=False, incognito=False)
    info, session = focused[0]
    if info.get("browserContextId") != default_context:
        # A non-default context is Chrome's incognito-style profile. Leave the
        # page address and text out of the observation entirely.
        return ChromeObservation(focused=True, incognito=True)
    return _ordinary_page(info, browser, session)


def _ordinary_page(
    info: dict[str, object],
    browser: CdpBrowser,
    session: str,
) -> ChromeObservation:
    target_id = info.get("targetId")
    url = info.get("url")
    title = info.get("title")
    if not isinstance(target_id, str) or not isinstance(url, str) or not isinstance(title, str):
        return ChromeObservation(focused=True, incognito=False)
    try:
        body_value = browser.evaluate(session, "document.body ? document.body.innerText : ''")
    except OSError:
        body_value = None
    if isinstance(body_value, str):
        body: str | None = body_value
        extraction = "ok"
    else:
        body = None
        extraction = "failed"
    return ChromeObservation(
        focused=True,
        incognito=False,
        pages=(
            ChromePage(
                page_id=target_id,
                active=True,
                url=url,
                title=title,
                body=body,
                extraction=extraction,
            ),
        ),
    )


def _object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConnectionError("chrome debugging message was not an object")
    typed: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ConnectionError("chrome debugging message was not an object")
        typed[key] = cast(object, item)
    return typed


def _maybe_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    typed: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            return None
        typed[key] = cast(object, item)
    return typed
