"""The spelling of HTTP/1.1 header names: `Client(http1_title_case_headers=...)`.

Python mirror of upstream's `e2e_http1_header_case.rs` and
`ws_upgrade_uses_client_http1_header_case`. Title-Case (`Content-Type`) is the
default; `False` sends every name in lowercase except `Host`, the ones lkrequest
writes itself included. The names are read from the raw request bytes, before
anything could normalise them: over plain HTTP and over TLS, for ordinary,
streamed and preconnected requests, and for a WebSocket handshake. `Host` keeps
its capital by a rewrite of the request head as it is written, so the last tests
check that a lookalike line in a chunked body or a WebSocket frame goes out
untouched.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
ORDER = ["host", "x-default", "x-mixed", "accept", "cookie"]
TITLE_CASE = ["Host", "X-Default", "X-Mixed", "Accept", "Cookie"]
# Mixed-case names and values: only the names may change on the way out.
REQUEST = {
    "headers": {"x-MIXED": "Value-MiXeD", "accept": "text/plain"},
    "cookies": {"test": "Cookie-MiXeD"},
    "body": b"body",
}
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# Request heads where only a body or a frame belongs: nothing in them may change.
LOOKALIKE_BODY = b"host: body\r\n\r\nPOST / HTTP/1.1\r\nhost: body\r\n\r\n"
LOOKALIKE_FRAME = b"GET / HTTP/1.1\r\nhost: frame\r\n\r\n"


@pytest.fixture
def tls(_certs) -> ssl.SSLContext:
    cert_file, key_file, _ = _certs
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.set_alpn_protocols(["http/1.1"])
    return context


def make_client(cls, title_case: bool | None, **kwargs):
    if title_case is not None:
        kwargs["http1_title_case_headers"] = title_case
    return cls(verify=False, default_headers={"X-Default": "Keep-MiXeD"}, **kwargs)


def title_cased(title_case: bool | None) -> bool:
    return title_case is not False


def check_request(request, title_case: bool | None) -> None:
    names = request.raw_names
    expected = TITLE_CASE if title_cased(title_case) else ["Host", *ORDER[1:]]
    assert names[:5] == expected, names
    assert names.count("Host") == 1
    assert request.values("x-default") == ["Keep-MiXeD"]
    assert request.values("x-mixed") == ["Value-MiXeD"]
    assert request.values("cookie") == ["test=Cookie-MiXeD"]
    # A header lkrequest adds itself is spelled the same way.
    assert ("Content-Length" if title_cased(title_case) else "content-length") in names
    if not title_cased(title_case):
        assert all(name == "Host" or name == name.lower() for name in names)


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("path", ["request", "streamed", "preconnected"])
@pytest.mark.parametrize("title_case", [None, True, False])
def test_http1_header_names(raw_http, tls, scheme, path, title_case):
    server = raw_http(lambda request: OK, ssl=tls if scheme == "https" else None)
    client = make_client(BlockingClient, title_case, header_order=ORDER)
    session = client.session(http1_only=True)
    url = f"{server.url}/headers"
    if path == "preconnected":
        session.preconnect(url)
    if path == "streamed":
        assert session.send_streaming("POST", url, **REQUEST).bytes() == b"OK"
    else:
        assert session.post(url, **REQUEST).content == b"OK"
    [request] = server.requests
    check_request(request, title_case)
    if path == "preconnected":
        # The request went out on the connection opened ahead of it.
        assert server.connections == 1


@pytest.mark.parametrize("title_case", [None, False])
async def test_the_async_client_takes_the_setting_too(raw_http, title_case):
    server = raw_http(lambda request: OK)
    client = make_client(lkrequest.Client, title_case, header_order=ORDER)
    await client.session(http1_only=True).post(f"{server.url}/headers", **REQUEST)
    [request] = server.requests
    check_request(request, title_case)


def accept_websocket(request) -> bytes:
    key = request.values("sec-websocket-key")[0]
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest())
    return (
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
    )


@pytest.mark.parametrize("title_case", [None, True, False])
def test_a_websocket_handshake_follows_the_client(raw_http, tls, title_case):
    server = raw_http(accept_websocket, ssl=tls)
    session = make_client(BlockingClient, title_case).session(http1_only=True)
    url = server.url.replace("https", "wss", 1) + "/ws"
    session.ws_connect(url, headers={"x-MIXED": "Value-MiXeD"}).close()
    [request] = server.requests
    expected = ["Host", "Upgrade", "Sec-Websocket-Key", "X-Default", "X-Mixed"]
    if not title_cased(title_case):
        expected = ["Host", *(name.lower() for name in expected[1:])]
    assert set(expected) <= set(request.raw_names), request.raw_names
    assert request.raw_names.count("Host") == 1
    assert request.values("x-default") == ["Keep-MiXeD"]
    assert request.values("x-mixed") == ["Value-MiXeD"]
    if not title_cased(title_case):
        assert all(name == "Host" or name == name.lower() for name in request.raw_names)


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
def test_the_client_reports_the_setting(client_cls):
    assert client_cls().http1_title_case_headers is True
    assert client_cls(http1_title_case_headers=True).http1_title_case_headers is True
    assert client_cls(http1_title_case_headers=False).http1_title_case_headers is False
    # The browser presets keep the default.
    assert client_cls.chrome_156().http1_title_case_headers is True


@pytest.mark.parametrize("streamed", [False, True], ids=["buffered", "streamed"])
def test_a_chunked_upload_goes_out_untouched(server_url, streamed):
    # Python mirror of upstream's `lowercase_headers_preserve_chunked_upload_bytes`.
    session = make_client(BlockingClient, False).session(http1_only=True)
    url = f"{server_url}/upload-echo"
    chunks = iter([LOOKALIKE_BODY[:7], LOOKALIKE_BODY[7:]])
    if streamed:
        response = session.send_streaming("POST", url, body_stream=chunks)
        report = json.loads(response.bytes())
    else:
        report = session.post(url, body_stream=chunks).json()
    # Over HTTP/1.1, where the rewrite runs.
    assert report["http_version"] == "1.1"
    assert report["transfer_encoding"] == "chunked"
    assert report["length"] == len(LOOKALIKE_BODY)
    assert report["sha256"] == hashlib.sha256(LOOKALIKE_BODY).hexdigest()


def test_websocket_frames_go_out_untouched(ws_server_url):
    # Python mirror of the frame check upstream added to
    # `ws_upgrade_uses_client_http1_header_case`.
    session = make_client(BlockingClient, False).session(http1_only=True)
    ws = session.ws_connect(f"{ws_server_url}/ws-echo")
    try:
        ws.send_binary(LOOKALIKE_FRAME)
        message = ws.recv()
    finally:
        ws.close()
    assert isinstance(message, lkrequest.WsMessage.Binary)
    assert message.data == LOOKALIKE_FRAME
