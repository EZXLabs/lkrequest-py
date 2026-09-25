"""Shared pytest fixtures.

`local_httpbin` starts a local httpbin-compatible server (the `httpbin` Flask
app wrapped as ASGI) under hypercorn, served over TLS with a self-signed cert.
It speaks HTTP/1.1 + HTTP/2 on TCP and HTTP/3 on the same UDP port (via
aioquic), so tests do not depend on the public httpbin.org being reachable.

Use the `server_url` fixture for the base URL and build clients with
`verify=False` (the cert is self-signed). The `server_ca` fixture exposes the
cert PEM for tests that prefer pinning over disabling verification.
"""

from __future__ import annotations

import asyncio
import codecs
import datetime
import hashlib
import ipaddress
import json
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

import pytest


def _make_self_signed_cert(cert_path, key_path):
    """Write a self-signed cert/key valid for localhost + 127.0.0.1."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_pem


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _ipv6_loopback_available() -> bool:
    """Whether this host can bind ::1 (CI containers often run without IPv6)."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def _wait_until_listening(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"local server on port {port} did not start in time")


class _ServerHandle:
    def __init__(self, port: int, ca_pem: bytes, stop, thread, *, ipv6: bool = False):
        self.port = port
        self.ca_pem = ca_pem
        self.url = f"https://127.0.0.1:{port}"
        # Set only when the server also listens on ::1.
        self.ipv6_url = f"https://[::1]:{port}" if ipv6 else None
        self._stop = stop
        self._thread = thread

    def shutdown(self):
        self._stop.set()
        self._thread.join(timeout=5.0)


def _with_early_hints(inner):
    """Add an `/early-hints` route that emits `103` before its final `200`.

    httpbin is a WSGI app and so cannot send 1xx informational responses, which
    makes it useless for pinning the HTTP/2 interim-response path. This shim
    serves one directly: a `103 Early Hints` block followed by the real `200`,
    mirroring what Cloudflare sends. Everything else is delegated to httpbin.

    Hypercorn only offers the extension on HTTP/2 and HTTP/3, so on HTTP/1.1
    the hint is skipped and the client just sees the final response.
    """

    async def app(scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/early-hints":
            await inner(scope, receive, send)
            return

        if "http.response.early_hint" in scope.get("extensions", {}):
            await send(
                {
                    "type": "http.response.early_hint",
                    "links": [b"</style.css>; rel=preload; as=style"],
                }
            )
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"final"})

    return app


def _with_upload_echo(inner):
    """Add an `/upload-echo` endpoint that reports the request body it read.

    httpbin is a WSGI app, and WSGI cannot read a request body without
    `CONTENT_LENGTH`: an unknown-length upload reaches it as an empty body over
    HTTP/2, and Werkzeug answers chunked HTTP/1.1 with `501 Not Implemented`.
    Neither is a client-side limit — the very same bytes with a length arrive at
    httpbin intact — so streaming-upload tests need a handler that reads the
    ASGI body itself.

    Reports the byte count and digest rather than echoing the body, so the same
    endpoint works for a payload of any size, plus the framing headers the
    server saw: that is how a test tells `Content-Length` from chunked framing.
    """

    async def app(scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/upload-echo":
            await inner(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break

        headers = {
            key.decode("latin-1"): value.decode("latin-1")
            for key, value in scope["headers"]
        }
        payload = json.dumps(
            {
                "length": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "content_length": headers.get("content-length"),
                "transfer_encoding": headers.get("transfer-encoding"),
                "http_version": scope.get("http_version"),
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    return app


#: Default body for `/charset`. Encodable in GBK, Big5 and the other CJK
#: charsets the tests reach for, and every character is outside ASCII, so a
#: decode that silently fell back to UTF-8 cannot accidentally pass.
_CHARSET_SAMPLE = "中文测试"


def _with_charset_body(inner):
    """Add a `/charset` endpoint serving a body in a non-UTF-8 charset.

    httpbin's only charset route is `/encoding/utf8`, so there is nothing to
    point a GBK / Shift_JIS test at. Query parameters:

    - `label`: charset to encode the body with, also the `charset=` value sent
      back (default `gbk`);
    - `text`: body content, given as UTF-8 and re-encoded to `label`
      (default `_CHARSET_SAMPLE`);
    - `declare`: the `charset=` value to send, defaulting to `label`. `0` omits
      it entirely — a server that leaves the encoding to be guessed — and any
      other value declares a charset that disagrees with the bytes, which is a
      server that states the wrong one;
    - `bom=1`: prefix a UTF-8 BOM, to check it is honoured and stripped.

    `content-length` is set from the encoded bytes, so a test can also tell that
    byte length and character count differ.
    """

    async def app(scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/charset":
            await inner(scope, receive, send)
            return

        query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
        label = query.get("label", ["gbk"])[0]
        body = query.get("text", [_CHARSET_SAMPLE])[0].encode(label)
        if query.get("bom", ["0"])[0] == "1":
            body = codecs.BOM_UTF8 + body
        declared = query.get("declare", [label])[0]
        content_type = (
            "text/plain" if declared == "0" else f"text/plain; charset={declared}"
        )

        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", content_type.encode("latin-1")),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app


#: Text frame that makes `/ws-echo` reply with JSON describing the handshake
#: request it received, instead of echoing. Exposed as the `ws_handshake_probe`
#: fixture.
_WS_HANDSHAKE_PROBE = "__handshake__"


def _with_websocket_echo(inner):
    """Add a `/ws-echo` WebSocket endpoint that echoes every frame it receives.

    httpbin has no WebSocket route, so without this the only coverage for
    `session.ws_connect(...)` is the live wss://echo.websocket.org test, which
    is skipped by default. That matters more than it looks: the client fails
    the connection unless the server's `Sec-WebSocket-Accept` matches
    base64(SHA1(key + RFC 6455 GUID)), so a conforming server is what pins the
    handshake. Hypercorn computes the token per spec, which is exactly the
    property under test — a client-side GUID or validation regression cannot
    complete a handshake against it.

    The route match runs on `urlsplit(...).path` because upstream sends the
    upgrade in absolute-form, so the whole URI arrives as the ASGI `path`. That
    defect is pinned separately by the xfail tests in test_local_server.py and
    written up in docs/UPSTREAM-WS-REQUEST-TARGET.md; normalising here keeps it
    from blocking the handshake coverage above.

    Sending `_WS_HANDSHAKE_PROBE` gets back JSON describing the request line and
    Host header the server saw, which is how those xfail tests observe them.

    Anything that is not a WebSocket scope is delegated untouched.
    """

    async def app(scope, receive, send):
        if scope["type"] != "websocket":
            await inner(scope, receive, send)
            return

        message = await receive()
        if message["type"] != "websocket.connect":
            return
        if urlsplit(scope.get("path", "")).path != "/ws-echo":
            await send({"type": "websocket.close", "code": 1000})
            return

        await send({"type": "websocket.accept"})
        while True:
            message = await receive()
            if message["type"] == "websocket.disconnect":
                return
            if message["type"] != "websocket.receive":
                continue
            text = message.get("text")
            if text == _WS_HANDSHAKE_PROBE:
                host = next(
                    (v for k, v in scope.get("headers", []) if k == b"host"), b""
                )
                await send(
                    {
                        "type": "websocket.send",
                        "text": json.dumps(
                            {
                                "raw_path": scope.get("raw_path", b"").decode(
                                    "latin-1"
                                ),
                                "host": host.decode("latin-1"),
                            }
                        ),
                    }
                )
            elif text is not None:
                await send({"type": "websocket.send", "text": text})
            elif message.get("bytes") is not None:
                await send({"type": "websocket.send", "bytes": message["bytes"]})

    return app


def _start_server(cert_file, key_file, ca_pem, *, with_quic: bool) -> _ServerHandle:
    """Start a hypercorn httpbin server in a background thread.

    `with_quic=False` (the default for behavioral tests) deliberately omits
    `quic_bind` so the server does NOT advertise Alt-Svc h3 — otherwise the
    Chrome protocol policy would upgrade multi-hop requests to HTTP/3 and make
    tests non-deterministic. The dedicated H3 server sets `with_quic=True`.
    """
    from asgiref.wsgi import WsgiToAsgi
    from httpbin import app as flask_app
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    port = _free_port()
    asgi_app = _with_websocket_echo(
        _with_charset_body(_with_upload_echo(_with_early_hints(WsgiToAsgi(flask_app))))
    )

    config = Config()
    config.bind = [f"127.0.0.1:{port}"]
    # The H3 server also listens on ::1 where the host has it, so HTTP/3 over
    # IPv6 can be exercised (`h3_server_url_ipv6`). The plain server stays
    # IPv4-only: the ip_family tests rely on ::1 being refused there.
    ipv6 = with_quic and _ipv6_loopback_available()
    if ipv6:
        config.bind.append(f"[::1]:{port}")
    config.certfile = str(cert_file)
    config.keyfile = str(key_file)
    config.loglevel = "ERROR"
    if with_quic:
        config.quic_bind = list(config.bind)  # HTTP/3 over UDP, same port
        config.alpn_protocols = ["h3", "h2", "http/1.1"]
    else:
        config.alpn_protocols = ["h2", "http/1.1"]

    stop = threading.Event()

    async def _shutdown_trigger():
        while not stop.is_set():
            await asyncio.sleep(0.05)

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                serve(asgi_app, config, shutdown_trigger=_shutdown_trigger)
            )
        except BaseException:
            # Graceful shutdown cancels any handler still parked on receive()
            # (e.g. an H3 request whose client reset the stream and went away,
            # as the xfailed test_h3_get leaves behind). Hypercorn answers the
            # cancellation by writing a 500 to that already-reset QUIC stream,
            # aioquic asserts, and the ExceptionGroup escapes serve() — which
            # pytest would report as an unhandled thread exception. Once stop
            # is set the server has done its job and teardown noise is
            # dropped; anything earlier is a real failure and still raises.
            if not stop.is_set():
                raise
        finally:
            loop.close()

    thread = threading.Thread(target=_run, name="hypercorn-test-server", daemon=True)
    thread.start()
    _wait_until_listening(port)
    return _ServerHandle(port, ca_pem, stop, thread, ipv6=ipv6)


@pytest.fixture(scope="session")
def _certs(tmp_path_factory):
    certs = tmp_path_factory.mktemp("certs")
    cert_file = certs / "cert.pem"
    key_file = certs / "key.pem"
    ca_pem = _make_self_signed_cert(cert_file, key_file)
    return cert_file, key_file, ca_pem


@pytest.fixture(scope="session")
def _server(_certs):
    cert_file, key_file, ca_pem = _certs
    handle = _start_server(cert_file, key_file, ca_pem, with_quic=False)
    try:
        yield handle
    finally:
        handle.shutdown()


@pytest.fixture(scope="session")
def server_url(_server) -> str:
    """Base URL of the local httpbin server (HTTP/1.1 + HTTP/2, no Alt-Svc)."""
    return _server.url


@pytest.fixture(scope="session")
def server_ca(_server) -> bytes:
    """PEM bytes of the server's self-signed cert (for pinning via ca_cert_pem)."""
    return _server.ca_pem


@pytest.fixture(scope="session")
def ws_server_url(_server) -> str:
    """`wss://` base URL of the same server; `/ws-echo` is the echo endpoint."""
    return f"wss://127.0.0.1:{_server.port}"


@pytest.fixture(scope="session")
def ws_handshake_probe() -> str:
    """Text frame that makes `/ws-echo` describe the handshake it received."""
    return _WS_HANDSHAKE_PROBE


@pytest.fixture(scope="session")
def charset_sample() -> str:
    """Body `/charset` serves by default, as the text it should decode back to."""
    return _CHARSET_SAMPLE


@pytest.fixture(scope="session")
def _h3_server(_certs):
    cert_file, key_file, ca_pem = _certs
    handle = _start_server(cert_file, key_file, ca_pem, with_quic=True)
    try:
        yield handle
    finally:
        handle.shutdown()


@pytest.fixture(scope="session")
def h3_server_url(_h3_server) -> str:
    """Base URL of a dedicated HTTP/3-capable server (quic_bind enabled).

    Started lazily so it only runs for tests that request it (e.g. the H3
    functional test under the quic-h3 build).
    """
    return _h3_server.url


@pytest.fixture(scope="session")
def h3_server_url_ipv6(_h3_server) -> str:
    """The same HTTP/3 server over IPv6 (``https://[::1]:port``); skips without ::1."""
    if _h3_server.ipv6_url is None:
        pytest.skip("this host cannot bind the IPv6 loopback ::1")
    return _h3_server.ipv6_url


@pytest.fixture(scope="session")
def _masque_proxy_server(_certs):
    from _masque_proxy import MasqueProxy

    cert_file, key_file, _ = _certs
    proxy = MasqueProxy(cert_file, key_file)
    try:
        yield proxy
    finally:
        proxy.shutdown()


@pytest.fixture
def masque_proxy(_masque_proxy_server):
    """A local MASQUE CONNECT-UDP proxy (see `_masque_proxy.py`).

    Its certificate is the same self-signed one as the other servers, so trust
    it with `MasqueConfig(ca_cert_pem=server_ca)`. What it has seen is cleared
    before each test; `masque_proxy.stats.connects` records every CONNECT-UDP.
    """
    _masque_proxy_server.reset()
    return _masque_proxy_server
