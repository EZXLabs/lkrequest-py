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
import datetime
import ipaddress
import socket
import threading
import time

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
    def __init__(self, port: int, ca_pem: bytes, stop, thread):
        self.port = port
        self.ca_pem = ca_pem
        self.url = f"https://127.0.0.1:{port}"
        self._stop = stop
        self._thread = thread

    def shutdown(self):
        self._stop.set()
        self._thread.join(timeout=5.0)


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
    asgi_app = WsgiToAsgi(flask_app)

    config = Config()
    config.bind = [f"127.0.0.1:{port}"]
    config.certfile = str(cert_file)
    config.keyfile = str(key_file)
    config.loglevel = "ERROR"
    if with_quic:
        config.quic_bind = [f"127.0.0.1:{port}"]  # HTTP/3 over UDP, same port
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
        finally:
            loop.close()

    thread = threading.Thread(target=_run, name="hypercorn-test-server", daemon=True)
    thread.start()
    _wait_until_listening(port)
    return _ServerHandle(port, ca_pem, stop, thread)


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
def h3_server_url(_certs) -> str:
    """Base URL of a dedicated HTTP/3-capable server (quic_bind enabled).

    Started lazily so it only runs for tests that request it (e.g. the H3
    functional test under the quic-h3 build).
    """
    cert_file, key_file, ca_pem = _certs
    handle = _start_server(cert_file, key_file, ca_pem, with_quic=True)
    try:
        yield handle.url
    finally:
        handle.shutdown()
