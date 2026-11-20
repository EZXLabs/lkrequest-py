"""The TLS session cache: which connections resume a session, how long a
cached session lives (`tls_session_cache_ttl`), and reading that back.

The server is a raw HTTP/1.1 one over TLS that closes the connection after
each answer, so every request makes a new connection, and it records whether
each one resumed a session (`session_reused` on the server's side).
"""

from __future__ import annotations

import math
import ssl
import time

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
VERSIONS = [ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2]


@pytest.fixture(params=VERSIONS, ids=["tls13", "tls12"])
def server(request, raw_http, _certs):
    cert_file, key_file, _ = _certs
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.set_alpn_protocols(["http/1.1"])
    context.maximum_version = request.param
    return raw_http(lambda received: OK, ssl=context)


def resumed(server, client: BlockingClient, *, pause: float = 0.0) -> list[bool]:
    """Send three requests, each on a connection of its own."""
    session = client.session()
    for _ in range(3):
        session.get(f"{server.url}/")
        time.sleep(pause)
    return server.resumed


def test_every_later_connection_resumes_by_default(server):
    # A TLS 1.2 session used to be resumed once at most, so the third
    # connection made a full handshake again.
    assert resumed(server, BlockingClient(verify=False)) == [False, True, True]


def test_a_ttl_of_zero_caches_nothing(server):
    client = BlockingClient(verify=False, tls_session_cache_ttl=0)
    assert resumed(server, client) == [False, False, False]
    assert client.tls_session_cache_enabled is False


def test_a_session_is_not_resumed_once_its_ttl_runs_out(server):
    client = BlockingClient(verify=False, tls_session_cache_ttl=0.3)
    assert resumed(server, client, pause=0.5) == [False, False, False]


def test_a_session_within_its_ttl_is_resumed(server):
    client = BlockingClient(verify=False, tls_session_cache_ttl=30)
    assert resumed(server, client) == [False, True, True]


def test_the_disabled_policy_turns_the_cache_off(server):
    client = BlockingClient(
        verify=False,
        tls_session_resumption_policy=lkrequest.TlsSessionResumptionPolicy.DISABLED,
    )
    assert resumed(server, client) == [False, False, False]
    assert client.tls_session_cache_enabled is False


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
def test_the_cache_settings_read_back(client_cls):
    default = client_cls()
    assert (default.tls_session_cache_enabled, default.tls_session_cache_ttl) == (
        True,
        None,
    )
    client = client_cls(tls_session_cache_ttl=90.5)
    assert (client.tls_session_cache_enabled, client.tls_session_cache_ttl) == (
        True,
        90.5,
    )


@pytest.mark.parametrize("seconds", [-1.0, float("nan"), math.inf])
def test_a_ttl_must_be_a_duration(seconds):
    with pytest.raises(ValueError, match="Duration must be"):
        BlockingClient(tls_session_cache_ttl=seconds)
