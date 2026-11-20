"""Concurrent requests to an origin no connection is open to yet wait for the
one being set up and share it, as a browser's requests do, rather than each
dialing a connection of its own.

The local server is reached through a forwarder that counts the TCP
connections made to it: the pool keeps only one of them afterwards either way,
so `pool_stats()` cannot tell.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from urllib.parse import urlsplit

import pytest

import lkrequest


def _relay(source: socket.socket, sink: socket.socket) -> None:
    try:
        while data := source.recv(65536):
            sink.sendall(data)
    except OSError:
        pass
    finally:
        sink.close()


@pytest.fixture
def counted(server_url):
    """The local server's base URL through a forwarder, and how many TCP
    connections the forwarder has accepted so far."""
    upstream = urlsplit(server_url).port
    listener = socket.create_server(("127.0.0.1", 0))
    accepted = [0]

    def accept() -> None:
        while True:
            try:
                downstream, _ = listener.accept()
            except OSError:
                return  # the listener was closed
            accepted[0] += 1
            up = socket.create_connection(("127.0.0.1", upstream))
            for pair in ((downstream, up), (up, downstream)):
                threading.Thread(target=_relay, args=pair, daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    try:
        yield f"https://127.0.0.1:{listener.getsockname()[1]}", accepted
    finally:
        listener.close()


async def test_a_cold_burst_shares_one_http2_connection(counted):
    url, accepted = counted
    session = lkrequest.Client(verify=False).session()
    responses = await asyncio.gather(*(session.get(f"{url}/get") for _ in range(50)))
    assert {r.status_code for r in responses} == {200}
    assert {r.version for r in responses} == {lkrequest.HttpVersion.H2}
    # It was 50, one per request, before the Rust library let requests wait
    # for a connection being set up.
    assert accepted[0] == 1


async def test_a_cold_burst_under_a_connection_cap_does_not_fail(counted):
    url, accepted = counted
    client = lkrequest.Client(verify=False, max_connections_per_session=6)
    session = client.session()
    responses = await asyncio.gather(*(session.get(f"{url}/get") for _ in range(100)))
    # Each request dialed for itself, so the seventh on hit the cap and failed.
    assert {r.status_code for r in responses} == {200}
    assert accepted[0] == 1
