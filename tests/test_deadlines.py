"""A client's deadlines: `read_idle_timeout` for a body that stops arriving,
`total_timeout` bounding a streamed body too, and `math.inf` turning any of
them off.

The server sends its headers and half of a 10-byte body, then stalls until the
test lets it finish, which is how a download that stops arriving looks.
"""

from __future__ import annotations

import asyncio
import contextlib
import math

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

# How long the server stalls at most, and how long a test waits for a read
# before failing: a deadline that stopped working fails the test, rather than
# hanging the suite.
STALL_LIMIT = 10.0
GUARD = 5.0

DEADLINES = (
    "dns_timeout",
    "tcp_connect_timeout",
    "tls_handshake_timeout",
    "ttfb_timeout",
    "total_timeout",
    "quic_connect_timeout",
    "read_idle_timeout",
)


@contextlib.asynccontextmanager
async def stalling_server():
    """Yield the server's URL and the event that lets it send the rest."""
    release = asyncio.Event()

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n"
                b"Connection: close\r\n\r\nhello"
            )
            await writer.drain()
            await asyncio.wait_for(release.wait(), STALL_LIMIT)
            writer.write(b"world")
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with server:
            yield f"http://127.0.0.1:{port}/", release
            release.set()
    finally:
        release.set()


async def read_streamed(client: lkrequest.Client, url: str) -> bytes:
    async def read() -> bytes:
        stream = await client.session().send_streaming("GET", url)
        return await stream.bytes()

    return await asyncio.wait_for(read(), GUARD)


async def read_buffered(client: lkrequest.Client, url: str) -> bytes:
    async def read() -> bytes:
        return (await client.session().get(url)).content

    return await asyncio.wait_for(read(), GUARD)


@pytest.mark.parametrize("read", [read_streamed, read_buffered])
async def test_read_idle_timeout_ends_a_body_that_stops_arriving(read):
    async with stalling_server() as (url, _):
        client = lkrequest.Client(read_idle_timeout=0.3)
        with pytest.raises(lkrequest.LkTimeoutError, match="idle timeout"):
            await read(client, url)


async def test_a_pause_shorter_than_read_idle_timeout_is_waited_out():
    async with stalling_server() as (url, release):
        asyncio.get_running_loop().call_later(0.2, release.set)
        client = lkrequest.Client(read_idle_timeout=2.0)
        assert await read_streamed(client, url) == b"helloworld"


async def test_total_timeout_bounds_a_streamed_body():
    async with stalling_server() as (url, _):
        client = lkrequest.Client(total_timeout=0.3)
        with pytest.raises(lkrequest.LkTimeoutError, match="total deadline"):
            await read_streamed(client, url)


async def test_math_inf_turns_total_timeout_off():
    async with stalling_server() as (url, release):
        asyncio.get_running_loop().call_later(0.6, release.set)
        # 0.3 s would end it, as above; no deadline waits for the rest.
        client = lkrequest.Client(total_timeout=math.inf)
        assert await read_streamed(client, url) == b"helloworld"


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
@pytest.mark.parametrize("name", DEADLINES)
def test_each_deadline_reads_back_as_none_when_turned_off(client_cls, name):
    client = client_cls(**{name: math.inf})
    assert client.timeouts[name] is None
    others = {key for key, value in client.timeouts.items() if value is None}
    # read_idle_timeout is off unless set.
    assert others == {name, "read_idle_timeout"}


def test_read_idle_timeout_reads_back():
    assert BlockingClient().timeouts["read_idle_timeout"] is None
    assert BlockingClient(read_idle_timeout=1.5).timeouts["read_idle_timeout"] == 1.5
