"""What a WebSocket connection offers beyond sending and receiving messages:
extensions offered in the upgrade, pings and pongs, and the URL it went to.

The server is the local `/ws-echo` endpoint, which answers a ping with a pong
as RFC 6455 requires and describes the upgrade request it received when sent
the handshake probe.
"""

from __future__ import annotations

import json

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient


def connect(ws_server_url, **kwargs):
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    return client.session().ws_connect(f"{ws_server_url}/ws-echo", **kwargs)


def handshake(ws, probe) -> dict:
    ws.send_text(probe)
    return json.loads(ws.recv().data)


def test_extensions_are_offered_in_the_upgrade(ws_server_url, ws_handshake_probe):
    # Names the server does not know, so it accepts none and the frames stay
    # plain: the client fails a handshake that accepts any extension other than
    # permessage-deflate.
    ws = connect(ws_server_url, extensions=["x-first", "x-second; level=1"])
    try:
        seen = handshake(ws, ws_handshake_probe)
    finally:
        ws.close()
    assert seen["extensions"] == "x-first, x-second; level=1"


def test_no_extensions_header_without_extensions(ws_server_url, ws_handshake_probe):
    ws = connect(ws_server_url)
    try:
        assert handshake(ws, ws_handshake_probe)["extensions"] == ""
    finally:
        ws.close()


def test_a_ping_comes_back_as_a_pong(ws_server_url):
    ws = connect(ws_server_url)
    try:
        ws.ping(b"are you there")
        assert ws.recv() == lkrequest.WsMessage.Pong(data=b"are you there")
        ws.ping()
        assert ws.recv() == lkrequest.WsMessage.Pong(data=b"")
    finally:
        ws.close()


async def test_an_async_ping_comes_back_as_a_pong(ws_server_url):
    client = lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = await client.session().ws_connect(
        f"{ws_server_url}/ws-echo", extensions=["x-first"]
    )
    try:
        await ws.ping(b"async")
        assert await ws.recv() == lkrequest.WsMessage.Pong(data=b"async")
        await ws.pong(b"beat")
        await ws.send_text("still here")
        assert await ws.recv() == lkrequest.WsMessage.text("still here")
    finally:
        await ws.close()


def test_a_pong_needs_no_answer(ws_server_url):
    ws = connect(ws_server_url)
    try:
        ws.pong(b"heartbeat")
        # The next thing back is the echo: the pong was taken without a reply.
        ws.send_text("after the pong")
        assert ws.recv() == lkrequest.WsMessage.text("after the pong")
    finally:
        ws.close()


def test_a_control_frame_carries_at_most_125_bytes(ws_server_url):
    ws = connect(ws_server_url)
    try:
        with pytest.raises(ValueError, match="125"):
            ws.ping(b"x" * 126)
        with pytest.raises(ValueError, match="125"):
            ws.pong(b"x" * 126)
        # Refused before anything was sent: the connection is still fine.
        ws.ping(b"x" * 125)
        assert ws.recv() == lkrequest.WsMessage.Pong(data=b"x" * 125)
    finally:
        ws.close()


def test_the_url_is_there_before_and_after_closing(ws_server_url):
    ws = connect(ws_server_url)
    assert ws.url == f"{ws_server_url}/ws-echo"
    ws.close()
    assert ws.url == f"{ws_server_url}/ws-echo"
    with pytest.raises(RuntimeError, match="closed"):
        ws.ping()


#: The offer Chrome makes. The local server accepts it and compresses what it
#: sends back: builds that offered it without speaking it failed every receive
#: with "Reserved bits".
CHROME_DEFLATE_OFFER = "permessage-deflate; client_max_window_bits"


@pytest.mark.parametrize(
    "offer", ["permessage-deflate", CHROME_DEFLATE_OFFER], ids=["bare", "chrome"]
)
def test_permessage_deflate_messages_are_compressed_and_received(ws_server_url, offer):
    ws = connect(ws_server_url, extensions=[offer])
    try:
        text = "hello " * 50
        ws.send_text(text)
        assert ws.recv().data == text
        data = bytes(range(256)) * 64
        ws.send_binary(data)
        assert ws.recv().data == data
    finally:
        ws.close()


def test_permessage_deflate_keeps_its_context_across_large_messages(ws_server_url):
    # Context takeover: each message is compressed against the ones before it,
    # so a mistake in the shared window shows up on the second and third.
    ws = connect(ws_server_url, extensions=[CHROME_DEFLATE_OFFER])
    try:
        for size in (300_000, 1_000_000, 64):
            text = ("abcdefghij" * (size // 10 + 1))[:size]
            ws.send_text(text)
            assert ws.recv().data == text
    finally:
        ws.close()
