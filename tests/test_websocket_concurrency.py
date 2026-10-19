"""A WebSocket connection's `recv()` does not hold up its `send_*()` or `close()`.

These run against the local `/ws-echo` endpoint (see conftest). The endpoint
only speaks when spoken to, so a `recv()` that is waiting for a message waits
for one the same connection has not sent yet: if that parked `recv()` also
blocked `send_*()`, the pair could never finish.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient


def _blocking_ws(ws_server_url):
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    return client.session().ws_connect(f"{ws_server_url}/ws-echo")


def _recv_in_thread(ws):
    """Start `ws.recv()` on a thread; returns (thread, list the outcome lands in)."""
    outcome: list = []

    def run() -> None:
        try:
            outcome.append(ws.recv())
        except Exception as error:  # noqa: BLE001 - recorded for the assertions
            outcome.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, outcome


def test_ws_send_does_not_wait_for_a_recv_that_is_waiting(ws_server_url):
    ws = _blocking_ws(ws_server_url)
    reader, outcome = _recv_in_thread(ws)
    reader.join(0.3)  # long enough for recv() to be parked
    assert reader.is_alive()

    sender = threading.Thread(target=lambda: ws.send_text("ping"), daemon=True)
    sender.start()
    sender.join(5)
    assert not sender.is_alive(), "send_text() was held up by the waiting recv()"
    reader.join(5)
    assert outcome == [lkrequest.WsMessage.text("ping")]
    ws.close()


def test_ws_close_does_not_wait_for_a_recv_that_is_waiting(ws_server_url):
    ws = _blocking_ws(ws_server_url)
    reader, outcome = _recv_in_thread(ws)
    reader.join(0.3)
    assert reader.is_alive()

    closer = threading.Thread(target=lambda: ws.close(1000, "bye"), daemon=True)
    closer.start()
    closer.join(5)
    assert not closer.is_alive(), "close() was held up by the waiting recv()"
    reader.join(5)
    # The waiting recv() is handed the closing handshake rather than left hanging.
    assert len(outcome) == 1 and outcome[0].is_close()


@pytest.mark.asyncio
async def test_ws_async_send_and_close_do_not_wait_for_a_recv_that_is_waiting(
    ws_server_url,
):
    client = lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = await client.session().ws_connect(f"{ws_server_url}/ws-echo")

    reader = asyncio.ensure_future(ws.recv())
    await asyncio.sleep(0.3)
    assert not reader.done()
    await asyncio.wait_for(ws.send_text("ping"), 5)
    assert await asyncio.wait_for(reader, 5) == lkrequest.WsMessage.text("ping")

    reader = asyncio.ensure_future(ws.recv())
    await asyncio.sleep(0.3)
    await asyncio.wait_for(ws.close(1000, "bye"), 5)
    assert (await asyncio.wait_for(reader, 5)).is_close()


def test_ws_refuses_every_operation_once_closed(ws_server_url):
    ws = _blocking_ws(ws_server_url)
    ws.close()
    for operation in (
        lambda: ws.send_text("late"),
        lambda: ws.send_binary(b"late"),
        ws.recv,
        ws.close,
    ):
        with pytest.raises(RuntimeError, match="closed"):
            operation()
    assert list(ws) == []  # iterating a closed connection just ends


@pytest.mark.asyncio
async def test_ws_async_refuses_every_operation_once_closed(ws_server_url):
    client = lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = await client.session().ws_connect(f"{ws_server_url}/ws-echo")
    await ws.close()
    for operation in (
        lambda: ws.send_text("late"),
        lambda: ws.send_binary(b"late"),
        ws.recv,
        ws.close,
    ):
        with pytest.raises(RuntimeError, match="closed"):
            await operation()
    assert [message async for message in ws] == []
