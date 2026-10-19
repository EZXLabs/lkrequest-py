"""HTTP/3 protocol-error retries (`H3RetryMode`).

The server here accepts a QUIC connection, reads the first request and closes
the connection with H3_INTERNAL_ERROR. Every attempt therefore fails the same
way, and the number of connections the server saw is the number of attempts the
client made.
"""

from __future__ import annotations

import asyncio
import socket
import threading

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

pytestmark = pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)

H3_INTERNAL_ERROR = 0x102


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _CloseOnFirstRequest:
    """The server's view of one connection; `accepted` counts connections."""

    def __init__(self, certs):
        self.accepted: list[int] = []
        self._certs = certs
        self.port = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}/"

    def start(self) -> None:
        from aioquic.asyncio import QuicConnectionProtocol, serve
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import ProtocolNegotiated

        accepted = self.accepted

        class Protocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._http = None
                accepted.append(1)

            def quic_event_received(self, event):
                if isinstance(event, ProtocolNegotiated):
                    self._http = H3Connection(self._quic)
                if self._http is None:
                    return
                for h3_event in self._http.handle_event(event):
                    if isinstance(h3_event, HeadersReceived):
                        self._quic.close(
                            error_code=H3_INTERNAL_ERROR, reason_phrase="boom"
                        )
                        self.transmit()

        cert_file, key_file, _ = self._certs
        configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        configuration.load_cert_chain(str(cert_file), str(key_file))
        self.port = _free_udp_port()
        started = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            loop.run_until_complete(
                serve(
                    "127.0.0.1",
                    self.port,
                    configuration=configuration,
                    create_protocol=Protocol,
                )
            )
            started.set()
            loop.run_forever()
            loop.close()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert started.wait(10), "the H3 test server did not start"

    def stop(self) -> None:
        async def shutdown() -> None:
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self._loop.stop()

        asyncio.run_coroutine_threadsafe(shutdown(), self._loop)
        self._thread.join(5)


@pytest.fixture
def h3_closing_server(_certs):
    server = _CloseOnFirstRequest(_certs)
    server.start()
    yield server
    server.stop()


def session(**options):
    client = BlockingClient(quic_profile="chrome_155", verify=False)
    return client.session(http3_only=True, **options)


def test_a_protocol_error_is_not_replayed_by_default(h3_closing_server):
    with pytest.raises(lkrequest.RequestError, match="H3_INTERNAL_ERROR"):
        session().get(h3_closing_server.url, timeout=5)
    assert len(h3_closing_server.accepted) == 1


def test_the_default_mode_is_safe(h3_closing_server):
    with pytest.raises(lkrequest.RequestError, match="H3_INTERNAL_ERROR"):
        session(h3_retry_mode=lkrequest.H3RetryMode.Safe).get(
            h3_closing_server.url, timeout=5
        )
    assert len(h3_closing_server.accepted) == 1


def test_chrome_155_mode_retries_a_protocol_error_twice(h3_closing_server):
    mode = lkrequest.H3RetryMode.Chrome155ProtocolErrors
    with pytest.raises(lkrequest.RequestError, match="H3_INTERNAL_ERROR"):
        session(h3_retry_mode=mode).get(h3_closing_server.url, timeout=5)
    # The first attempt plus two retries, each on a connection of its own.
    assert len(h3_closing_server.accepted) == 3


def test_chrome_155_mode_replays_a_buffered_post(h3_closing_server):
    mode = lkrequest.H3RetryMode.Chrome155ProtocolErrors
    with pytest.raises(lkrequest.RequestError, match="H3_INTERNAL_ERROR"):
        session(h3_retry_mode=mode).post(
            h3_closing_server.url, json={"order": 1}, timeout=5
        )
    assert len(h3_closing_server.accepted) == 3


def test_a_not_idempotent_request_opts_out_of_the_mode(h3_closing_server):
    mode = lkrequest.H3RetryMode.Chrome155ProtocolErrors
    with pytest.raises(lkrequest.RequestError, match="H3_INTERNAL_ERROR"):
        session(h3_retry_mode=mode).post(
            h3_closing_server.url,
            json={"order": 1},
            idempotency=lkrequest.Idempotency.NotIdempotent,
            timeout=5,
        )
    assert len(h3_closing_server.accepted) == 1


async def test_the_async_session_takes_the_mode_too(h3_closing_server):
    client = lkrequest.Client(quic_profile="chrome_155", verify=False)
    mode = lkrequest.H3RetryMode.Chrome155ProtocolErrors
    with pytest.raises(lkrequest.RequestError, match="H3_INTERNAL_ERROR"):
        await client.session(http3_only=True, h3_retry_mode=mode).get(
            h3_closing_server.url, timeout=5
        )
    assert len(h3_closing_server.accepted) == 3
