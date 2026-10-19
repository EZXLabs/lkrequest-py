"""What the client puts on an HTTP/2 connection, seen by a server that records
the frames it receives.

An ordinary server hides these: which stream a request opened, the weight in the
legacy priority field of its HEADERS frame, and whether a request the caller
gave up on was reset. The server here is a bare `h2` state machine behind TLS,
run on a thread of its own.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import h2.config
import h2.connection
import h2.events
import h2.settings
import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

CANCEL = 0x8  # RFC 9113 §7: the error code a caller-abandoned request is reset with


@dataclass
class Seen:
    stream_id: int
    path: str
    # The weight in the HEADERS priority field as it went on the wire (0-255),
    # or None when the frame carried no priority field.
    wire_weight: int | None
    priority_header: str | None
    # (stream depended on, exclusive) from the same field; None without one.
    dependency: tuple[int, bool] | None = None


class H2Probe:
    """A TLS HTTP/2 server that records what it receives.

    `/hang` is never answered, `/stream` gets its headers and one chunk of body
    but the stream is never finished, and any other path gets a short 200.
    """

    def __init__(self, cert_file, key_file, *, max_concurrent_streams: int = 100):
        self.requests: list[Seen] = []
        self.resets: list[tuple[int, int]] = []  # (stream id, error code)
        self.connections_opened = 0
        self.connections_closed = 0
        self.port = 0
        self._cert_file = cert_file
        self._key_file = key_file
        self._max_concurrent_streams = max_concurrent_streams
        self._writers: set[asyncio.StreamWriter] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.AbstractServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def start(self) -> None:
        started = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self._cert_file, self._key_file)
            context.set_alpn_protocols(["h2"])
            self._server = loop.run_until_complete(
                asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=context)
            )
            self.port = self._server.sockets[0].getsockname()[1]
            started.set()
            loop.run_forever()
            loop.close()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert started.wait(10), "the H2 probe server did not start"

    def stop(self) -> None:
        async def shutdown() -> None:
            self._server.close()
            for writer in list(self._writers):
                writer.close()
            handlers = [
                t for t in asyncio.all_tasks() if t is not asyncio.current_task()
            ]
            for handler in handlers:
                handler.cancel()
            await asyncio.gather(*handlers, return_exceptions=True)
            self._loop.stop()

        asyncio.run_coroutine_threadsafe(shutdown(), self._loop)
        self._thread.join(5)

    async def _handle(self, reader, writer) -> None:
        self.connections_opened += 1
        self._writers.add(writer)
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False)
        )
        conn.initiate_connection()
        conn.update_settings(
            {
                h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: (
                    self._max_concurrent_streams
                )
            }
        )
        try:
            writer.write(conn.data_to_send())
            await writer.drain()
            while data := await reader.read(65535):
                for event in conn.receive_data(data):
                    self._on_event(conn, event)
                out = conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            self.connections_closed += 1
            self._writers.discard(writer)
            writer.close()

    def _on_event(self, conn: h2.connection.H2Connection, event) -> None:
        if isinstance(event, h2.events.StreamReset):
            self.resets.append((event.stream_id, event.error_code))
            return
        if not isinstance(event, h2.events.RequestReceived):
            return

        headers = {
            (k.decode() if isinstance(k, bytes) else k): (
                v.decode() if isinstance(v, bytes) else v
            )
            for k, v in event.headers
        }
        path = headers[":path"]
        priority = event.priority_updated
        self.requests.append(
            Seen(
                stream_id=event.stream_id,
                path=path,
                # `h2` reports the semantic weight, 1-256; the wire carries it less one.
                wire_weight=None if priority is None else priority.weight - 1,
                priority_header=headers.get("priority"),
                dependency=(
                    None
                    if priority is None
                    else (priority.depends_on, priority.exclusive)
                ),
            )
        )
        if path == "/hang":
            return
        if path == "/stream":
            conn.send_headers(event.stream_id, [(":status", "200")])
            conn.send_data(event.stream_id, b"x" * 1024, end_stream=False)
            return
        conn.send_headers(
            event.stream_id, [(":status", "200"), ("content-length", "2")]
        )
        conn.send_data(event.stream_id, b"ok", end_stream=True)


def wait_until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.01)


@pytest.fixture
def h2_probe(_certs):
    cert_file, key_file, _ = _certs
    probe = H2Probe(cert_file, key_file)
    probe.start()
    yield probe
    probe.stop()


@pytest.fixture
def h2_probe_with_two_streams(_certs):
    cert_file, key_file, _ = _certs
    probe = H2Probe(cert_file, key_file, max_concurrent_streams=2)
    probe.start()
    yield probe
    probe.stop()


def browser(tls_profile: str, h2_profile) -> BlockingClient:
    return BlockingClient(tls_profile=tls_profile, h2_profile=h2_profile, verify=False)


# ---------------------------------------------------------------------------
# The first request stream
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "first_stream"),
    [("chrome_155", 1), ("firefox_147", 1), ("firefox_156", 3)],
)
def test_the_first_request_opens_the_profiles_initial_stream(
    h2_probe, name, first_stream
):
    session = browser(name, name).session()
    session.get(f"{h2_probe.url}/first")
    session.get(f"{h2_probe.url}/second")
    # Client-initiated streams go up by two.
    assert [r.stream_id for r in h2_probe.requests] == [first_stream, first_stream + 2]


def test_a_custom_initial_stream_id_is_what_the_client_opens(h2_probe):
    data = lkrequest.H2Profile.chrome_155().to_dict()
    data["initial_stream_id"] = 7
    profile = lkrequest.H2Profile.from_json(json.dumps(data))
    session = browser("chrome_155", profile).session()
    session.get(f"{h2_probe.url}/first")
    session.get(f"{h2_probe.url}/second")
    assert [r.stream_id for r in h2_probe.requests] == [7, 9]


# ---------------------------------------------------------------------------
# The legacy priority weight of a request
#
# `h2_priority_weight` reaches the wire on every request, the one that opens the
# connection included: most tests below make that request the one they check.
# ---------------------------------------------------------------------------


def firefox_156_session():
    return browser("firefox_156", "firefox_156").session()


def test_h2_priority_weight_replaces_the_profiles_headers_weight(h2_probe):
    session = firefox_156_session()
    session.get(f"{h2_probe.url}/default")
    session.get(f"{h2_probe.url}/override", h2_priority_weight=21)
    session.get(f"{h2_probe.url}/default-again")
    # The profile's own weight is back for the request after the override.
    assert [r.wire_weight for r in h2_probe.requests] == [41, 21, 41]


def test_h2_priority_weight_applies_to_the_request_that_opens_the_connection(h2_probe):
    session = firefox_156_session()
    session.get(f"{h2_probe.url}/opens", h2_priority_weight=21)
    session.get(f"{h2_probe.url}/reuses")
    assert [r.wire_weight for r in h2_probe.requests] == [21, 41]


def test_h2_priority_weight_applies_to_a_first_request_with_a_body(h2_probe):
    session = firefox_156_session()
    response = session.post(f"{h2_probe.url}/", body=b"payload", h2_priority_weight=21)
    assert response.status_code == 200
    assert h2_probe.requests[0].wire_weight == 21


@pytest.mark.parametrize("weight", [0, 255])
def test_h2_priority_weight_accepts_the_whole_wire_range(h2_probe, weight):
    session = firefox_156_session()
    session.get(f"{h2_probe.url}/opens", h2_priority_weight=weight)
    session.get(f"{h2_probe.url}/reuses", h2_priority_weight=weight)
    assert [r.wire_weight for r in h2_probe.requests] == [weight, weight]


@pytest.mark.parametrize("weight", [-1, 256])
def test_h2_priority_weight_outside_the_wire_range_is_rejected(h2_probe, weight):
    session = firefox_156_session()
    with pytest.raises((OverflowError, ValueError)):
        session.get(f"{h2_probe.url}/", h2_priority_weight=weight)
    assert h2_probe.requests == []  # nothing was sent


def test_h2_priority_weight_leaves_the_priority_header_alone(h2_probe):
    # Firefox's favicon request pairs RFC 9218 urgency 6 with legacy weight 21;
    # the two are set independently.
    session = firefox_156_session()
    session.get(
        f"{h2_probe.url}/favicon",
        priority=lkrequest.RequestPriority(6, False),
        h2_priority_weight=21,
    )
    seen = h2_probe.requests[0]
    assert seen.wire_weight == 21
    assert seen.priority_header is not None and "u=6" in seen.priority_header


def test_h2_priority_weight_changes_only_the_weight_not_the_dependency(h2_probe):
    # Chrome sends a dependency chain; an override replaces the weight and
    # nothing else in the field.
    browser("chrome_155", "chrome_155").session().get(f"{h2_probe.url}/plain")
    browser("chrome_155", "chrome_155").session().get(
        f"{h2_probe.url}/override", h2_priority_weight=21
    )
    plain, override = h2_probe.requests
    assert plain.dependency is not None
    assert override.dependency == plain.dependency
    assert override.wire_weight == 21 != plain.wire_weight


def test_h2_priority_weight_does_not_add_a_priority_field_the_profile_lacks(h2_probe):
    # Safari 26 sends RFC 9218 priorities only: its HEADERS have no legacy field.
    session = browser("chrome_155", "safari_26").session()
    session.get(f"{h2_probe.url}/opens", h2_priority_weight=21)
    session.get(f"{h2_probe.url}/reuses", h2_priority_weight=21)
    assert [r.wire_weight for r in h2_probe.requests] == [None, None]


def test_requests_racing_to_open_connections_each_keep_their_own_weight(h2_probe):
    # Nothing is warmed up, so any of these may be the one that opens a connection.
    session = firefox_156_session()
    weights = [10, 20, 30, 40, 50, 60, 70, 80]
    barrier = threading.Barrier(len(weights), timeout=10)

    def get(weight: int) -> None:
        barrier.wait()
        session.get(f"{h2_probe.url}/{weight}", h2_priority_weight=weight)

    with ThreadPoolExecutor(len(weights)) as pool:
        list(pool.map(get, weights))  # re-raises a failure from any of them
    assert {r.path: r.wire_weight for r in h2_probe.requests} == {
        f"/{weight}": weight for weight in weights
    }


async def test_h2_priority_weight_is_accepted_by_the_async_session(h2_probe):
    client = lkrequest.Client(
        tls_profile="firefox_156", h2_profile="firefox_156", verify=False
    )
    response = await client.session().get(f"{h2_probe.url}/", h2_priority_weight=21)
    assert response.status_code == 200
    assert h2_probe.requests[0].wire_weight == 21


# ---------------------------------------------------------------------------
# Requests the caller gives up on after they are on the wire
# ---------------------------------------------------------------------------


def warmed_up(h2_probe: H2Probe):
    """A session whose connection is already up, so a short timeout below only
    ever expires on a request that is on the wire."""
    session = BlockingClient(verify=False).session()
    session.get(f"{h2_probe.url}/ok")
    return session


def hang_stream_ids(h2_probe: H2Probe) -> list[int]:
    return [r.stream_id for r in h2_probe.requests if r.path == "/hang"]


def test_a_request_that_times_out_is_reset(h2_probe):
    session = warmed_up(h2_probe)
    with pytest.raises(lkrequest.LkTimeoutError):
        session.get(f"{h2_probe.url}/hang", timeout=0.3)
    wait_until(lambda: h2_probe.resets)
    assert h2_probe.resets == [(hang_stream_ids(h2_probe)[0], CANCEL)]


async def test_a_request_cancelled_by_the_caller_is_reset(h2_probe):
    session = lkrequest.Client(verify=False).session()
    await session.get(f"{h2_probe.url}/ok")
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(session.get(f"{h2_probe.url}/hang"), 0.3)
    await asyncio.to_thread(wait_until, lambda: h2_probe.resets)
    assert h2_probe.resets == [(hang_stream_ids(h2_probe)[0], CANCEL)]


def test_a_dropped_streaming_response_is_reset(h2_probe):
    session = warmed_up(h2_probe)
    response = session.send_streaming("GET", f"{h2_probe.url}/stream")
    assert response.chunk()  # headers and the first piece of the body arrived
    del response
    wait_until(lambda: h2_probe.resets)
    stream_id = next(r.stream_id for r in h2_probe.requests if r.path == "/stream")
    assert h2_probe.resets == [(stream_id, CANCEL)]


def test_abandoned_requests_do_not_use_up_the_servers_stream_limit(
    h2_probe_with_two_streams,
):
    probe = h2_probe_with_two_streams
    session = warmed_up(probe)
    # Far more than the two streams the server allows at once.
    for _ in range(6):
        with pytest.raises(lkrequest.LkTimeoutError):
            session.get(f"{probe.url}/hang", timeout=0.2)
    assert session.get(f"{probe.url}/ok", timeout=5).status_code == 200
    assert len(hang_stream_ids(probe)) == 6
    assert probe.connections_opened == 1  # the connection was never written off


def test_a_dropped_session_does_not_leave_its_connection_open(h2_probe):
    session = warmed_up(h2_probe)
    with pytest.raises(lkrequest.LkTimeoutError):
        session.get(f"{h2_probe.url}/hang", timeout=0.3)
    del session
    # The driver used to wait out a 30 second grace period for the stream
    # nobody was going to answer.
    wait_until(lambda: h2_probe.connections_closed == 1, timeout=5)
