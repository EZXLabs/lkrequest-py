"""Tests against local servers only (no external network).

Mostly the shared hypercorn httpbin fixture, covering HTTP/1.1, HTTP/2, and
(when built with the quic-h3 feature) HTTP/3. A few cases that need the server
to misbehave on cue stand up their own raw socket server instead.
"""

import asyncio
import json
from urllib.parse import urlsplit

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient


def test_blocking_h2_get(server_url):
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert "headers" in resp.json()
    # chrome preset advertises h2 in ALPN; hypercorn offers it.
    assert resp.version == lkrequest.HttpVersion.H2


def test_blocking_http1_only(server_url):
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    resp = client.session(http1_only=True).get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.HTTP11


def test_ca_cert_pem_is_accepted(server_url, server_ca):
    # Smoke test that ca_cert_pem is accepted as a client option. NOTE: this
    # does not currently assert that pinning is *enforced* — see
    # test_tls_verification_is_enforced (xfail) for the verification gap.
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", ca_cert_pem=server_ca
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200


@pytest.mark.parametrize(
    ("status", "followed"),
    [
        (300, False),  # Multiple Choices — no single target to follow
        (301, True),
        (302, True),
        (303, True),
        (304, False),  # Not Modified — a cache response, not a redirect
        (305, False),  # Use Proxy — deprecated, must never be honoured
        (306, False),  # unused/reserved
        (307, True),
        (308, True),
    ],
)
def test_only_real_redirect_statuses_are_followed(server_url, status, followed):
    # Upstream `do not treat 304/300/305/306 as redirects`: those carry a
    # Location header here, so a client that keys off "3xx + Location" would
    # wrongly follow them and hide the original status from the caller.
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    resp = client.session().get(
        f"{server_url}/redirect-to?url=/get&status_code={status}"
    )
    if followed:
        assert resp.status_code == 200
        assert resp.url.endswith("/get")
    else:
        assert resp.status_code == status
        assert "/redirect-to" in resp.url


# ---------------------------------------------------------------------------
# WebSocket handshake (RFC 6455 §4.1 / §5.5)
# ---------------------------------------------------------------------------
#
# These run against the local `/ws-echo` endpoint rather than the public
# echo.websocket.org tests in test_client.py, which are skipped unless
# LKREQUEST_WS_LIVE=1 — so before this the whole upgrade path was unexercised
# in CI. Upstream now *enforces* the §4.1 response checks that previously only
# logged a warning, which uncovered that `Sec-WebSocket-Accept` was being
# computed with a GUID that is not the one §1.3 specifies. Completing a
# handshake against a conforming server is what pins both.


def test_ws_handshake_and_echo_blocking(ws_server_url):
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = client.session().ws_connect(f"{ws_server_url}/ws-echo")
    try:
        ws.send_text("hello")
        echo = ws.recv()
        assert echo.is_text()
        assert echo == lkrequest.WsMessage.text("hello")

        ws.send_binary(b"\x01\x02\x03")
        binary_echo = ws.recv()
        assert binary_echo.is_binary()
        assert binary_echo == lkrequest.WsMessage.binary(b"\x01\x02\x03")
    finally:
        ws.close()


@pytest.mark.asyncio
async def test_ws_handshake_and_echo_async(ws_server_url):
    client = lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = await client.session().ws_connect(f"{ws_server_url}/ws-echo")
    try:
        await ws.send_text("hello async")
        echo = await ws.recv()
        assert echo == lkrequest.WsMessage.text("hello async")
    finally:
        await ws.close()


def test_ws_upgrade_rejects_a_non_websocket_endpoint(ws_server_url):
    # A 101 is the only acceptable status: an ordinary HTTP endpoint answering
    # an Upgrade request must fail the connection, not hand back a stream.
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    with pytest.raises(lkrequest.RequestError, match="WebSocket upgrade failed"):
        client.session().ws_connect(f"{ws_server_url}/get")


@pytest.mark.parametrize(
    "code",
    [
        999,  # below the assigned range
        1004,  # reserved, no defined meaning
        1005,  # "no status code present" — MUST NOT be sent
        1006,  # "closed abnormally" — MUST NOT be sent
        1015,  # "TLS handshake failure" — MUST NOT be sent
        2000,  # unassigned
        5000,  # outside every defined range
    ],
)
def test_ws_close_rejects_codes_that_may_not_go_on_the_wire(ws_server_url, code):
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = client.session().ws_connect(f"{ws_server_url}/ws-echo")
    try:
        with pytest.raises(lkrequest.RequestError):
            ws.close(code)
        # Rejected before anything reached the wire, so the connection is still
        # usable and a legal code still closes it.
        ws.send_text("still open")
        assert ws.recv().is_text()
    finally:
        ws.close(1000)


def _ws_handshake_seen_by_server(ws_server_url, probe):
    """Ask `/ws-echo` what request line and Host header it actually received."""
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = client.session().ws_connect(f"{ws_server_url}/ws-echo")
    try:
        ws.send_text(probe)
        return json.loads(ws.recv().data)
    finally:
        ws.close()


@pytest.mark.xfail(
    reason="upstream ws_upgrade_h1 sends absolute-form; see "
    "docs/UPSTREAM-WS-REQUEST-TARGET.md",
    strict=True,
)
def test_ws_upgrade_uses_an_origin_form_request_target(
    ws_server_url, ws_handshake_probe
):
    # RFC 9112 §3.2.2: a client sends absolute-form only to a proxy; to an
    # origin server the target MUST be origin-form. Upstream builds the request
    # URI as `https://{host}{path}`, so the whole URI goes out as the target and
    # any server that routes on the path (here hypercorn) misroutes the upgrade.
    seen = _ws_handshake_seen_by_server(ws_server_url, ws_handshake_probe)
    assert seen["raw_path"] == "/ws-echo"


@pytest.mark.xfail(
    reason="upstream ws_upgrade_h1 drops the port from Host; see "
    "docs/UPSTREAM-WS-REQUEST-TARGET.md",
    strict=True,
)
def test_ws_upgrade_host_header_carries_the_port(ws_server_url, ws_handshake_probe):
    # RFC 9110 §7.2: Host carries the port whenever it is not the scheme
    # default. Upstream reuses the bare hostname as the authority, so a
    # non-443 wss:// endpoint is addressed as if it were on 443 — invisible
    # against public servers, wrong against anything vhosted on another port.
    port = urlsplit(ws_server_url).port
    seen = _ws_handshake_seen_by_server(ws_server_url, ws_handshake_probe)
    assert seen["host"] == f"127.0.0.1:{port}"


def test_ws_close_reason_must_fit_in_a_control_frame(ws_server_url):
    # RFC 6455 §5.5 caps a control frame payload at 125 bytes, 2 of which the
    # status code takes — so 123 bytes of reason is the limit.
    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    ws = client.session().ws_connect(f"{ws_server_url}/ws-echo")
    with pytest.raises(lkrequest.RequestError):
        ws.close(1000, "x" * 124)
    ws.close(1000, "x" * 123)


def test_tls_verification_is_enforced(server_url):
    # A default (verify=True) client MUST reject the local self-signed cert.
    # Requires the lkrequest core fix that maps verify=True -> Strict (otherwise
    # it falls through to BrowserCompat, which swallows all chain errors).
    client = BlockingClient(tls_profile="chrome_144", h2_profile="chrome_144")
    with pytest.raises(Exception):
        client.session().get(f"{server_url}/get")


def test_verify_false_still_connects(server_url):
    # The escape hatch must keep working: verify=False trusts anything.
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    assert client.session().get(f"{server_url}/get").status_code == 200


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)
@pytest.mark.xfail(
    reason="lkrequest's QUIC stack does not complete a handshake against the "
    "hypercorn/aioquic test server (handshake times out). The H3 client path "
    "is exercised (it emits an H3-specific error), but full wire interop with "
    "this server is unverified — validate against a production H3 server "
    "(e.g. Caddy) or a public H3 endpoint.",
    strict=False,
)
def test_h3_get(h3_server_url):
    # The dedicated H3 server serves HTTP/3 on its UDP port via aioquic. With
    # http3_only the client must use QUIC or fail, so a 200 proves H3 worked.
    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        quic_profile="chrome_146",
        verify=False,
    )
    resp = client.session(http3_only=True).get(f"{h3_server_url}/get", timeout=5.0)
    assert resp.status_code == 200
    assert "headers" in resp.json()


def test_extension_order_randomization_completes_request(server_url):
    # A client with per-connection TLS extension-order randomization (Tier 1)
    # must still complete a real handshake + request against the local server.
    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        randomize=lkrequest.Randomize.extension_order(),
        verify=False,
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.H2


@pytest.mark.skipif(
    not hasattr(lkrequest, "NegotiabilityFloor"),
    reason="synthetic fingerprint tiers require the synthetic-fp build feature",
)
@pytest.mark.parametrize("floor_name", ["UNIVERSAL", "PRESET_FAMILY"])
def test_recombine_negotiability_floor_completes_request(server_url, floor_name):
    # Python mirror of upstream lkrequest's `recombine_preset_family_floor_
    # negotiates` e2e test, but hermetic (local server, no public network): a
    # synthetic (recombine) client whose sig-alg negotiability floor is a
    # guaranteed-negotiable tier must still complete a real TLS handshake +
    # request. Exercises the `negotiability()` builder threading end to end.
    floor = getattr(lkrequest.NegotiabilityFloor, floor_name)
    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        randomize=lkrequest.Randomize.recombine().negotiability(floor),
        verify=False,
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.H2


def test_h2_consumes_103_early_hints(server_url):
    # A 1xx sent ahead of the real response is interim: the driver must keep
    # reading until the final (non-1xx) HEADERS block. Regression for the
    # native H2 driver surfacing the interim status as the final one — the
    # visible symptom was GET https://www.cloudflare.com/ returning 103,
    # since Cloudflare emits 103 Early Hints before its 200.
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    resp = client.session(http2_only=True).get(f"{server_url}/early-hints")
    assert resp.version == lkrequest.HttpVersion.H2
    assert resp.status_code == 200
    assert resp.text() == "final"


@pytest.mark.asyncio
async def test_max_connections_counts_checked_out_connections(server_url):
    # Python mirror of upstream's issue_1_connection_limit tests: the cap is on
    # *physical* connections, so a connection checked out by an in-flight
    # request occupies its slot even though nothing sits idle in the pool. A
    # concurrent second request must be refused rather than quietly dialing
    # past the limit.
    client = lkrequest.Client(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    session = client.session(http1_only=True, max_connections=1)

    # `.get()` hands back an already-scheduled future, not a coroutine.
    first = asyncio.ensure_future(session.get(f"{server_url}/delay/2"))
    for _ in range(100):  # wait for the connection to be checked out
        if session.pool_stats().total == 1:
            break
        await asyncio.sleep(0.05)

    stats = session.pool_stats()
    assert stats.total == 1
    assert stats.h1_connections == 0, "a checked-out H1 is not idle in the pool"
    assert stats.at_capacity is True

    with pytest.raises(lkrequest.RequestError, match="connection limit reached"):
        await session.get(f"{server_url}/get")

    assert (await first).status_code == 200


@pytest.mark.xfail(
    reason="Known upstream bug: reusing a pooled H1 connection the peer already "
    "closed can surface as hyper's Kind::Io, whose Display is the bare string "
    "'connection error' (hyper-1.6.0 src/error.rs:483) with the io detail only "
    "in the source() chain. classify_connection_closed_message matches on the "
    "message text and has no pattern for it, so is_connection_closed() is false, "
    "the stale-connection retry in transport.rs never fires, and the redirect "
    "fails instead of redialling. Measured ~28% failure at concurrency 20 on "
    "both 7da5345 and 5b09bf7, so this is pre-existing, not a sync regression. "
    "Timing-dependent, hence strict=False: it passes when the client notices "
    "the close before checking the connection out.",
    strict=False,
)
@pytest.mark.asyncio
async def test_redirect_reconnects_when_pooled_h1_closed_after_302():
    # A server that hangs up right after its 302 must not break the redirect:
    # the client has to notice the pooled connection is dead and dial again.
    # Needs a raw socket server, since hypercorn will not close on cue.
    request_lines = []

    async def handle(reader, writer):
        request_lines.append((await reader.read(4096)).split(b"\r\n", 1)[0])
        if len(request_lines) == 1:
            writer.write(
                b"HTTP/1.1 302 Found\r\nLocation: /result\r\nContent-Length: 0\r\n\r\n"
            )
        else:
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        client = lkrequest.Client(tls_profile="chrome_144", h2_profile="chrome_144")
        session = client.session(http1_only=True)
        resp = await session.post(
            f"http://127.0.0.1:{port}/submit", body=b"payload", timeout=10.0
        )

    assert resp.status_code == 200
    assert resp.text() == "OK"
    assert request_lines[0].startswith(b"POST /submit")
    assert request_lines[1].startswith(b"GET /result")


# Script run in a subprocess by the test below: fire requests, let the event
# loop close while they are still in flight, then give them time to finish.
_LATE_COMPLETION_SCRIPT = """
import asyncio, socket, sys, threading, time

def slow_server(port, delay):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(256)
    def handle(conn):
        try:
            conn.recv(4096)
            time.sleep(delay)
            conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n"
                         b"Connection: close\\r\\n\\r\\nOK")
        except OSError:
            pass
        finally:
            try: conn.close()
            except OSError: pass
    def accept():
        while True:
            try: conn, _ = srv.accept()
            except OSError: return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    return srv.getsockname()[1]

port = slow_server(0, 0.8)

async def main():
    import lkrequest
    session = lkrequest.Client().session(http1_only=True)
    for _ in range(20):
        session.get(f"http://127.0.0.1:{port}/x", timeout=30.0)
    await asyncio.sleep(0.2)          # let the requests actually go out

asyncio.run(main())                    # closes the loop, requests still pending
time.sleep(2.0)                        # they complete now, against a closed loop
print("DONE")
"""


def test_late_completion_after_loop_close_is_silent():
    # A request finishing after the event loop closed must not write to stderr.
    # pyo3-async-runtimes delivers results via loop.call_soon_threadsafe(); on a
    # closed loop that raises, and the bridge prints the traceback rather than
    # propagating it. One such print per late task, each from its own tokio
    # worker, is what turns into `Fatal Python error: _enter_buffered_busy` at
    # interpreter shutdown — the SIGABRT users hit under load.
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-c", _LATE_COMPLETION_SCRIPT],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"exited {proc.returncode}\n{proc.stderr[-2000:]}"
    assert "DONE" in proc.stdout
    assert "Event loop is closed" not in proc.stderr, (
        "late completions leaked tracebacks to stderr:\n" + proc.stderr[-2000:]
    )
    assert "Fatal Python error" not in proc.stderr


def _slow_raw_server(delay=1.0):
    """Raw TCP server that stalls before replying, so requests stay in flight."""
    import socket
    import threading
    import time

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(128)

    def handle(conn):
        try:
            conn.recv(4096)
            time.sleep(delay)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def accept():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return srv.getsockname()[1], srv


@pytest.mark.asyncio
async def test_drain_pending_waits_for_in_flight_requests():
    # pending_requests() must see in-flight work, and drain_pending() must not
    # return until it is done — that is what lets a caller close the loop safely.
    port, srv = _slow_raw_server(delay=1.0)
    try:
        session = lkrequest.Client().session(http1_only=True)
        futures = [
            asyncio.ensure_future(session.get(f"http://127.0.0.1:{port}/x", timeout=30))
            for _ in range(5)
        ]
        for _ in range(100):
            if lkrequest.pending_requests() >= 5:
                break
            await asyncio.sleep(0.01)
        assert lkrequest.pending_requests() >= 5

        assert await lkrequest.drain_pending(timeout=20.0) is True
        assert lkrequest.pending_requests() == 0
        assert all(f.done() for f in futures)
    finally:
        srv.close()


@pytest.mark.asyncio
async def test_cancelling_a_request_releases_it():
    # pyo3-async-runtimes already propagates cancellation: cancelling the Python
    # future drops the Rust future rather than letting it run to completion.
    # Asserting it here keeps that guarantee from regressing silently, since the
    # in-flight count is what a caller's drain depends on.
    port, srv = _slow_raw_server(delay=5.0)
    try:
        session = lkrequest.Client().session(http1_only=True)
        before = lkrequest.pending_requests()
        fut = asyncio.ensure_future(
            session.get(f"http://127.0.0.1:{port}/x", timeout=30)
        )
        for _ in range(100):
            if lkrequest.pending_requests() > before:
                break
            await asyncio.sleep(0.01)
        assert lkrequest.pending_requests() > before

        fut.cancel()
        # Well under the server's 5s delay: the count dropping proves the Rust
        # future was abandoned, not merely awaited to completion.
        assert await lkrequest.drain_pending(timeout=2.0) is True
        assert lkrequest.pending_requests() == before
    finally:
        srv.close()


def test_failed_submission_outside_loop_does_not_leak_pending_count():
    # A submission that fails synchronously — here: no running event loop, a
    # plain sync-context misuse — must roll the in-flight count back. The
    # count is taken before anything fallible, so the rollback relies on the
    # never-polled wrapper future dropping the guard it captured. A leak here
    # is permanent and poisons every later drain_pending() in the process.
    before = lkrequest.pending_requests()
    session = lkrequest.Client().session(http1_only=True)
    with pytest.raises(RuntimeError, match="no running event loop"):
        session.get("http://127.0.0.1:1/x")
    assert lkrequest.pending_requests() == before


@pytest.mark.asyncio
async def test_drain_true_implies_results_already_delivered():
    # drain_pending() == True must mean the results are already in the Python
    # futures, not merely that the Rust side finished. The count releases only
    # after each result callback is enqueued on the loop, and the drain
    # wake-up is enqueued after all of them, so reading f.result() in the very
    # callback tick that observes True must never find a pending future.
    port, srv = _slow_raw_server(delay=0.05)
    try:
        session = lkrequest.Client().session(http1_only=True)
        for _ in range(10):
            futures = [
                asyncio.ensure_future(
                    session.get(f"http://127.0.0.1:{port}/x", timeout=30)
                )
                for _ in range(8)
            ]
            assert await lkrequest.drain_pending(timeout=20.0) is True
            not_done = [f for f in futures if not f.done()]
            assert not not_done, f"{len(not_done)} futures pending after drain"
            for f in futures:
                assert f.result().status_code == 200
    finally:
        srv.close()
