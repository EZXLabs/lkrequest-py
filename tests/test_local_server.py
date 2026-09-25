"""Tests against local servers only (no external network).

Mostly the shared hypercorn httpbin fixture, covering HTTP/1.1, HTTP/2, and
(when built with the quic-h3 feature) HTTP/3. A few cases that need the server
to misbehave on cue stand up their own raw socket server instead.
"""

import asyncio
import hashlib
import io
import json
import socket
import threading
from urllib.parse import quote, urlsplit

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
# Streaming uploads
# ---------------------------------------------------------------------------
#
# All of these post to the ASGI `/upload-echo` endpoint rather than httpbin's
# `/post`: httpbin is WSGI and cannot read a body without Content-Length, so an
# unknown-length upload would look empty there and chunked HTTP/1.1 draws a
# `501` out of Werkzeug. See the fixture for the details.

PAYLOAD = b"streaming upload payload"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _streaming_client():
    return BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )


def test_upload_from_a_file_like_object_with_known_length(server_url):
    resp = (
        _streaming_client()
        .session()
        .post(
            f"{server_url}/upload-echo",
            body_stream=io.BytesIO(PAYLOAD),
            content_length=len(PAYLOAD),
        )
    )
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["length"] == len(PAYLOAD)
    assert echo["sha256"] == _digest(PAYLOAD)
    # An exact length is declared rather than framed as chunks.
    assert echo["content_length"] == str(len(PAYLOAD))


def test_upload_from_a_real_file_on_disk(server_url, tmp_path):
    path = tmp_path / "upload.bin"
    path.write_bytes(PAYLOAD)
    with path.open("rb") as handle:
        resp = (
            _streaming_client()
            .session()
            .post(
                f"{server_url}/upload-echo",
                body_stream=handle,
                content_length=path.stat().st_size,
            )
        )
    assert resp.json()["sha256"] == _digest(PAYLOAD)


def test_upload_from_a_generator_without_a_length(server_url):
    chunks = [b"first-", b"second-", b"third"]

    resp = (
        _streaming_client()
        .session()
        .post(f"{server_url}/upload-echo", body_stream=(chunk for chunk in chunks))
    )
    echo = resp.json()
    assert echo["sha256"] == _digest(b"".join(chunks))
    # No length was supplied, so the transport picks the framing itself: HTTP/2
    # DATA frames carry no Content-Length.
    assert echo["content_length"] is None


def test_upload_without_a_length_uses_chunked_on_http1(server_url):
    chunks = [b"alpha", b"beta"]

    resp = (
        _streaming_client()
        .session(http1_only=True)
        .post(f"{server_url}/upload-echo", body_stream=iter(chunks))
    )
    echo = resp.json()
    assert echo["sha256"] == _digest(b"".join(chunks))
    assert echo["transfer_encoding"] == "chunked"


@pytest.mark.asyncio
async def test_upload_from_an_async_generator(server_url):
    chunks = [b"async-", b"chunks"]

    async def produce():
        for chunk in chunks:
            await asyncio.sleep(0)
            yield chunk

    client = lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    resp = await client.session().post(
        f"{server_url}/upload-echo", body_stream=produce()
    )
    assert resp.json()["sha256"] == _digest(b"".join(chunks))


@pytest.mark.asyncio
async def test_upload_from_a_file_like_object_on_the_async_client(server_url):
    client = lkrequest.Client(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    resp = await client.session().post(
        f"{server_url}/upload-echo",
        body_stream=io.BytesIO(PAYLOAD),
        content_length=len(PAYLOAD),
    )
    assert resp.json()["sha256"] == _digest(PAYLOAD)


def test_async_iterable_is_rejected_by_the_blocking_client(server_url):
    # There is no event loop to await __anext__ on, so this has to fail at the
    # call rather than hang or half-upload.
    async def produce():
        yield b"nope"

    with pytest.raises(TypeError, match="running event loop"):
        _streaming_client().session().post(
            f"{server_url}/upload-echo", body_stream=produce()
        )


def test_declared_length_must_match_the_source(server_url):
    # Upstream treats a supplied length as exact; a short source is an error
    # rather than a silently truncated request.
    with pytest.raises(lkrequest.RequestError):
        _streaming_client().session().post(
            f"{server_url}/upload-echo",
            body_stream=io.BytesIO(b"short"),
            content_length=999,
        )


def test_str_chunks_name_the_fix(server_url):
    with pytest.raises(lkrequest.RequestError, match="binary mode"):
        _streaming_client().session().post(
            f"{server_url}/upload-echo", body_stream=iter(["not bytes"])
        )


def test_body_stream_is_exclusive_with_the_buffered_bodies(server_url):
    with pytest.raises(ValueError, match="more than one of"):
        _streaming_client().session().post(
            f"{server_url}/upload-echo",
            body=b"buffered",
            body_stream=io.BytesIO(b"streamed"),
        )


def test_content_length_requires_body_stream(server_url):
    with pytest.raises(ValueError, match="content_length requires body_stream"):
        _streaming_client().session().post(
            f"{server_url}/upload-echo", body=b"buffered", content_length=8
        )


def test_body_stream_rejects_an_unusable_source(server_url):
    with pytest.raises(TypeError, match="body_stream must be"):
        _streaming_client().session().post(
            f"{server_url}/upload-echo", body_stream=object()
        )


# ---------------------------------------------------------------------------
# Streaming responses share the buffered path's request handling
# ---------------------------------------------------------------------------
#
# `send_streaming` used to skip request middleware and the session's HSTS
# upgrade: only the buffered path ran them, so the same session behaved
# differently depending on how the response was read.


def test_send_streaming_runs_request_middleware(server_url):
    def inject(request):
        request["headers"]["X-Injected"] = "yes"
        return request

    client = BlockingClient(
        tls_profile="chrome_152",
        h2_profile="chrome_152",
        verify=False,
        middleware=[lkrequest.Middleware("inject", on_request=inject)],
    )
    session = client.session()

    buffered = session.get(f"{server_url}/get").json()
    streamed = json.loads(session.send_streaming("GET", f"{server_url}/get").bytes())

    assert buffered["headers"]["X-Injected"] == "yes"
    assert streamed["headers"]["X-Injected"] == "yes"


def test_send_streaming_applies_the_hsts_upgrade(server_url):
    # Addressed by hostname rather than 127.0.0.1 on purpose: HSTS is never
    # applied to an IP literal, so an IP would upgrade nothing and the test
    # would pass for the wrong reason. The fixture's cert covers `localhost`.
    port = urlsplit(server_url).port
    plain = f"http://localhost:{port}/get"

    client = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    )
    session = client.session(hsts=lkrequest.Hsts.static_(["localhost"]))

    # Without the upgrade this speaks plain HTTP to a TLS port and fails.
    assert session.get(plain).url.startswith("https://")
    streamed = json.loads(session.send_streaming("GET", plain).bytes())
    assert streamed["url"].startswith("https://")


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
def test_h3_fallback_still_reuses_the_pooled_h2_connection(server_url):
    # The local server listens on TCP only, so the HTTP/3 attempt cannot
    # succeed and every request falls back to HTTP/2 — the exact shape in which
    # upstream used to lose the pool: `Http3WithFallback` only ever looked for a
    # pooled H3 connection, so the H2 connection the fallback had just created
    # and pooled was invisible and each request re-dialled TCP + TLS.
    #
    # `diagnostics` reports None for a phase that did not happen, so a reused
    # connection is one with no TCP and no TLS timing. See
    # docs/UPSTREAM-H3-FALLBACK-POOL.md for the original defect report.
    client = BlockingClient(
        tls_profile="chrome_152",
        h2_profile="chrome_152",
        quic_profile="chrome_152",
        verify=False,
    )
    session = client.session(http3_with_fallback=True)

    first = session.get(f"{server_url}/get")
    assert first.version == lkrequest.HttpVersion.H2
    assert first.diagnostics["tls_ms"] is not None, "first request must dial"

    for _ in range(2):
        resp = session.get(f"{server_url}/get")
        assert resp.version == lkrequest.HttpVersion.H2
        assert resp.diagnostics["tcp_ms"] is None
        assert resp.diagnostics["tls_ms"] is None


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
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


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)
@pytest.mark.parametrize("preset", ["chrome", "chrome_146", "chrome_153", "chrome_154"])
def test_h3_connection_survives_the_qpack_dynamic_table(h3_server_url, preset):
    # The Chrome QUIC presets advertise a 64 KiB QPACK dynamic table, as Chrome
    # does, and the test server's encoder (aioquic, on ls-qpack) takes them up
    # on it from the second response on. The client used to decode static
    # references only, so the connection died with QPACK_DECOMPRESSION_FAILED
    # at the second request and HTTP/3 connections could not be reused.
    session = BlockingClient(quic_profile=preset, verify=False).session(http3_only=True)
    for _ in range(4):
        resp = session.get(f"{h3_server_url}/get", timeout=5.0)
        assert resp.status_code == 200
        assert resp.version == lkrequest.HttpVersion.H3


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)
async def test_h3_concurrent_responses_share_the_qpack_dynamic_table(h3_server_url):
    # Every response on the connection decodes against the one dynamic table,
    # and a response may reference entries whose inserts are still in flight
    # on the encoder stream.
    session = lkrequest.Client(quic_profile="chrome_154", verify=False).session(
        http3_only=True
    )
    await session.get(f"{h3_server_url}/get", timeout=5.0)
    responses = await asyncio.gather(
        *(session.get(f"{h3_server_url}/get?n={i}", timeout=10.0) for i in range(30))
    )
    assert [(r.status_code, r.version) for r in responses] == [
        (200, lkrequest.HttpVersion.H3)
    ] * 30


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)
@pytest.mark.parametrize("family", ["any", "ipv6"])
def test_h3_reaches_an_ipv6_target(h3_server_url_ipv6, family):
    # The QUIC endpoint used to be bound to 0.0.0.0 only, so quinn refused every
    # IPv6 destination before sending a packet: HTTP/3 to an IPv6 address always
    # failed, and a dual-stack site whose AAAA sorted first never got HTTP/3.
    client = BlockingClient(quic_profile="chrome_154", verify=False, ip_family=family)
    resp = client.session(http3_only=True).get(f"{h3_server_url_ipv6}/get", timeout=5.0)
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.H3


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


# ---------------------------------------------------------------------------
# Response.text() charset decoding (public issue #2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "sample"),
    [
        ("gbk", "中文测试"),
        ("big5", "中文測試"),
        ("shift_jis", "日本語テスト"),
        ("euc-kr", "한국어 테스트"),
    ],
)
def test_text_decodes_declared_charset(server_url, label, sample):
    # The charset from Content-Type drives the decode. Before this worked,
    # text() decoded UTF-8 unconditionally and any of these raised.
    client = BlockingClient(verify=False)
    resp = client.session().get(
        f"{server_url}/charset?label={label}&text={quote(sample)}"
    )
    assert resp.encoding == label
    assert resp.text() == sample
    # The body really is in the legacy charset, not UTF-8 that happened to work:
    # these encodings are more compact than UTF-8 for CJK.
    assert resp.content == sample.encode(label)
    assert len(resp.content) != len(sample.encode("utf-8"))


def test_text_without_declared_charset_does_not_raise(server_url):
    # A server that declares no charset leaves undecodable bytes. text() must
    # still return something: this is the exact case that used to raise
    # `TypeError: function takes exactly 5 arguments (1 given)`, because the
    # error path built a UnicodeDecodeError with one argument instead of five.
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/charset?label=gbk&declare=0")
    assert resp.encoding is None
    text = resp.text()
    assert "�" in text, "undecodable bytes should become U+FFFD"
    # ...and the caller can still recover the real text.
    assert resp.text(encoding="gbk") == "中文测试"


def test_text_encoding_argument_overrides_a_wrong_declaration(server_url):
    # A server that states the wrong charset is common enough that requests
    # makes `.encoding` writable for it; here the override is an argument.
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/charset?label=gbk&declare=iso-8859-1")
    assert resp.encoding == "iso-8859-1"
    assert resp.text() != "中文测试"
    assert resp.text(encoding="gbk") == "中文测试"


def test_text_rejects_an_unknown_encoding_argument(server_url):
    # An unknown codec from the caller is a mistake worth raising, unlike an
    # unusable label from the server, which falls back to UTF-8. LookupError is
    # what bytes.decode raises for the same mistake.
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/charset?label=gbk")
    with pytest.raises(LookupError):
        resp.text(encoding="definitely-not-a-charset")


@pytest.mark.parametrize(
    "label", ["latin-1", "utf-8-sig", "cp936", "euc_kr", "utf-16-le", "cp437"]
)
def test_text_accepts_python_codec_spellings(server_url, label):
    # These are ordinary Python codec names that the WHATWG label set does not
    # list. Resolving `encoding=` against Python's registry instead is what
    # keeps `text(encoding="latin-1")` — the obvious thing to write — working.
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/charset?label=gbk")
    assert isinstance(resp.text(encoding=label), str)


def test_text_falls_back_to_utf8_for_an_unknown_declared_charset(server_url):
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/charset?label=utf-8&declare=x-made-up")
    assert resp.encoding == "x-made-up"
    assert resp.text() == "中文测试"


def test_text_honours_and_strips_a_utf8_bom(server_url):
    # A BOM overrides the declared charset and is removed, per the WHATWG
    # Encoding Standard. Leaving it in would also break json() on the
    # BOM-prefixed bodies some servers emit.
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/charset?label=utf-8&declare=gbk&bom=1")
    assert resp.content.startswith(b"\xef\xbb\xbf")
    assert resp.text() == "中文测试"


def test_text_bom_stripping_lets_json_parse(server_url):
    # A BOM left in place would make json.loads reject an otherwise fine body.
    body = quote(json.dumps({"ok": True}))
    client = BlockingClient(verify=False)
    resp = client.session().get(
        f"{server_url}/charset?label=utf-8&declare=utf-8&bom=1&text={body}"
    )
    assert resp.json() == {"ok": True}


def test_text_caches_the_declared_decode_but_not_an_override(server_url):
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/charset?label=gbk")
    # An override must neither read nor fill the cache, or one odd call would
    # poison every later text() on the same response.
    assert resp.text(encoding="iso-8859-1") != "中文测试"
    assert resp.text() == "中文测试"
    assert resp.text(encoding="iso-8859-1") != "中文测试"
    assert resp.text() == "中文测试"


# ---------------------------------------------------------------------------
# StreamingResponse.text() decodes like Response.text() (public issue #2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "sample"),
    [("gbk", "中文测试"), ("big5", "中文測試"), ("shift_jis", "日本語テスト")],
)
def test_streaming_text_decodes_declared_charset(server_url, label, sample):
    # The streaming text() used to decode strict UTF-8 whatever the header
    # said, so the same GBK page that Response.text() handles raised here.
    session = BlockingClient(verify=False).session()
    stream = session.send_streaming(
        "GET", f"{server_url}/charset?label={label}&text={quote(sample)}"
    )
    assert stream.text() == sample


async def test_async_streaming_text_decodes_declared_charset(server_url):
    session = lkrequest.Client(verify=False).session()
    stream = await session.send_streaming("GET", f"{server_url}/charset?label=gbk")
    assert await stream.text() == "中文测试"


def test_streaming_text_encoding_argument_overrides_the_header(server_url):
    session = BlockingClient(verify=False).session()
    url = f"{server_url}/charset?label=gbk&declare=0"
    assert "�" in session.send_streaming("GET", url).text()
    assert session.send_streaming("GET", url).text(encoding="gbk") == "中文测试"


async def test_async_streaming_text_encoding_argument(server_url):
    session = lkrequest.Client(verify=False).session()
    stream = await session.send_streaming(
        "GET", f"{server_url}/charset?label=gbk&declare=0"
    )
    assert await stream.text(encoding="gbk") == "中文测试"


def test_streaming_text_is_lossy_rather_than_raising(server_url):
    # Undecodable bytes become U+FFFD, as with Response.text(); before, a body
    # that was not valid UTF-8 raised RequestError and the text was lost.
    session = BlockingClient(verify=False).session()
    stream = session.send_streaming("GET", f"{server_url}/charset?label=gbk&declare=0")
    assert "�" in stream.text()


def test_streaming_text_rejects_an_unknown_encoding_argument(server_url):
    session = BlockingClient(verify=False).session()
    stream = session.send_streaming("GET", f"{server_url}/charset?label=gbk")
    with pytest.raises(LookupError):
        stream.text(encoding="definitely-not-a-charset")


def test_streaming_text_honours_and_strips_a_utf8_bom(server_url):
    session = BlockingClient(verify=False).session()
    stream = session.send_streaming(
        "GET", f"{server_url}/charset?label=utf-8&declare=gbk&bom=1"
    )
    assert stream.text() == "中文测试"


def test_streaming_text_still_consumes_the_stream(server_url):
    session = BlockingClient(verify=False).session()
    stream = session.send_streaming("GET", f"{server_url}/charset?label=gbk")
    stream.text()
    with pytest.raises(RuntimeError, match="already consumed"):
        stream.text()


# ---------------------------------------------------------------------------
# Response.json() error type (public issue #5)
# ---------------------------------------------------------------------------


def test_json_decode_failure_is_a_request_error(server_url):
    # The whole point: `except lkrequest.RequestError` used to miss this,
    # because json.loads' own exception escaped unwrapped.
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/html")
    with pytest.raises(lkrequest.RequestError) as caught:
        resp.json()
    assert isinstance(caught.value, lkrequest.JsonDecodeError)


def test_json_decode_failure_is_still_a_stdlib_json_error(server_url):
    # Callers who wrote `except json.JSONDecodeError` as a workaround while the
    # exception leaked must keep working; that is why the class has two bases.
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/html")
    with pytest.raises(json.JSONDecodeError) as caught:
        resp.json()
    assert isinstance(caught.value, lkrequest.RequestError)


def test_json_decode_failure_keeps_the_position_fields(server_url):
    client = BlockingClient(verify=False)
    resp = client.session().get(f"{server_url}/html")
    with pytest.raises(lkrequest.JsonDecodeError) as caught:
        resp.json()
    error = caught.value
    assert error.doc == resp.text()
    assert isinstance(error.pos, int)
    assert error.msg
    assert error.lineno >= 1
    assert error.colno >= 1


def test_json_decode_failure_survives_the_async_client(server_url):
    async def run():
        session = lkrequest.Client(verify=False).session()
        resp = await session.get(f"{server_url}/html")
        with pytest.raises(lkrequest.JsonDecodeError):
            resp.json()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# ip_family — address-family selection (public issue #6)
# ---------------------------------------------------------------------------
#
# The local server binds 127.0.0.1 only, while `localhost` resolves to both
# 127.0.0.1 and ::1 on a dual-stack machine. That makes `localhost` a real
# dual-stack target reachable offline: asking for one family and observing which
# address was attempted is what proves the filter is doing anything at all.


def _localhost_families() -> set:
    return {info[4][0] for info in socket.getaddrinfo("localhost", 80)}


dual_stack_localhost = pytest.mark.skipif(
    "::1" not in _localhost_families() or "127.0.0.1" not in _localhost_families(),
    reason="localhost is not dual-stack here, so family selection is unobservable",
)


def _localhost_url(server_url: str) -> str:
    return server_url.replace("127.0.0.1", "localhost")


@pytest.mark.parametrize("family", [None, "any", "ipv4"])
def test_ip_family_allowing_ipv4_connects_over_ipv4(server_url, family):
    # The default and an explicit "any" must keep working, and "ipv4" must pick
    # the v4 address of a dual-stack name.
    kwargs = {} if family is None else {"ip_family": family}
    resp = BlockingClient(verify=False, **kwargs).session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.diagnostics["remote_addr"].startswith("127.0.0.1:")


@dual_stack_localhost
def test_ip_family_ipv4_selects_the_v4_address_of_a_dual_stack_name(server_url):
    resp = (
        BlockingClient(verify=False, ip_family="ipv4")
        .session()
        .get(f"{_localhost_url(server_url)}/get")
    )
    assert resp.status_code == 200
    assert resp.diagnostics["remote_addr"].startswith("127.0.0.1:")


@dual_stack_localhost
def test_ip_family_ipv6_selects_the_v6_address_of_a_dual_stack_name(server_url):
    # The server listens on 127.0.0.1 only, so choosing ::1 must fail to
    # connect. That failure is the evidence: with "any" the same URL succeeds
    # over 127.0.0.1, so only the family filter can account for the difference.
    session = BlockingClient(verify=False, ip_family="ipv6").session()
    with pytest.raises(lkrequest.RequestError):
        session.get(f"{_localhost_url(server_url)}/get")

    control = BlockingClient(verify=False, ip_family="any").session()
    assert control.get(f"{_localhost_url(server_url)}/get").status_code == 200


def test_ip_family_excluding_every_address_names_the_setting(server_url):
    # A host that resolves only to the excluded family must say so. Reporting a
    # bare "no addresses" here would read like a DNS outage and hide the cause.
    session = BlockingClient(verify=False, ip_family="ipv6").session()
    with pytest.raises(lkrequest.LkConnectionError) as caught:
        session.get(f"{server_url}/get")
    message = str(caught.value)
    assert "ip_family" in message, message
    assert "IPv6 policy" in message, message
    assert "127.0.0.1" in message, message


@pytest.mark.asyncio
async def test_ip_family_applies_to_the_async_client_too(server_url):
    client = lkrequest.Client(verify=False, ip_family="ipv4")
    resp = await client.session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.diagnostics["remote_addr"].startswith("127.0.0.1:")


def test_ip_family_leaves_https_record_discovery_intact(server_url):
    # Upstream's family policy wraps the resolver, and DnsResolver::lookup_https
    # has a default implementation returning None. Forgetting to forward it would silently
    # report that no host has an HTTPS record, which disables ECH and HTTP/3
    # discovery without any error. A DoH resolver is the one that answers those
    # queries, so pair it with the filter and check the client still builds and
    # requests normally.
    client = BlockingClient(verify=False, dns="cloudflare_https", ip_family="ipv4")
    assert client.session().get(f"{server_url}/get").status_code == 200


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_ip_family_covers_the_proxy_ingress_without_falling_back_direct(server_url):
    # The policy also covers the address this process dials to reach a proxy.
    # An unreachable proxy normally falls back to a direct connection under
    # proxy_fallback_direct=True — the control shows it would succeed here —
    # but a policy rejection must not: falling back would leave from exactly the
    # kind of address the caller excluded, through a route they did not choose.
    port = _closed_port()
    control = BlockingClient(verify=False, proxy_fallback_direct=True).session(
        proxy=f"http://127.0.0.1:{port}"
    )
    assert control.get(f"{server_url}/get").status_code == 200

    session = BlockingClient(
        verify=False, ip_family="ipv4", proxy_fallback_direct=True
    ).session(proxy=f"http://[::1]:{port}")
    with pytest.raises(lkrequest.ProxyError, match="IPv4 policy"):
        session.get(f"{server_url}/get")


def test_ip_family_ipv6_refuses_ipv4_mapped_addresses(server_url):
    # ::ffff:127.0.0.1 is an IPv6 literal that carries IPv4 traffic; letting it
    # through would defeat "ipv6" without the caller noticing.
    port = urlsplit(server_url).port
    session = BlockingClient(verify=False, ip_family="ipv6").session()
    with pytest.raises(lkrequest.LkConnectionError, match="IPv6 policy"):
        session.get(f"https://[::ffff:127.0.0.1]:{port}/get")


# ---------------------------------------------------------------------------
# connect_to — dialing a fixed address under the original name
# ---------------------------------------------------------------------------
#
# `connect-to.test` resolves nowhere, so a request to it can only succeed if the
# mapping is what got dialed; the local server's echo of the Host header shows
# the name the request was made under.


class _TunnelingConnectProxy:
    """An HTTP CONNECT proxy that records each request line and tunnels it."""

    def __init__(self) -> None:
        self.request_lines: list[str] = []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self._listener.getsockname()[1]}"
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        with client:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            request_line = head.split(b"\r\n", 1)[0].decode()
            self.request_lines.append(request_line)
            host, port = request_line.split()[1].rsplit(":", 1)
            with socket.create_connection((host.strip("[]"), int(port))) as upstream:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                pump = threading.Thread(
                    target=self._pump, args=(upstream, client), daemon=True
                )
                pump.start()
                self._pump(client, upstream)
                pump.join(5)

    @staticmethod
    def _pump(source: socket.socket, sink: socket.socket) -> None:
        try:
            while data := source.recv(65536):
                sink.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self) -> None:
        self._listener.close()


def test_connect_to_dials_the_mapped_address_under_the_original_name(server_url):
    port = urlsplit(server_url).port
    url = f"https://connect-to.test:{port}/get"
    with pytest.raises(lkrequest.RequestError):
        BlockingClient(verify=False).session().get(url, timeout=5.0)

    client = BlockingClient(
        verify=False, connect_to={f"connect-to.test:{port}": f"127.0.0.1:{port}"}
    )
    resp = client.session().get(url, timeout=5.0)
    assert resp.status_code == 200
    assert resp.json()["headers"]["Host"] == f"connect-to.test:{port}"
    assert resp.diagnostics["remote_addr"] == f"127.0.0.1:{port}"


def test_connect_to_hands_an_http_connect_proxy_the_address(server_url):
    # The case ip_family cannot reach: an HTTP CONNECT proxy handed a hostname
    # resolves it itself and picks the family. Given the mapping, the CONNECT
    # line carries the address instead, while TLS and Host keep the name.
    port = urlsplit(server_url).port
    proxy = _TunnelingConnectProxy()
    try:
        client = BlockingClient(
            verify=False,
            ip_family="ipv4",
            connect_to={f"connect-to.test:{port}": f"127.0.0.1:{port}"},
        )
        resp = client.session(proxy=proxy.url).get(
            f"https://connect-to.test:{port}/get", timeout=5.0
        )
    finally:
        proxy.close()
    assert resp.status_code == 200
    assert resp.json()["headers"]["Host"] == f"connect-to.test:{port}"
    assert proxy.request_lines == [f"CONNECT 127.0.0.1:{port} HTTP/1.1"]


def test_connect_to_leaves_other_origins_alone(server_url):
    port = urlsplit(server_url).port
    client = BlockingClient(
        verify=False, connect_to={f"127.0.0.1:{port + 1}": "192.0.2.1:9"}
    )
    assert client.session().get(f"{server_url}/get", timeout=5.0).status_code == 200


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ({"example.com": "192.0.2.1:443"}, "has no port"),
        ({"example.com:0": "192.0.2.1:443"}, "invalid port"),
        ({"::1:443": "192.0.2.1:443"}, "unbracketed IPv6 host"),
        ({"exa mple.com:443": "192.0.2.1:443"}, "invalid host"),
        ({"example.com:443": "192.0.2.1"}, 'must be "ip:port"'),
        ({"example.com:443": "192.0.2.1:0"}, "non-zero port"),
        (
            {"Example.com:443": "192.0.2.1:443", "example.com:443": "192.0.2.2:443"},
            "more than once",
        ),
    ],
)
def test_connect_to_rejects_malformed_entries(entries, message):
    # Upstream panics on a bad host or a zero port; each must be a ValueError.
    with pytest.raises(ValueError, match=message):
        BlockingClient(connect_to=entries)


@pytest.mark.parametrize(
    ("family", "address"),
    [
        ("ipv4", "[2001:db8::1]:443"),
        ("ipv6", "192.0.2.1:443"),
        ("ipv6", "[::ffff:192.0.2.1]:443"),
    ],
)
def test_connect_to_must_fit_ip_family(family, address):
    # Both arrive in one call, so the contradiction is refused up front rather
    # than surfacing as a connection error on the first request.
    with pytest.raises(ValueError, match=f'ip_family="{family}" excludes'):
        lkrequest.Client(ip_family=family, connect_to={"example.com:443": address})


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)
def test_connect_to_applies_to_http3(h3_server_url):
    port = urlsplit(h3_server_url).port
    client = BlockingClient(
        quic_profile="chrome_154",
        verify=False,
        connect_to={f"connect-to.test:{port}": f"127.0.0.1:{port}"},
    )
    resp = client.session(http3_only=True).get(
        f"https://connect-to.test:{port}/get", timeout=5.0
    )
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.H3
