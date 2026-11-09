"""`randomize_fingerprint()` replaces the TLS profile and nothing else.

It used to build the copy from the fingerprint layers alone, so the options a
client was created with were dropped, and so were the header order and QUIC
profile a browser preset brings. The tests compare what the original client and
its copy put on the wire, or read back.
"""

from __future__ import annotations

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
# Not the order a browser template puts them in, so a template shows.
HEADERS = [("accept", "text/plain"), ("user-agent", "fixture")]
ORDER = ["host", "x-default", "user-agent", "accept"]


def heads(raw_http, *clients) -> list[list[tuple[str, str]]]:
    """The request head each blocking client sends to the same server, with the
    names spelled as on the wire."""
    server = raw_http(lambda request: OK)
    for client in clients:
        client.session().get(f"{server.url}/", headers=HEADERS)
    return [
        list(zip(request.raw_names, (value for _, value in request.headers)))
        for request in server.requests
    ]


def test_the_options_a_client_was_built_with_carry_over(raw_http):
    client = BlockingClient(
        default_headers=[("X-Default", "kept")],
        header_order=ORDER,
        http1_title_case_headers=False,
    )
    randomized = client.randomize_fingerprint()
    twice = randomized.randomize_fingerprint(shuffle_extensions=False)
    original, *copies = heads(raw_http, client, randomized, twice)
    # Lowercase names, but Host keeps its capital.
    assert [name for name, _ in original] == ["Host", *ORDER[1:]]
    assert copies == [original, original]


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
def test_the_options_read_back_the_same(client_cls):
    client = client_cls(
        tls_profile="chrome_156",
        h2_profile="chrome_156",
        tcp_fingerprint="chrome_win",
        http1_title_case_headers=False,
        h2_dispatch_batch_size=4,
        require_close_notify=True,
        tls_session_resumption_policy=lkrequest.TlsSessionResumptionPolicy.DISABLED,
    )
    randomized = client.randomize_fingerprint()
    assert randomized.fingerprint_info() == client.fingerprint_info()
    assert randomized.http1_title_case_headers is False
    assert randomized.h2_dispatch_batch_size == 4
    assert randomized.require_close_notify is True
    assert (
        randomized.tls_session_resumption_policy
        == lkrequest.TlsSessionResumptionPolicy.DISABLED
    )


@pytest.mark.parametrize("trust", ["pinned", "unverified"])
def test_the_trust_settings_carry_over(server_url, server_ca, trust):
    options = {"ca_cert_pem": server_ca} if trust == "pinned" else {"verify": False}
    randomized = BlockingClient(**options).randomize_fingerprint()
    # The local server's certificate is self-signed: only the copy's own trust
    # settings let it through.
    assert randomized.session().get(f"{server_url}/get").status_code == 200


def test_the_quic_profile_carries_over(h3_server_url):
    if not hasattr(lkrequest, "QuicProfile"):
        pytest.skip("built without the quic-h3 feature")
    client = BlockingClient(quic_profile="chrome_156", verify=False)
    session = client.randomize_fingerprint().session(http3_only=True)
    resp = session.get(f"{h3_server_url}/get", timeout=5.0)
    assert resp.version == lkrequest.HttpVersion.H3


def test_a_preset_keeps_its_header_order(raw_http):
    client = BlockingClient.chrome_156()
    template_free = BlockingClient(tls_profile="chrome_156", h2_profile="chrome_156")
    original, randomized, plain = heads(
        raw_http, client, client.randomize_fingerprint(), template_free
    )
    # The preset's header-order template moved the headers ...
    assert original != plain
    # ... and the copy still has it.
    assert randomized == original


async def test_the_async_client_keeps_its_options(raw_http):
    server = raw_http(lambda request: OK)
    client = lkrequest.Client(default_headers=[("X-Default", "kept")])
    for each in (client, client.randomize_fingerprint()):
        await each.session().get(f"{server.url}/", headers=HEADERS)
    original, randomized = server.requests
    assert original.values("x-default") == ["kept"]
    assert (randomized.raw_names, randomized.headers) == (
        original.raw_names,
        original.headers,
    )


def test_a_client_from_a_client_pool_keeps_its_options():
    pool = lkrequest.ClientPool([lkrequest.Client(http1_title_case_headers=False)])
    assert pool.acquire().randomize_fingerprint().http1_title_case_headers is False
