"""The order lkrequest-py hands request fields on in: default headers, request
cookies, and the headers an `on_request` hook is shown.

The Rust library keeps all of these in the order they are given, and that
order reaches the wire, where it is part of the client's fingerprint. Each test
sends several requests, because an order that is only right by chance is right
for some of them and wrong for others. The expected Cookie headers are the ones
the Rust library itself produces for the same calls.
"""

from __future__ import annotations

import h2.events
import pytest
from test_h2_wire import H2Probe

import lkrequest
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
DEFAULTS = {
    "User-Agent": "default-order-test",
    "Accept": "*/*",
    "Accept-Language": "en",
    "X-First": "1",
    "X-Second": "2",
}
NAMES = [name.lower() for name in DEFAULTS]
COOKIES = {"alpha": "1", "bravo": "2", "charlie": "3", "delta": "4", "echo": "5"}
COOKIE_HEADER = "alpha=1; bravo=2; charlie=3; delta=4; echo=5"
REPEAT = 12


def client(defaults=None, **kwargs) -> BlockingClient:
    return BlockingClient(
        tls_profile="chrome_155",
        h2_profile="chrome_155",
        verify=False,
        default_headers=defaults,
        **kwargs,
    )


def default_names(headers: list[tuple[str, str]]) -> list[str]:
    return [name for name, _ in headers if name in NAMES]


def jar_server(raw_http):
    """`/login` puts `jar1=a` and `jar2=b` in the jar; everything else is a 200."""

    def reply(request):
        if request.target == "/login":
            return (
                b"HTTP/1.1 200 OK\r\nSet-Cookie: jar1=a; Path=/\r\n"
                b"Set-Cookie: jar2=b; Path=/\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\nOK"
            )
        return OK

    return raw_http(reply)


class OrderProbe(H2Probe):
    """An HTTP/2 server that also records the header names and the cookies of
    each request."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.header_names: list[list[str]] = []
        self.cookies: list[str] = []

    def _on_event(self, conn, event):
        if isinstance(event, h2.events.RequestReceived):
            fields = [
                (
                    k.decode() if isinstance(k, bytes) else k,
                    v.decode() if isinstance(v, bytes) else v,
                )
                for k, v in event.headers
            ]
            self.header_names.append([n for n, _ in fields if n in NAMES])
            self.cookies.append("; ".join(v for n, v in fields if n == "cookie"))
        super()._on_event(conn, event)


@pytest.fixture
def order_probe(_certs):
    cert_file, key_file, _ = _certs
    probe = OrderProbe(cert_file, key_file)
    probe.start()
    yield probe
    probe.stop()


# ---------------------------------------------------------------------------
# Client(default_headers=...)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "defaults",
    [DEFAULTS, list(DEFAULTS.items())],
    ids=["dict", "list-of-pairs"],
)
def test_http1_sends_the_defaults_in_the_order_given(raw_http, defaults):
    server = raw_http(lambda request: OK)
    for _ in range(REPEAT):
        client(defaults).session().get(f"{server.url}/")
    assert [default_names(r.headers) for r in server.requests] == [NAMES] * REPEAT


def test_http2_sends_the_defaults_in_the_order_given(order_probe):
    for _ in range(REPEAT):
        client(DEFAULTS).session().get(f"{order_probe.url}/")
    assert order_probe.header_names == [NAMES] * REPEAT


async def test_the_async_client_sends_the_defaults_in_the_order_given(raw_http):
    server = raw_http(lambda request: OK)
    for _ in range(REPEAT):
        c = lkrequest.Client(
            tls_profile="chrome_155", h2_profile="chrome_155", default_headers=DEFAULTS
        )
        await c.session().get(f"{server.url}/")
    assert [default_names(r.headers) for r in server.requests] == [NAMES] * REPEAT


def test_an_explicit_header_order_still_decides(raw_http):
    server = raw_http(lambda request: OK)
    order = list(reversed(NAMES))
    for _ in range(4):
        client(DEFAULTS, header_order=order).session().get(f"{server.url}/")
    assert [default_names(r.headers) for r in server.requests] == [order] * 4


def test_a_default_header_given_twice_is_sent_once_with_the_last_value(raw_http):
    server = raw_http(lambda request: OK)
    client([("X-Dup", "first"), ("Accept", "*/*"), ("X-Dup", "second")]).session().get(
        f"{server.url}/"
    )
    [request] = server.requests
    assert request.values("x-dup") == ["second"]
    # It keeps the place where it first appeared.
    names = [n for n, _ in request.headers if n in ("x-dup", "accept")]
    assert names == ["x-dup", "accept"]


def test_default_headers_of_the_wrong_type_are_rejected():
    with pytest.raises(TypeError, match="dict\\[str, str\\] or a sequence of"):
        client(["not", "pairs"])


# ---------------------------------------------------------------------------
# cookies= / cookie_override= on a request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cookies",
    [COOKIES, list(COOKIES.items())],
    ids=["dict", "list-of-pairs"],
)
def test_request_cookies_go_out_in_the_order_given(raw_http, cookies):
    server = raw_http(lambda request: OK)
    session = client().session()
    for _ in range(REPEAT):
        session.get(f"{server.url}/", cookies=cookies)
    assert [r.values("cookie") for r in server.requests] == [[COOKIE_HEADER]] * REPEAT


def test_request_cookies_go_out_in_the_order_given_over_http2(order_probe):
    session = client().session()
    for _ in range(REPEAT):
        session.get(f"{order_probe.url}/", cookies=COOKIES)
    assert order_probe.cookies == [COOKIE_HEADER] * REPEAT


async def test_the_async_client_sends_request_cookies_in_the_order_given(raw_http):
    server = raw_http(lambda request: OK)
    session = lkrequest.Client(
        tls_profile="chrome_155", h2_profile="chrome_155"
    ).session()
    for _ in range(REPEAT):
        await session.get(f"{server.url}/", cookies=COOKIES)
    assert [r.values("cookie") for r in server.requests] == [[COOKIE_HEADER]] * REPEAT


def test_a_streamed_request_sends_its_cookies_in_the_order_given(raw_http):
    server = raw_http(lambda request: OK)
    session = client().session()
    for _ in range(REPEAT):
        session.send_streaming("GET", f"{server.url}/", cookies=COOKIES).bytes()
    assert [r.values("cookie") for r in server.requests] == [[COOKIE_HEADER]] * REPEAT


def test_a_cookie_name_given_twice_is_sent_twice(raw_http):
    server = raw_http(lambda request: OK)
    client().session().get(f"{server.url}/", cookies=[("dup", "1"), ("dup", "2")])
    assert server.requests[0].values("cookie") == ["dup=1; dup=2"]


def test_jar_request_and_override_cookies_combine_in_order(raw_http):
    # The jar's cookies first (an overridden name dropped), then the request's
    # in the order given, then the overrides.
    server = jar_server(raw_http)
    for _ in range(REPEAT // 2):
        session = client().session()
        session.get(f"{server.url}/login")
        session.get(
            f"{server.url}/page",
            cookies={"zulu": "z", "alpha": "1"},
            cookie_override={"jar1": "override"},
        )
    pages = [r for r in server.requests if r.target == "/page"]
    assert [r.values("cookie") for r in pages] == [
        ["jar2=b; zulu=z; alpha=1; jar1=override"]
    ] * (REPEAT // 2)


def test_overrides_go_out_in_the_order_given(raw_http):
    server = jar_server(raw_http)
    for _ in range(REPEAT // 2):
        session = client().session()
        session.get(f"{server.url}/login")
        session.get(
            f"{server.url}/page", cookie_override=[("jar2", "two"), ("jar1", "one")]
        )
    pages = [r for r in server.requests if r.target == "/page"]
    assert [r.values("cookie") for r in pages] == [["jar2=two; jar1=one"]] * (
        REPEAT // 2
    )


def test_a_cookie_order_still_decides(raw_http):
    server = raw_http(lambda request: OK)
    session = client(cookie_order=["echo", "alpha"]).session()
    for _ in range(4):
        session.get(f"{server.url}/", cookies={"alpha": "1", "bravo": "2", "echo": "5"})
    assert [r.values("cookie") for r in server.requests] == [
        ["echo=5; alpha=1; bravo=2"]
    ] * 4


def test_request_cookies_of_the_wrong_type_are_rejected():
    with pytest.raises(TypeError, match="dict\\[str, str\\] or a sequence of"):
        client().session().get("http://127.0.0.1:9/", cookies=["not", "pairs"])


# ---------------------------------------------------------------------------
# The headers an on_request hook is shown
# ---------------------------------------------------------------------------


def test_an_on_request_hook_sees_the_headers_in_the_order_given(raw_http):
    server = raw_http(lambda request: OK)
    given = [("X-One", "1"), ("X-Two", "2"), ("X-Three", "3"), ("X-Four", "4")]
    seen = []
    for _ in range(REPEAT):
        session = client().session()
        session.on_request(lambda method, url, headers: seen.append(list(headers)))
        session.get(f"{server.url}/", headers=given)
    assert seen == [[name for name, _ in given]] * REPEAT
