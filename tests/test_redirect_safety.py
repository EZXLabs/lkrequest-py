"""What a redirect carries along, and what it may follow.

The client's default headers are applied to every hop of a redirect chain, so
the ones that identify the caller have to be dropped where a request's own
headers are: when the redirect leaves the origin, when it goes from https to
http, and when it turns a POST into a GET. A `Location` the server wrote in raw
UTF-8 has to be followed too.

The servers are bare sockets (see `_raw_http.py`) so the test controls the exact
bytes of every response and sees the exact headers of every request.
"""

from __future__ import annotations

from urllib.parse import quote

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

AUTH = "Bearer FAKE_REDIRECT_TEST"
COOKIE = "fixture_session=FAKE_REDIRECT_TEST"
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"


def redirect(location: str | bytes, status: int = 302, extra: bytes = b"") -> bytes:
    if isinstance(location, str):
        location = location.encode()
    return (
        b"HTTP/1.1 %d Redirect\r\nLocation: %s\r\n%sContent-Length: 0\r\n"
        b"Connection: close\r\n\r\n" % (status, location, extra)
    )


def client(defaults: dict[str, str], **kwargs) -> BlockingClient:
    return BlockingClient(
        tls_profile="chrome_152",
        h2_profile="chrome_152",
        default_headers=defaults,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Default headers across a redirect
# ---------------------------------------------------------------------------


def test_a_cross_origin_redirect_does_not_resend_the_default_credentials(raw_http):
    target = raw_http(lambda request: OK)
    source = raw_http(lambda request: redirect(f"{target.url}/landing"))
    session = client(
        {
            "Authorization": AUTH,
            "Cookie": COOKIE,
            "Host": "fixture.invalid",
            "X-Trace": "keep",
        }
    ).session()

    assert session.get(f"{source.url}/start").status_code == 200

    [start] = source.requests
    [landing] = target.requests
    assert start.values("authorization") == [AUTH]
    assert start.values("cookie") == [COOKIE]
    assert landing.values("authorization") == []
    assert landing.values("cookie") == []
    # The destination is addressed as itself, not as the default Host.
    assert landing.values("host") == [f"127.0.0.1:{target.port}"]
    # Only what identifies the caller is dropped.
    assert landing.values("x-trace") == ["keep"]

    # The redirect did not change the client's defaults: a new request to the
    # same destination carries them again.
    session.get(f"{target.url}/direct")
    assert target.requests[1].values("authorization") == [AUTH]
    assert target.requests[1].values("cookie") == [COOKIE]


def test_a_same_origin_redirect_keeps_the_default_credentials(raw_http):
    def reply(request):
        if request.target == "/start":
            return redirect("/landing", extra=b"Set-Cookie: server=fresh; Path=/\r\n")
        return OK

    server = raw_http(reply)
    session = client({"Authorization": AUTH, "Cookie": COOKIE}).session()

    assert session.get(f"{server.url}/start").status_code == 200

    landing = server.requests[1]
    assert landing.values("authorization") == [AUTH]
    # The cookie the redirect response set is added to the default one.
    assert landing.values("cookie") == [f"{COOKIE}; server=fresh"]


def test_returning_to_the_first_origin_does_not_bring_the_defaults_back(raw_http):
    first = raw_http(
        lambda request: (
            redirect(f"{second.url}/middle") if request.target == "/start" else OK
        )
    )
    second = raw_http(lambda request: redirect(f"{first.url}/returned"))
    session = client({"Authorization": AUTH, "Cookie": COOKIE}).session()

    assert session.get(f"{first.url}/start").status_code == 200

    start, returned = first.requests
    assert start.values("authorization") == [AUTH]
    for hop in (second.requests[0], returned):
        assert hop.values("authorization") == []
        assert hop.values("cookie") == []


def test_an_https_to_http_redirect_drops_a_default_referer(server_url, raw_http):
    target = raw_http(lambda request: OK)
    session = client(
        {"Referer": "https://fixture.invalid/private", "X-Trace": "keep"},
        verify=False,
    ).session()
    destination = quote(f"{target.url}/landing", safe="")

    session.get(f"{server_url}/redirect-to?url={destination}&status_code=302")

    [landing] = target.requests
    assert landing.values("referer") == []
    assert landing.values("x-trace") == ["keep"]


BODY_HEADERS = {
    "Content-Type": "application/fixture",
    "Content-Encoding": "identity",
    "Content-Language": "en",
    "Content-Location": "/original",
    "Content-Length": "0",
}


@pytest.mark.parametrize(
    ("status", "becomes_get"),
    [(301, True), (302, True), (303, True), (307, False), (308, False)],
)
def test_a_redirect_that_turns_a_post_into_a_get_drops_the_default_body_headers(
    raw_http, status, becomes_get
):
    server = raw_http(
        lambda request: (
            redirect("/landing", status) if request.target == "/start" else OK
        )
    )
    session = client({**BODY_HEADERS, "X-Trace": "keep"}).session()

    session.post(f"{server.url}/start")

    landing = server.requests[1]
    assert landing.method == ("GET" if becomes_get else "POST")
    for name in BODY_HEADERS:
        assert (landing.values(name) == []) == becomes_get, name
    assert landing.values("x-trace") == ["keep"]


# ---------------------------------------------------------------------------
# A Location written in raw UTF-8
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "location",
    [b"/caf\xc3\xa9", b"/caf%C3%A9"],
    ids=["raw-utf-8", "percent-encoded"],
)
def test_a_utf8_location_is_followed_and_percent_encoded(raw_http, location):
    server = raw_http(
        lambda request: redirect(location) if request.target == "/start" else OK
    )
    session = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152"
    ).session()

    assert session.get(f"{server.url}/start").status_code == 200

    assert [r.target for r in server.requests] == ["/start", "/caf%C3%A9"]


def test_a_location_that_is_not_utf8_is_an_explicit_error(raw_http):
    server = raw_http(lambda request: redirect(b"/invalid\xff"))
    session = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152"
    ).session()

    with pytest.raises(lkrequest.RequestError, match="Location is not valid UTF-8"):
        session.get(f"{server.url}/start")

    assert len(server.requests) == 1
