"""A `Set-Cookie` with an empty `Max-Age=` attribute.

The attribute carries no value, so it says nothing: the cookie is kept, and its
lifetime comes from whatever else the header gives it. Before, the whole header
was rejected and the cookie silently never stored.
"""

from __future__ import annotations

import time

import pytest

from lkrequest.blocking import Client as BlockingClient

URL = "https://example.com/"
EPOCH = "Expires=Thu, 01 Jan 1970 00:00:00 GMT"


def new_session():
    return BlockingClient(tls_profile="chrome_152", h2_profile="chrome_152").session()


def test_an_empty_max_age_leaves_a_session_cookie():
    session = new_session()
    session.set_cookie_raw(URL, "sid=live; Path=/; Max-Age=")
    [cookie] = session.get_cookies_with_attrs(URL)
    assert (cookie.name, cookie.value) == ("sid", "live")
    assert cookie.expires is None
    assert not cookie.is_persistent


@pytest.mark.parametrize(
    "attributes",
    [f"Max-Age=; {EPOCH}", f"{EPOCH}; Max-Age=", f"Max-Age=; mAx-AgE = \t; {EPOCH}"],
)
def test_an_empty_max_age_does_not_override_expires(attributes):
    session = new_session()
    session.set_cookie_raw(URL, "sid=old; Path=/; Max-Age=3600")
    session.set_cookie_raw(URL, f"sid=new; Path=/; {attributes}")
    # `Expires` is in the past, so the cookie is deleted.
    assert session.get_cookie(URL, "sid") is None
    assert session.get_all_cookies() == []


@pytest.mark.parametrize(
    ("attributes", "seconds"),
    [
        ("Max-Age=60; Max-Age=", 60),
        ("Max-Age=; Max-Age=60", 60),
        ("Max-Age=60; Max-Age=; Max-Age=120; Max-Age=", 120),
        ("Max-Age=60; Max-Age=; Max-Age=bogus", 60),
    ],
)
def test_the_last_valid_max_age_wins_around_empty_ones(attributes, seconds):
    session = new_session()
    before = int(time.time())
    session.set_cookie_raw(URL, f"sid=value; Path=/; {attributes}")
    after = int(time.time())
    [cookie] = session.get_cookies_with_attrs(URL)
    assert before + seconds <= cookie.expires <= after + seconds + 1


def test_an_empty_max_age_is_not_confused_with_a_value_that_contains_it():
    session = new_session()
    session.set_cookie_raw(URL, "sid=Max-Age=; Path=/api; Secure; Max-Age=")
    [cookie] = session.get_cookies_with_attrs("https://example.com/api/item")
    assert (cookie.name, cookie.value) == ("sid", "Max-Age=")
    assert cookie.path == "/api"
    assert cookie.secure
    assert cookie.expires is None
    assert cookie.host_only


def set_cookie_server(raw_http):
    """`/login` sets a cookie with an empty Max-Age; `/logout` tries to delete it
    with an `Expires` in the past and an empty Max-Age."""

    def reply(request):
        headers = {
            "/login": b"Set-Cookie: sid=abc; Path=/; Max-Age=\r\n",
            "/logout": b"Set-Cookie: sid=abc; Path=/; Max-Age=; "
            + EPOCH.encode()
            + b"\r\n",
        }.get(request.target, b"")
        return (
            b"HTTP/1.1 200 OK\r\n%sContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            % headers
        )

    return raw_http(reply)


def test_a_response_with_an_empty_max_age_sets_a_session_cookie(raw_http):
    server = set_cookie_server(raw_http)
    session = new_session()
    session.get(f"{server.url}/login")
    [cookie] = session.get_all_cookies()
    assert (cookie.name, cookie.value) == ("sid", "abc")
    # Not a cookie that lasts until the year 9999.
    assert cookie.expires is None
    session.get(f"{server.url}/next")
    assert server.requests[1].values("cookie") == ["sid=abc"]


def test_an_empty_max_age_does_not_stop_a_response_from_deleting_a_cookie(raw_http):
    server = set_cookie_server(raw_http)
    session = new_session()
    session.get(f"{server.url}/login")
    session.get(f"{server.url}/logout")
    session.get(f"{server.url}/after")
    assert session.get_all_cookies() == []
    assert server.requests[2].values("cookie") == []
