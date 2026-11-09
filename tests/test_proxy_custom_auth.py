"""`ProxyConfig.with_custom_auth(identity, authorize)`: a proxy credential a
Python function works out for each connection, such as a short-lived token.

The proxies are local servers that refuse or challenge every CONNECT, which is
enough to see which credential each connection went out with.
"""

from __future__ import annotations

import json

import pytest

import lkrequest
from lkrequest import ProxyConfig
from lkrequest.blocking import Client as BlockingClient

REFUSED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
CHALLENGE = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="proxy"\r\n'
    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
)
TARGET = "https://target.example/"
# Spliced into proxy URLs rather than written in them: the public mirror's
# cleaner rewrites any `scheme://user:pass@host` it finds.
USERINFO = "alice:secret@"


class Tokens:
    """Hands out a new bearer token on every call."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        return f"Bearer token-{self.calls}"


def get_through(proxy: ProxyConfig) -> lkrequest.ProxyError:
    session = BlockingClient().session(proxy=proxy)
    with pytest.raises(lkrequest.ProxyError) as caught:
        session.get(TARGET, timeout=5.0)
    return caught.value


def test_each_connection_gets_a_credential_of_its_own(raw_http):
    server = raw_http(lambda request: REFUSED)
    tokens = Tokens()
    proxy = ProxyConfig(f"http://127.0.0.1:{server.port}").with_custom_auth(
        "tokens", tokens
    )
    get_through(proxy)
    get_through(proxy)
    assert [r.values("proxy-authorization") for r in server.requests] == [
        ["Bearer token-1"],
        ["Bearer token-2"],
    ]


async def test_an_async_session_asks_as_well(raw_http):
    server = raw_http(lambda request: REFUSED)
    proxy = ProxyConfig(f"http://127.0.0.1:{server.port}").with_custom_auth(
        "tokens", Tokens()
    )
    session = lkrequest.Client().session(proxy=proxy)
    with pytest.raises(lkrequest.ProxyError):
        await session.get(TARGET, timeout=5.0)
    [connect] = server.requests
    assert connect.values("proxy-authorization") == ["Bearer token-1"]


def test_a_challenge_is_answered_with_a_new_credential(raw_http):
    replies = iter([CHALLENGE, REFUSED])
    server = raw_http(lambda request: next(replies))
    proxy = ProxyConfig(f"http://127.0.0.1:{server.port}").with_custom_auth(
        "tokens", Tokens()
    )
    get_through(proxy)
    first, second = (r.values("proxy-authorization") for r in server.requests)
    assert first == ["Bearer token-1"]
    assert second != first and second[0].startswith("Bearer token-")


def test_the_credential_goes_in_the_header_chosen(raw_http):
    server = raw_http(lambda request: REFUSED)
    proxy = (
        ProxyConfig(f"http://127.0.0.1:{server.port}")
        .with_custom_auth("tokens", Tokens())
        .with_auth_header("authorization")
    )
    get_through(proxy)
    [connect] = server.requests
    assert connect.values("authorization") == ["Bearer token-1"]
    assert connect.values("proxy-authorization") == []


def raises() -> str:
    raise RuntimeError("token service down")


@pytest.mark.parametrize(
    "authorize",
    [lambda: None, raises, lambda: 42],
    ids=["none", "raises", "not-a-string"],
)
def test_no_credential_is_sent_without_one(raw_http, authorize):
    server = raw_http(lambda request: CHALLENGE)
    proxy = ProxyConfig(f"http://127.0.0.1:{server.port}").with_custom_auth(
        "tokens", authorize
    )
    err = get_through(proxy)
    # Without a credential to answer it with, the challenge is the answer.
    assert err.proxy_error_kind == "authentication_required"
    [connect] = server.requests
    assert connect.values("proxy-authorization") == []


def test_the_identity_tells_credentials_on_one_address_apart():
    proxy = ProxyConfig("http://proxy.example:8080")
    first = proxy.with_custom_auth("account-1", Tokens())
    second = proxy.with_custom_auth("account-2", Tokens())
    [hop] = json.loads(first.identity())
    assert hop == ["http", "proxy.example", 8080, "custom:account-1"]
    assert first.identity() != second.identity()
    # The function is not called to work the identity out.
    assert proxy.with_custom_auth("account-1", raises).identity() == first.identity()


def test_it_replaces_the_credential_of_the_url(raw_http):
    server = raw_http(lambda request: REFUSED)
    proxy = ProxyConfig(f"http://{USERINFO}127.0.0.1:{server.port}")
    get_through(proxy.with_custom_auth("tokens", Tokens()))
    [connect] = server.requests
    assert connect.values("proxy-authorization") == ["Bearer token-1"]


def test_a_socks5_proxy_cannot_carry_it():
    with pytest.raises(ValueError, match="SOCKS5"):
        ProxyConfig("socks5://proxy.example:1080").with_custom_auth("x", Tokens())


def test_authorize_must_be_a_plain_function():
    async def authorize() -> str:
        return "Bearer x"

    proxy = ProxyConfig("http://proxy.example:8080")
    with pytest.raises(TypeError, match="not an async one"):
        proxy.with_custom_auth("x", authorize)
    with pytest.raises(TypeError, match="callable"):
        proxy.with_custom_auth("x", "Bearer x")
