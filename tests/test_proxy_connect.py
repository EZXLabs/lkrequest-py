"""How a proxy's refusal of a CONNECT is reported.

Given credentials, the client answers a `407` challenge with one more CONNECT.
Whatever that attempt is refused with is the proxy's real answer: a second `407`
means the credentials are wrong, anything else is a refusal for another reason.
"""

from __future__ import annotations

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

CREDENTIALS = "fixture:FAKE_PASSWORD@"


def refusing_proxy(raw_http, *statuses: int):
    """A proxy that refuses each successive CONNECT with the next status; a 407
    carries a Basic challenge."""

    def reply(request):
        status = statuses[min(len(proxy.requests), len(statuses)) - 1]
        challenge = (
            b'Proxy-Authenticate: Basic realm="fixture"\r\n' if status == 407 else b""
        )
        return (
            b"HTTP/1.1 %d Fixture\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n"
            % (status, challenge)
        )

    proxy = raw_http(reply)
    return proxy


def get_through(proxy, userinfo: str = CREDENTIALS) -> str:
    session = BlockingClient(
        tls_profile="chrome_152", h2_profile="chrome_152", verify=False
    ).session()
    with pytest.raises(lkrequest.ProxyError) as caught:
        session.get(
            "https://127.0.0.1:9/",
            proxy=f"http://{userinfo}127.0.0.1:{proxy.port}",
            timeout=5.0,
        )
    return str(caught.value)


@pytest.mark.parametrize("status", [402, 503])
def test_a_refusal_after_the_auth_retry_reports_its_own_status(raw_http, status):
    proxy = refusing_proxy(raw_http, 407, status)
    message = get_through(proxy)
    assert f"status {status}" in message
    assert "authentication failed" not in message
    assert [r.method for r in proxy.requests] == ["CONNECT", "CONNECT"]


def test_a_second_407_is_an_authentication_failure(raw_http):
    proxy = refusing_proxy(raw_http, 407, 407)
    message = get_through(proxy)
    assert "authentication failed" in message
    assert "status 407" in message
    assert len(proxy.requests) == 2


def test_a_407_without_credentials_is_not_retried(raw_http):
    proxy = refusing_proxy(raw_http, 407)
    message = get_through(proxy, userinfo="")
    assert "407" in message
    assert len(proxy.requests) == 1


def test_a_refusal_with_no_challenge_reports_its_status(raw_http):
    proxy = refusing_proxy(raw_http, 503)
    message = get_through(proxy)
    assert "503" in message
    assert "authentication" not in message
    assert len(proxy.requests) == 1
