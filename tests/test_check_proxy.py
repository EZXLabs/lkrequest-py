"""`check_proxy()` on both clients: set a tunnel up through a proxy, without
sending a request through it, and say how long that took.

The proxies are local servers that grant, refuse or ignore the CONNECT, which
is all a check sends.
"""

from __future__ import annotations

import socket

import pytest

import lkrequest
from lkrequest import ProxyConfig
from lkrequest.blocking import Client as BlockingClient

GRANTED = b"HTTP/1.1 200 Connection established\r\n\r\n"
REFUSED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def test_a_check_returns_the_seconds_the_tunnel_took(raw_http):
    proxy = raw_http(lambda request: GRANTED)
    latency = BlockingClient().check_proxy(
        f"http://127.0.0.1:{proxy.port}", "health.example", 8443
    )
    assert 0 < latency < 5
    [connect] = proxy.requests
    assert (connect.method, connect.target) == ("CONNECT", "health.example:8443")


async def test_an_async_check_tunnels_to_what_a_pool_checks_by_default(raw_http):
    proxy = raw_http(lambda request: GRANTED)
    config = ProxyConfig(f"http://user:pw@127.0.0.1:{proxy.port}")
    latency = await lkrequest.Client().check_proxy(config)
    assert 0 < latency < 5
    [connect] = proxy.requests
    assert connect.target == "www.google.com:443"
    assert connect.values("proxy-authorization")


def test_a_refused_tunnel_raises(raw_http):
    proxy = raw_http(lambda request: REFUSED)
    with pytest.raises(lkrequest.ProxyError) as caught:
        BlockingClient().check_proxy(f"http://127.0.0.1:{proxy.port}")
    assert caught.value.proxy_error_kind == "tunnel_refused"


def test_a_proxy_that_does_not_answer_times_out():
    with socket.create_server(("127.0.0.1", 0)) as silent:
        port = silent.getsockname()[1]
        with pytest.raises(lkrequest.LkTimeoutError) as caught:
            BlockingClient().check_proxy(f"http://127.0.0.1:{port}", timeout=0.3)
    assert caught.value.phase == "proxy_tunnel"


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
async def test_the_proxy_is_found_by_the_clients_resolver(raw_http, client_cls):
    proxy = raw_http(lambda request: GRANTED)
    asked = []

    def resolve(host, port):
        asked.append((host, port))
        return ["127.0.0.1"]

    client = client_cls(dns=resolve)
    check = client.check_proxy(f"http://proxy.test:{proxy.port}")
    latency = await check if client_cls is lkrequest.Client else check
    assert latency > 0
    assert asked == [("proxy.test", proxy.port)]


def test_what_cannot_be_checked_is_refused():
    client = BlockingClient()
    with pytest.raises(ValueError, match="proxy"):
        client.check_proxy("not a proxy URL")
    with pytest.raises(TypeError, match="str or ProxyConfig"):
        client.check_proxy(object())
    with pytest.raises(ValueError, match="Duration must be"):
        client.check_proxy("http://127.0.0.1:9", timeout=-1.0)
