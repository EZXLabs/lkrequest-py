"""Every request method takes the request options it can use.

`head()` and `options()` take what `get()` takes, and `send_streaming()` what
`request()` takes; they used to lack the priority, HTTP version, idempotency and
encoding options. These tests check, for those methods, the options that show up
without an HTTP/2 or HTTP/3 probe: the priority options are checked in
`test_h2_wire.py`, and idempotency in `test_h3_retry.py`.
"""

from __future__ import annotations

import gzip
import json

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

NO_BODY = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
HTTP1 = lkrequest.PreferredHttpVersion.Http1Only


@pytest.mark.parametrize("method", ["head", "options"])
def test_head_and_options_take_accept_encoding(raw_http, method):
    server = raw_http(lambda request: NO_BODY)
    send = getattr(BlockingClient().session(), method)
    send(f"{server.url}/", accept_encoding=lkrequest.AcceptEncoding.GZIP)
    [request] = server.requests
    assert request.method == method.upper()
    assert request.values("accept-encoding") == ["gzip"]


@pytest.mark.parametrize("method", ["head", "options"])
def test_head_and_options_take_a_preferred_http_version(server_url, method):
    send = getattr(BlockingClient(verify=False).session(), method)
    assert send(f"{server_url}/get").version == lkrequest.HttpVersion.H2
    forced = send(f"{server_url}/get", preferred_http_version=HTTP1)
    assert forced.version == lkrequest.HttpVersion.HTTP11


def test_send_streaming_takes_a_preferred_http_version(server_url):
    session = BlockingClient(verify=False).session()

    def seen_version(**options) -> str:
        url = f"{server_url}/upload-echo"
        response = session.send_streaming("POST", url, body=b"x", **options)
        return json.loads(response.bytes())["http_version"]

    assert seen_version() == "2"
    assert seen_version(preferred_http_version=HTTP1) == "1.1"


def test_send_streaming_takes_no_decompress(server_url):
    session = BlockingClient(verify=False).session()
    url = f"{server_url}/gzip"
    raw = session.send_streaming("GET", url, no_decompress=True).bytes()
    assert json.loads(gzip.decompress(raw))["gzipped"] is True
    decoded = session.send_streaming("GET", url).bytes()
    assert json.loads(decoded)["gzipped"] is True


async def test_the_async_session_takes_them_too(server_url):
    session = lkrequest.Client(verify=False).session()
    for send in (session.head, session.options):
        response = await send(f"{server_url}/get", preferred_http_version=HTTP1)
        assert response.version == lkrequest.HttpVersion.HTTP11
    response = await session.send_streaming(
        "POST", f"{server_url}/upload-echo", body=b"x", preferred_http_version=HTTP1
    )
    assert json.loads(await response.bytes())["http_version"] == "1.1"
