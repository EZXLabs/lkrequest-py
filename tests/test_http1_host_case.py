"""Check header spelling at a loopback HTTP/1.1 server, before normalization."""

from __future__ import annotations

import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient


@pytest.fixture
def header_probe(request, _certs):
    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.append((list(self.headers.raw_items()), body, self.client_address))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

        def do_GET(self):
            received.append((list(self.headers.raw_items()), b"", self.client_address))
            self.send_error(400, "Upgrade captured")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = request.param
    if tls:
        cert_file, key_file, _ = _certs
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        context.set_alpn_protocols(["http/1.1"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    scheme = "https" if tls else "http"
    try:
        yield f"{scheme}://127.0.0.1:{server.server_port}/headers", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


async def result(value, blocking):
    return value if blocking else await value


def make_client(blocking, title_case):
    kwargs = {} if title_case is None else {"http1_title_case_headers": title_case}
    client_cls = BlockingClient if blocking else lkrequest.Client
    return client_cls(
        verify=False,
        default_headers={"X-Default": "Keep-MiXeD"},
        header_order=["host", "x-default", "x-mixed", "accept", "cookie"],
        total_timeout=5,
        **kwargs,
    )


def assert_headers(headers, title_case):
    names = [name for name, _ in headers]
    expected = ["Host", "X-Default", "X-Mixed", "Accept", "Cookie"]
    if title_case is False:
        expected = ["Host", *(name.lower() for name in expected[1:])]
        assert all(name == "Host" or name == name.lower() for name in names)
    assert names.count("Host") == 1
    assert names[:5] == expected
    values = {name.lower(): value for name, value in headers}
    assert values["x-default"] == "Keep-MiXeD"
    assert values["x-mixed"] == "Value-MiXeD"
    assert values["cookie"] == "test=Cookie-MiXeD"


@pytest.mark.parametrize(
    "header_probe", [False, True], indirect=True, ids=["http", "https"]
)
@pytest.mark.parametrize("blocking", [False, True], ids=["async", "blocking"])
@pytest.mark.parametrize(
    "title_case", [None, True, False], ids=["default", "title", "lower"]
)
@pytest.mark.parametrize("streaming", [False, True], ids=["buffered", "streaming"])
@pytest.mark.parametrize("preconnect", [False, True], ids=["new", "preconnected"])
@pytest.mark.parametrize(
    "host_header", [None, "hOsT"], ids=["auto-host", "custom-host"]
)
async def test_http1_header_case(
    header_probe, blocking, title_case, streaming, preconnect, host_header
):
    url, received = header_probe
    payload = b"host: body\r\n\r\nPOST / HTTP/1.1\r\nhost: body\r\n\r\n"
    host = "Wire-Host.Example:8443" if host_header else urlsplit(url).netloc
    session = make_client(blocking, title_case).session(http1_only=True)
    try:
        if preconnect:
            await result(session.preconnect(url), blocking)
        for _ in range(2):
            kwargs = {
                "headers": {"x-MIXED": "Value-MiXeD", "accept": "text/plain"},
                "cookies": {"test": "Cookie-MiXeD"},
                "body": payload,
            }
            if host_header:
                kwargs["headers"][host_header] = host
            if streaming:
                response = await result(
                    session.send_streaming("POST", url, **kwargs), blocking
                )
                assert await result(response.bytes(), blocking) == b"OK"
            else:
                response = await result(session.post(url, **kwargs), blocking)
                assert response.content == b"OK"
        assert len(received) == 2
        for headers, body, _ in received:
            assert_headers(headers, title_case)
            assert ("Host", host) in headers
            length_name = "content-length" if title_case is False else "Content-Length"
            assert (length_name, str(len(payload))) in headers
            assert body == payload
        if not streaming:
            assert received[0][2] == received[1][2], (
                "buffered requests should reuse the connection"
            )
    finally:
        session.close()


@pytest.mark.parametrize("header_probe", [True], indirect=True, ids=["wss"])
@pytest.mark.parametrize("blocking", [False, True], ids=["async", "blocking"])
@pytest.mark.parametrize(
    "title_case", [None, True, False], ids=["default", "title", "lower"]
)
async def test_websocket_upgrade_header_case(header_probe, blocking, title_case):
    url, received = header_probe
    session = make_client(blocking, title_case).session()
    try:
        with pytest.raises(lkrequest.RequestError, match="400"):
            await result(
                session.ws_connect(
                    url.replace("http", "ws", 1), headers={"x-MIXED": "Value-MiXeD"}
                ),
                blocking,
            )
        [capture] = received
        headers = dict(capture[0])
        key = "sec-websocket-key" if title_case is False else "Sec-Websocket-Key"
        assert key in headers
        name = "x-mixed" if title_case is False else "X-Mixed"
        assert headers[name] == "Value-MiXeD"
        assert headers["Host"] == urlsplit(url).netloc
        assert [name for name, _ in capture[0]].count("Host") == 1
        if title_case is False:
            assert all(name == "Host" or name == name.lower() for name in headers)
    finally:
        session.close()
