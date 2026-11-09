"""What an exception says about the failure beyond its message.

Every `RequestError` carries `phase`, `retryable`, `safe_to_replay`,
`status_code`, `proxy_error_kind`, `tls_alert` and `diagnostics`, read from the
Rust library's error: which step of the connection failed, whether trying
again could help, whether the request can be sent again without the server
having seen it. A retry callback that takes `exception=` gets the exception
itself. The failures here are made by local servers that refuse in a known way.
"""

from __future__ import annotations

import pickle
import socket
import threading

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

TARGET = "https://target.example/"
ATTRIBUTES = {
    "phase": None,
    "retryable": False,
    "safe_to_replay": False,
    "status_code": None,
    "proxy_error_kind": None,
    "tls_alert": None,
    "diagnostics": None,
}
# A TLS record holding a fatal handshake_failure alert.
HANDSHAKE_FAILURE = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
# Credentials are only sent again for a proxy that asks for Basic.
AUTH_REQUIRED = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="proxy"\r\n\r\n'
)
FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def answer_once(reply: bytes) -> int:
    """A TCP server that answers the first thing it receives with `reply`."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(reply)
        listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1]


def raised(call) -> lkrequest.RequestError:
    with pytest.raises(lkrequest.RequestError) as info:
        call()
    return info.value


def details(err: lkrequest.RequestError) -> dict:
    return {name: getattr(err, name) for name in ATTRIBUTES if name != "diagnostics"}


@pytest.mark.parametrize(
    "cls",
    [
        lkrequest.RequestError,
        lkrequest.TlsError,
        lkrequest.ProxyError,
        lkrequest.HttpStatusError,
        lkrequest.LkConnectionError,
        lkrequest.LkTimeoutError,
        lkrequest.TooManyRedirectsError,
        lkrequest.ResourceLimitError,
    ],
)
def test_every_request_error_has_the_attributes(cls):
    err = cls("built by hand")
    assert {name: getattr(err, name) for name in ATTRIBUTES} == ATTRIBUTES


def test_json_decode_error_has_them_too():
    err = lkrequest.JsonDecodeError("Expecting value", "", 0)
    assert err.retryable is False and err.phase is None


def test_a_refused_connection():
    port = closed_port()
    err = raised(lambda: BlockingClient().session().get(f"http://127.0.0.1:{port}/"))
    assert isinstance(err, lkrequest.LkConnectionError)
    assert details(err) == {
        "phase": "tcp_connect",
        "retryable": True,
        # Nothing was sent, so sending it again cannot repeat it.
        "safe_to_replay": True,
        "status_code": None,
        "proxy_error_kind": None,
        "tls_alert": None,
    }
    # The timings of the attempt come with it, as on a response.
    assert set(err.diagnostics) == {
        "dns_ms",
        "tcp_ms",
        "tls_ms",
        "ttfb_ms",
        "total_ms",
        "remote_addr",
        "protocol",
        "cipher_suite",
        "trust_anchor",
    }
    assert err.diagnostics["total_ms"] is not None
    # No TLS handshake, so no trust anchor negotiation either.
    assert err.diagnostics["trust_anchor"] is None


async def test_an_async_request_raises_with_the_attributes():
    port = closed_port()
    with pytest.raises(lkrequest.LkConnectionError) as info:
        await lkrequest.Client().session().get(f"http://127.0.0.1:{port}/")
    assert info.value.phase == "tcp_connect"
    assert info.value.diagnostics is not None


def test_a_tls_alert_from_the_server():
    port = answer_once(HANDSHAKE_FAILURE)
    err = raised(lambda: BlockingClient().session().get(f"https://127.0.0.1:{port}/"))
    assert isinstance(err, lkrequest.TlsError)
    assert (err.phase, err.tls_alert) == ("tls_handshake", "handshake_failure")
    assert err.diagnostics["remote_addr"] == f"127.0.0.1:{port}"


@pytest.mark.parametrize(
    ("reply", "credentials", "kind"),
    [
        (AUTH_REQUIRED, "", "authentication_required"),
        (AUTH_REQUIRED, "u:p@", "authentication_failed"),
        (FORBIDDEN, "", "tunnel_refused"),
    ],
    ids=["no-credentials", "wrong-credentials", "refused"],
)
def test_what_a_proxy_refused(raw_http, reply, credentials, kind):
    proxy = raw_http(lambda request: reply)
    session = BlockingClient().session(
        proxy=f"http://{credentials}127.0.0.1:{proxy.port}"
    )
    err = raised(lambda: session.get(TARGET, timeout=5.0))
    assert isinstance(err, lkrequest.ProxyError)
    assert (err.phase, err.proxy_error_kind) == ("proxy_tunnel", kind)


def test_a_proxy_that_is_not_there():
    session = BlockingClient().session(proxy=f"http://127.0.0.1:{closed_port()}")
    err = raised(lambda: session.get(TARGET, timeout=5.0))
    assert err.proxy_error_kind == "tcp_connect_failed"


@pytest.mark.parametrize(("status", "retryable"), [(503, True), (404, False)])
def test_error_for_status_carries_the_status(raw_http, status, retryable):
    server = raw_http(
        lambda request: f"HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n".encode()
    )
    response = BlockingClient().session().get(server.url)
    err = raised(response.error_for_status)
    assert isinstance(err, lkrequest.HttpStatusError)
    assert (err.status_code, err.retryable, err.safe_to_replay) == (
        status,
        retryable,
        False,
    )
    assert err.diagnostics == response.diagnostics


def test_the_attributes_survive_pickling():
    port = closed_port()
    err = raised(lambda: BlockingClient().session().get(f"http://127.0.0.1:{port}/"))
    restored = pickle.loads(pickle.dumps(err))
    assert type(restored) is type(err)
    assert str(restored) == str(err)
    assert details(restored) == details(err)
    assert restored.diagnostics == err.diagnostics


# ---------------------------------------------------------------------------
# Retry callbacks
# ---------------------------------------------------------------------------


def test_a_retry_callback_that_takes_exception_gets_it():
    seen = []

    def retry(attempt, error, status, exception=None):
        seen.append((attempt, error, status, exception))
        return None

    port = closed_port()
    session = BlockingClient().session(retry=retry)
    with pytest.raises(lkrequest.LkConnectionError):
        session.get(f"http://127.0.0.1:{port}/")
    [(attempt, error, status, exception)] = seen
    assert isinstance(exception, lkrequest.LkConnectionError)
    assert exception.phase == "tcp_connect" and exception.retryable
    # The positional arguments are what they always were.
    assert (attempt, error, status) == (1, str(exception), None)


def test_a_retry_callback_with_kwargs_gets_it_too():
    seen = []

    def retry(attempt, error, status, **kwargs):
        seen.append(kwargs)

    session = BlockingClient().session(retry=retry)
    with pytest.raises(lkrequest.LkConnectionError):
        session.get(f"http://127.0.0.1:{closed_port()}/")
    assert isinstance(seen[0]["exception"], lkrequest.LkConnectionError)


def test_a_retry_callback_of_three_arguments_still_gets_three():
    seen = []

    def retry(attempt, error, status):
        seen.append((attempt, error, status))

    session = BlockingClient().session(retry=retry)
    with pytest.raises(lkrequest.LkConnectionError):
        session.get(f"http://127.0.0.1:{closed_port()}/")
    assert len(seen) == 1
