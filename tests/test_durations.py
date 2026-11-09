"""A duration given in seconds is checked before it is used.

A negative, NaN or infinite value, or one too large for the Rust library to
hold, raises `ValueError` instead of crashing with a `PanicException`, which
`except Exception` does not catch.
"""

from __future__ import annotations

import socket

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

# Seconds, more than a Rust `Duration` holds.
TOO_LARGE = 1e30
NOT_DURATIONS = [-1.0, float("nan"), float("inf"), TOO_LARGE]


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("seconds", NOT_DURATIONS)
def test_a_client_timeout_must_be_a_duration(seconds):
    with pytest.raises(ValueError, match="Duration must be"):
        lkrequest.Client(total_timeout=seconds)
    with pytest.raises(ValueError, match="Duration must be"):
        BlockingClient(total_timeout=seconds)


@pytest.mark.parametrize("seconds", NOT_DURATIONS)
def test_a_request_timeout_must_be_a_duration(raw_http, seconds):
    server = raw_http(lambda request: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    with pytest.raises(ValueError, match="Duration must be"):
        BlockingClient().session().get(server.url, timeout=seconds)
    assert server.connections == 0


def test_a_retry_delay_too_long_to_wait_is_no_retry():
    attempts = []

    def retry(attempt, error, status):
        attempts.append(attempt)
        return TOO_LARGE

    session = BlockingClient().session(retry=retry)
    with pytest.raises(lkrequest.LkConnectionError):
        session.get(f"http://127.0.0.1:{closed_port()}/")
    assert attempts == [1]
