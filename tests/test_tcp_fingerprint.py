"""The parts of a `TcpFingerprint` beyond window, MSS, scale, TTL and buffers:
the SYN's option order, keep-alive, and the `none()` and `safari_ios()` presets.

The option order is descriptive, since the OS builds the SYN, so it shows in
`to_ja4t()`; keep-alive is a socket option, read back with `to_dict()`.
"""

from __future__ import annotations

import pytest

import lkrequest
from lkrequest import TcpFingerprint
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
NOTHING = {
    "window_size": None,
    "mss": None,
    "window_scale": None,
    "ttl": None,
    "tcp_nodelay": None,
    "recv_buf_size": None,
    "send_buf_size": None,
    "tcp_options": None,
    "keepalive": None,
    "keepalive_idle": None,
    "keepalive_interval": None,
}


def test_tcp_options_are_part_b_of_ja4t():
    windows = TcpFingerprint(
        window_size=64240, tcp_options=[2, 1, 3, 1, 1, 4], mss=1460, window_scale=8
    )
    assert windows.to_ja4t() == "64240_2-1-3-1-1-4_1460_8"
    parsed = TcpFingerprint.from_ja4t("64240_2-1-3-1-1-4_1460_8").to_dict()
    assert windows.to_dict() == parsed
    assert parsed["tcp_options"] == [2, 1, 3, 1, 1, 4]


@pytest.mark.parametrize("kinds", [[5], [2, 9]])
def test_an_unknown_option_kind_is_refused(kinds):
    with pytest.raises(ValueError, match="Unknown TCP option kind"):
        TcpFingerprint(tcp_options=kinds)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, (None, None, None)),
        ({"keepalive": True}, (True, None, None)),
        ({"keepalive": False}, (False, None, None)),
        # Either timing alone turns keep-alive on.
        ({"keepalive_idle": 30.0}, (True, 30.0, None)),
        ({"keepalive_idle": 30.0, "keepalive_interval": 5.0}, (True, 30.0, 5.0)),
    ],
)
def test_keepalive(kwargs, expected):
    settings = TcpFingerprint(**kwargs).to_dict()
    assert (
        settings["keepalive"],
        settings["keepalive_idle"],
        settings["keepalive_interval"],
    ) == expected


def test_keepalive_timing_without_keepalive_is_refused():
    with pytest.raises(ValueError, match="keepalive=False"):
        TcpFingerprint(keepalive=False, keepalive_idle=30.0)


@pytest.mark.parametrize("seconds", [-1.0, float("nan")])
def test_a_keepalive_timing_must_be_a_duration(seconds):
    with pytest.raises(ValueError):
        TcpFingerprint(keepalive_interval=seconds)


def test_none_sets_nothing():
    assert TcpFingerprint.none().to_dict() == NOTHING
    assert TcpFingerprint.none().to_ja4t() is None
    assert TcpFingerprint().to_dict() == NOTHING


def test_safari_on_ios():
    ios = TcpFingerprint.safari_ios()
    assert ios.to_ja4t() == "65535_2-1-3-1-1-8-4-0_1460_6"
    assert ios.to_dict()["ttl"] == 64


def test_a_preset_reads_back_as_its_ja4t_says():
    settings = TcpFingerprint.chrome_win().to_dict()
    window, options, mss, scale = TcpFingerprint.chrome_win().to_ja4t().split("_")
    assert settings["window_size"] == int(window)
    assert settings["tcp_options"] == [int(kind) for kind in options.split("-")]
    assert (settings["mss"], settings["window_scale"]) == (int(mss), int(scale))


def test_a_client_with_keepalive_connects(raw_http):
    server = raw_http(lambda request: OK)
    fingerprint = TcpFingerprint(keepalive_idle=30.0, keepalive_interval=5.0)
    session = BlockingClient(tcp_fingerprint=fingerprint).session()
    assert session.get(server.url).status_code == 200


async def test_an_async_client_with_keepalive_connects(raw_http):
    server = raw_http(lambda request: OK)
    client = lkrequest.Client(tcp_fingerprint=TcpFingerprint(keepalive=True))
    assert (await client.session().get(server.url)).status_code == 200


@pytest.mark.parametrize(
    ("fingerprint", "text"),
    [
        (TcpFingerprint.none(), "TcpFingerprint()"),
        (
            TcpFingerprint(ttl=128, keepalive=True),
            "TcpFingerprint(ttl=128, keepalive=True)",
        ),
        (
            TcpFingerprint(window_size=65535, tcp_options=[2, 4]),
            "TcpFingerprint(window_size=65535, tcp_options=[2, 4])",
        ),
        # What JA4T covers reads as one; the rest follows by name.
        (
            TcpFingerprint.chrome_win(),
            "TcpFingerprint(ja4t='64240_2-1-3-1-1-4_1460_8', ttl=128, tcp_nodelay=True)",
        ),
        (
            TcpFingerprint.from_ja4t("64240_2-1-3-1-1-4_1460_8"),
            "TcpFingerprint(ja4t='64240_2-1-3-1-1-4_1460_8')",
        ),
        (
            TcpFingerprint(
                recv_buf_size=4096, keepalive_idle=30.0, keepalive_interval=5.0
            ),
            "TcpFingerprint(recv_buf_size=4096, keepalive=True, keepalive_idle=30.0, "
            "keepalive_interval=5.0)",
        ),
    ],
)
def test_the_repr_shows_what_is_set(fingerprint, text):
    assert repr(fingerprint) == text
