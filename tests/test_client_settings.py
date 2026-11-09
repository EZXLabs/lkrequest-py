"""What a client was built with, read back: the fingerprint, the wire order,
timeouts and limits, the protocol policy and the rest, mostly under the name of
the argument that sets each, with a preset's own values where one was used.
"""

from __future__ import annotations

import pytest

import lkrequest
from lkrequest import ProtocolPolicy, TcpFingerprint
from lkrequest.blocking import Client as BlockingClient

OPTIONS = {
    "tls_profile": "chrome_152",
    "h2_profile": "firefox_147",
    "tcp_fingerprint": "chrome_win",
    "default_headers": [("X-First", "1"), ("Accept", "*/*")],
    "header_order": ["accept", "x-first"],
    "h3_header_order": ["x-first", "accept"],
    "cookie_order": ["b", "a"],
    "tcp_connect_timeout": 1.5,
    "total_timeout": 3.0,
    "max_connections_per_session": 4,
    "max_header_count": 50,
    "min_transfer_rate": 100,
    "min_transfer_rate_window": 2.0,
    "protocol_policy": ProtocolPolicy.chrome_conservative(),
    "verify": False,
    "ip_family": "ipv4",
    "proxy_fallback_direct": True,
    "h2_fallback_h1": False,
    "max_pending_h2_requests": 8,
    "ech_config": b"\x00\x01",
}


def axes(policy: ProtocolPolicy) -> tuple:
    return (policy.intent, policy.acquisition, policy.upgrade, policy.fallback)


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
def test_the_options_given_read_back(client_cls):
    client = client_cls(**OPTIONS)
    assert client.tls_profile.to_dict() == lkrequest.TlsProfile.chrome_152().to_dict()
    assert client.h2_profile.to_dict() == lkrequest.H2Profile.firefox_147().to_dict()
    assert client.tcp_fingerprint.to_dict() == TcpFingerprint.chrome_win().to_dict()
    # Lowercase, as they go out over HTTP/2.
    assert client.default_headers == [("x-first", "1"), ("accept", "*/*")]
    assert client.header_order == ["accept", "x-first"]
    assert client.h3_header_order == ["x-first", "accept"]
    assert client.cookie_order == ["b", "a"]
    assert client.timeouts["tcp_connect_timeout"] == 1.5
    assert client.timeouts["total_timeout"] == 3.0
    limits = client.resource_limits
    assert limits["max_connections_per_session"] == 4
    assert limits["max_header_count"] == 50
    assert (limits["min_transfer_rate"], limits["min_transfer_rate_window"]) == (
        100,
        2.0,
    )
    assert axes(client.protocol_policy) == axes(ProtocolPolicy.chrome_conservative())
    assert client.verify is False
    assert client.ip_family == "ipv4"
    assert (client.proxy_fallback_direct, client.h2_fallback_h1) == (True, False)
    assert client.max_pending_h2_requests == 8
    assert client.ech_config == b"\x00\x01"


def test_what_is_left_out_reads_as_the_default():
    client = lkrequest.Client()
    assert client.tcp_fingerprint is None
    assert client.default_headers == []
    assert (client.header_order, client.h3_header_order, client.cookie_order) == (
        None,
        None,
        None,
    )
    assert set(client.timeouts) == {
        "dns_timeout",
        "tcp_connect_timeout",
        "tls_handshake_timeout",
        "ttfb_timeout",
        "total_timeout",
        "quic_connect_timeout",
    }
    # No cap, as the argument's None means.
    assert client.resource_limits["max_connections_per_session"] is None
    assert axes(client.protocol_policy) == axes(ProtocolPolicy.crawler_throughput())
    assert (client.verify, client.ip_family) == (True, "any")
    assert (client.max_pending_h2_requests, client.ech_config) == (None, None)


def test_a_preset_reads_back_as_the_browser_it_copies():
    client = BlockingClient.chrome_155()
    assert client.tls_profile.to_dict() == lkrequest.TlsProfile.chrome_155().to_dict()
    assert client.tcp_fingerprint.to_dict() == TcpFingerprint.chrome().to_dict()
    assert client.header_order[:3] == [
        "content-length",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
    ]
    assert axes(client.protocol_policy) == axes(ProtocolPolicy.chrome_standard())


@pytest.mark.parametrize("client_cls", [lkrequest.Client, BlockingClient])
def test_a_randomized_copy_keeps_the_rest_of_the_client(client_cls):
    client = client_cls(**OPTIONS)
    copy = client.randomize_fingerprint(shuffle_extensions=False)
    for name in (
        "h2_profile",
        "tcp_fingerprint",
        "timeouts",
        "resource_limits",
    ):
        original, copied = getattr(client, name), getattr(copy, name)
        if hasattr(original, "to_dict"):
            original, copied = original.to_dict(), copied.to_dict()
        assert copied == original, name
    for name in (
        "default_headers",
        "header_order",
        "h3_header_order",
        "cookie_order",
        "verify",
        "ip_family",
        "proxy_fallback_direct",
        "h2_fallback_h1",
        "max_pending_h2_requests",
        "ech_config",
    ):
        assert getattr(copy, name) == getattr(client, name), name
    assert axes(copy.protocol_policy) == axes(client.protocol_policy)
    randomization = copy.tls_profile.to_dict()["randomization"]
    assert randomization == {"shuffle_extensions": False}
