"""The axes of a `ProtocolPolicy`: how connections are acquired, upgraded to
HTTP/3 and fallen back from it.

The presets can be read axis by axis and changed one axis at a time. A
combination the Rust library calls contradictory is refused when the policy
reaches a session or a client, rather than when the first request is sent.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

import lkrequest
from lkrequest import (
    AcquisitionPolicy,
    FallbackPolicy,
    HttpIntent,
    ProtocolPolicy,
    RacePolicy,
    UpgradePolicy,
)
from lkrequest.blocking import Client as BlockingClient


@pytest.mark.parametrize(
    ("preset", "acquisition", "upgrade", "fallback"),
    [
        (
            ProtocolPolicy.chrome_standard,
            RacePolicy.chrome_like(),
            UpgradePolicy.ProbeAndMigrate,
            FallbackPolicy.AllowFallbackOnNetworkErrors,
        ),
        (
            ProtocolPolicy.chrome_conservative,
            AcquisitionPolicy.ReuseExistingFirst,
            UpgradePolicy.ProbeOnly,
            FallbackPolicy.AllowFallbackOnNetworkErrors,
        ),
        (
            ProtocolPolicy.crawler_throughput,
            AcquisitionPolicy.ReuseExistingFirst,
            UpgradePolicy.Off,
            FallbackPolicy.AllowFallback,
        ),
        (
            ProtocolPolicy.h3_strict,
            AcquisitionPolicy.EstablishBestAvailable,
            UpgradePolicy.ForceForNewRequests,
            FallbackPolicy.NoFallback,
        ),
    ],
)
def test_a_preset_reads_axis_by_axis(preset, acquisition, upgrade, fallback):
    policy = preset()
    assert (policy.acquisition, policy.upgrade, policy.fallback) == (
        acquisition,
        upgrade,
        fallback,
    )
    policy.validate()


def test_each_with_changes_one_axis_of_a_copy():
    standard = ProtocolPolicy.chrome_standard()
    race = RacePolicy(tcp_delay=0.1)
    changed = (
        standard.with_acquisition(race)
        .with_upgrade(UpgradePolicy.ProbeOnly)
        .with_fallback(FallbackPolicy.NoFallback)
    )
    assert (changed.acquisition, changed.upgrade, changed.fallback) == (
        race,
        UpgradePolicy.ProbeOnly,
        FallbackPolicy.NoFallback,
    )
    assert changed.intent == standard.intent
    assert standard.acquisition == RacePolicy.chrome_like()
    assert standard.with_acquisition(
        AcquisitionPolicy.EstablishBestAvailable
    ).acquisition == (AcquisitionPolicy.EstablishBestAvailable)


def test_a_race_keeps_chromes_timing_unless_told_otherwise():
    chrome = RacePolicy.chrome_like()
    assert (
        chrome.enable_tcp,
        chrome.enable_quic,
        chrome.tcp_delay,
        chrome.quic_delay,
        chrome.only_when_h3_advertised,
    ) == (True, True, 0.3, 0.0, True)
    assert RacePolicy() == chrome
    race = RacePolicy(enable_quic=False, quic_delay=0.05)
    assert (race.enable_tcp, race.enable_quic, race.quic_delay) == (True, False, 0.05)
    assert race != chrome
    assert "enable_quic=False" in repr(race)


@pytest.mark.parametrize("delay", [-1.0, float("nan"), float("inf")])
def test_a_race_refuses_a_delay_that_is_not_a_duration(delay):
    with pytest.raises(ValueError):
        RacePolicy(tcp_delay=delay)


def test_acquisition_must_be_a_policy_or_a_race():
    with pytest.raises(TypeError, match="AcquisitionPolicy or a RacePolicy"):
        ProtocolPolicy.chrome_standard().with_acquisition("race")


CONTRADICTIONS = {
    "h3-only falls back": ProtocolPolicy.h3_strict().with_fallback(
        FallbackPolicy.AllowFallback
    ),
    "h2-only upgrades": ProtocolPolicy.crawler_throughput()
    .with_intent(HttpIntent.H2Only)
    .with_upgrade(UpgradePolicy.ProbeOnly),
    "race of nothing": ProtocolPolicy.chrome_standard().with_acquisition(
        RacePolicy(enable_tcp=False, enable_quic=False)
    ),
    "h2-only races quic": ProtocolPolicy.crawler_throughput()
    .with_intent(HttpIntent.H2Only)
    .with_acquisition(RacePolicy()),
    "h3-only races tcp": ProtocolPolicy.h3_strict().with_acquisition(RacePolicy()),
}


@pytest.mark.parametrize("policy", CONTRADICTIONS.values(), ids=CONTRADICTIONS.keys())
def test_a_contradiction_is_refused(policy):
    with pytest.raises(ValueError, match="ProtocolPolicy conflict"):
        policy.validate()
    # ... by a session and a client alike, before anything is sent.
    with pytest.raises(ValueError, match="ProtocolPolicy conflict"):
        lkrequest.Client().session(protocol_policy=policy)
    with pytest.raises(ValueError, match="ProtocolPolicy conflict"):
        BlockingClient().session(protocol_policy=policy)
    with pytest.raises(ValueError, match="ProtocolPolicy conflict"):
        lkrequest.Client(protocol_policy=policy)
    with pytest.raises(ValueError, match="ProtocolPolicy conflict"):
        BlockingClient(protocol_policy=policy)


def test_a_contradiction_for_one_request_is_refused_before_it_is_sent(raw_http):
    server = raw_http(lambda request: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    policy = CONTRADICTIONS["h3-only falls back"]
    with pytest.raises(ValueError, match="ProtocolPolicy conflict"):
        BlockingClient().session().get(server.url, protocol_policy=policy)
    assert server.connections == 0


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"), reason="built without the quic-h3 feature"
)
@pytest.mark.parametrize(
    ("acquisition", "version"),
    [(AcquisitionPolicy.ReuseExistingFirst, "H2"), (RacePolicy(), "H3")],
)
def test_a_race_reaches_an_origin_over_http3(h3_server_url, acquisition, version):
    class Resolver:
        """Advertises HTTP/3 for the host, as its DNS HTTPS record would."""

        def resolve(self, host, port):
            return ["127.0.0.1"]

        def lookup_https(self, host):
            return {"alpn": ["h3", "h2"]}

    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        quic_profile="chrome_146",
        verify=False,
        dns=Resolver(),
    )
    # The conservative preset keeps to TCP; racing gives QUIC its head start.
    policy = ProtocolPolicy.chrome_conservative().with_acquisition(acquisition)
    session = client.session(protocol_policy=policy)
    port = urlsplit(h3_server_url).port
    response = session.get(f"https://service.test:{port}/get", timeout=5.0)
    assert response.version is getattr(lkrequest.HttpVersion, version)
