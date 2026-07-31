"""Tests against the local hypercorn httpbin server (no external network).

Covers HTTP/1.1, HTTP/2, and (when built with the quic-h3 feature) HTTP/3.
"""

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient


def test_blocking_h2_get(server_url):
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert "headers" in resp.json()
    # chrome preset advertises h2 in ALPN; hypercorn offers it.
    assert resp.version == lkrequest.HttpVersion.H2


def test_blocking_http1_only(server_url):
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    resp = client.session(http1_only=True).get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.HTTP11


def test_ca_cert_pem_is_accepted(server_url, server_ca):
    # Smoke test that ca_cert_pem is accepted as a client option. NOTE: this
    # does not currently assert that pinning is *enforced* — see
    # test_tls_verification_is_enforced (xfail) for the verification gap.
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", ca_cert_pem=server_ca
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200


def test_tls_verification_is_enforced(server_url):
    # A default (verify=True) client MUST reject the local self-signed cert.
    # Requires the lkrequest core fix that maps verify=True -> Strict (otherwise
    # it falls through to BrowserCompat, which swallows all chain errors).
    client = BlockingClient(tls_profile="chrome_144", h2_profile="chrome_144")
    with pytest.raises(Exception):
        client.session().get(f"{server_url}/get")


def test_verify_false_still_connects(server_url):
    # The escape hatch must keep working: verify=False trusts anything.
    client = BlockingClient(
        tls_profile="chrome_144", h2_profile="chrome_144", verify=False
    )
    assert client.session().get(f"{server_url}/get").status_code == 200


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"),
    reason="built without the quic-h3 feature (maturin develop --features quic-h3)",
)
@pytest.mark.xfail(
    reason="lkrequest's QUIC stack does not complete a handshake against the "
    "hypercorn/aioquic test server (handshake times out). The H3 client path "
    "is exercised (it emits an H3-specific error), but full wire interop with "
    "this server is unverified — validate against a production H3 server "
    "(e.g. Caddy) or a public H3 endpoint.",
    strict=False,
)
def test_h3_get(h3_server_url):
    # The dedicated H3 server serves HTTP/3 on its UDP port via aioquic. With
    # http3_only the client must use QUIC or fail, so a 200 proves H3 worked.
    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        quic_profile="chrome_146",
        verify=False,
    )
    resp = client.session(http3_only=True).get(f"{h3_server_url}/get", timeout=5.0)
    assert resp.status_code == 200
    assert "headers" in resp.json()


def test_extension_order_randomization_completes_request(server_url):
    # A client with per-connection TLS extension-order randomization (Tier 1)
    # must still complete a real handshake + request against the local server.
    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        randomize=lkrequest.Randomize.extension_order(),
        verify=False,
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.H2


@pytest.mark.skipif(
    not hasattr(lkrequest, "NegotiabilityFloor"),
    reason="synthetic fingerprint tiers require the synthetic-fp build feature",
)
@pytest.mark.parametrize("floor_name", ["UNIVERSAL", "PRESET_FAMILY"])
def test_recombine_negotiability_floor_completes_request(server_url, floor_name):
    # Python mirror of upstream lkrequest's `recombine_preset_family_floor_
    # negotiates` e2e test, but hermetic (local server, no public network): a
    # synthetic (recombine) client whose sig-alg negotiability floor is a
    # guaranteed-negotiable tier must still complete a real TLS handshake +
    # request. Exercises the `negotiability()` builder threading end to end.
    floor = getattr(lkrequest.NegotiabilityFloor, floor_name)
    client = BlockingClient(
        tls_profile="chrome_146",
        h2_profile="chrome_146",
        randomize=lkrequest.Randomize.recombine().negotiability(floor),
        verify=False,
    )
    resp = client.session().get(f"{server_url}/get")
    assert resp.status_code == 200
    assert resp.version == lkrequest.HttpVersion.H2
