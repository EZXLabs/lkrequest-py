"""MASQUE (RFC 9298 CONNECT-UDP) proxy support.

The end-to-end tests run a real tunnel: the client dials the local MASQUE proxy
(`_masque_proxy.py`) over HTTP/3, which relays the inner QUIC connection to the
local HTTP/3 server as plain UDP. What the proxy records is how a test tells a
request that went through the tunnel from one that did not.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit

import pytest

import lkrequest
from lkrequest import BlockingClient

pytestmark = pytest.mark.skipif(
    not hasattr(lkrequest, "MasqueConfig"),
    reason="built without the masque feature (maturin develop --features masque)",
)


def _masque_client(server_ca: bytes, **masque_kwargs) -> BlockingClient:
    """A client trusting the proxy's certificate; the origin hop skips verification."""
    masque_kwargs.setdefault("ca_cert_pem", server_ca)
    return BlockingClient(
        tls_profile="chrome_153",
        h2_profile="chrome_153",
        quic_profile="chrome_153",
        verify=False,
        masque=lkrequest.MasqueConfig(**masque_kwargs),
    )


_TIMEOUT = 10.0


def _port(url: str) -> int:
    port = urlsplit(url).port
    assert port is not None
    return port


class TestMasqueConfig:
    def test_defaults_follow_upstream(self):
        config = lkrequest.MasqueConfig()
        assert config.server_name is None
        assert config.use_native_certs is True
        assert config.verify is True
        assert config.ca_cert_count == 0
        assert config.tunnel_idle_timeout == 120.0
        assert config.max_idle_tunnels == 256

    def test_idle_timeout_none_disables_reclamation(self):
        assert (
            lkrequest.MasqueConfig(tunnel_idle_timeout=None).tunnel_idle_timeout is None
        )

    def test_ca_cert_pem_loads_every_certificate_in_the_bundle(self, server_ca):
        config = lkrequest.MasqueConfig(ca_cert_pem=server_ca + server_ca)
        assert config.ca_cert_count == 2

    def test_ca_cert_reads_a_pem_file(self, server_ca, tmp_path):
        path = tmp_path / "ca.pem"
        path.write_bytes(server_ca)
        assert lkrequest.MasqueConfig(ca_cert=str(path)).ca_cert_count == 1

    def test_missing_ca_cert_file_raises_oserror(self, tmp_path):
        with pytest.raises(OSError, match="MASQUE CA cert"):
            lkrequest.MasqueConfig(ca_cert=str(tmp_path / "missing.pem"))

    @pytest.mark.parametrize(
        "pem",
        [
            b"",
            b"not a certificate",
            b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        ],
    )
    def test_a_bundle_without_a_usable_certificate_is_rejected(self, pem):
        # Leaving the trust store silently unchanged would only surface later,
        # as a handshake failure against the proxy.
        with pytest.raises(ValueError, match="MASQUE outer trust anchor PEM"):
            lkrequest.MasqueConfig(ca_cert_pem=pem)

    def test_negative_idle_timeout_is_rejected(self):
        with pytest.raises(ValueError):
            lkrequest.MasqueConfig(tunnel_idle_timeout=-1.0)

    def test_repr_reads_like_python(self):
        config = lkrequest.MasqueConfig(server_name="proxy.example", verify=False)
        assert repr(config) == (
            "MasqueConfig(server_name='proxy.example', verify=False, "
            "ca_cert_count=0, use_native_certs=True)"
        )

    def test_client_rejects_anything_else_as_masque(self):
        with pytest.raises(TypeError, match="MasqueConfig"):
            BlockingClient(masque={"verify": False})

    def test_is_exported_from_the_package(self):
        assert "MasqueConfig" in lkrequest.__all__


class TestMasqueProxyConfig:
    def test_masque_url_parses_with_the_default_port(self):
        proxy = lkrequest.ProxyConfig("masque://proxy.example")
        assert str(proxy) == "masque://proxy.example:443"
        assert proxy.hop_count() == 1

    def test_masque_cannot_be_a_chain_hop(self):
        # Nested tunnels shrink the usable MTU at every hop.
        with pytest.raises(ValueError, match="MASQUE"):
            lkrequest.ProxyConfig.parse_chain(
                ["masque://proxy.example:443", "http://final.example:8080"]
            )


class TestHealthCheckTunnelProbe:
    def test_probe_without_an_outer_config_is_refused(self):
        # Upstream would skip the probe with only a log line; here both arrive
        # in one call, so the silent no-op is refused instead.
        with pytest.raises(ValueError, match="tunnel_probe=True needs masque"):
            lkrequest.HealthCheckConfig(tunnel_probe=True)

    def test_probe_with_an_outer_config_is_accepted(self):
        lkrequest.HealthCheckConfig(tunnel_probe=True, masque=lkrequest.MasqueConfig())

    def test_probe_opens_a_real_tunnel(self, masque_proxy, h3_server_url, server_ca):
        target_port = _port(h3_server_url)
        health = lkrequest.HealthCheckConfig(
            interval=60.0,
            timeout=5.0,
            target_host="127.0.0.1",
            target_port=target_port,
            tunnel_probe=True,
            masque=lkrequest.MasqueConfig(ca_cert_pem=server_ca),
        )
        # The first check runs as soon as the pool is built.
        pool = lkrequest.ProxyPool([masque_proxy.url], health_check=health)
        deadline = time.monotonic() + 10
        while not masque_proxy.stats.connects and time.monotonic() < deadline:
            time.sleep(0.05)
        del pool

        [connect] = masque_proxy.stats.connects
        assert connect.target == ("127.0.0.1", target_port)
        assert connect.status == 200


class TestRequestsThroughMasque:
    def test_h3_request_goes_through_the_tunnel(
        self, masque_proxy, h3_server_url, server_ca
    ):
        session = _masque_client(server_ca).session(
            proxy=masque_proxy.url, http3_only=True
        )
        resp = session.get(f"{h3_server_url}/get", timeout=_TIMEOUT)

        assert resp.status_code == 200
        assert resp.version == lkrequest.HttpVersion.H3
        # One tunnel: the first one on a new outer connection must succeed.
        [connect] = masque_proxy.stats.connects
        assert connect.target == ("127.0.0.1", _port(h3_server_url))
        assert connect.headers[":protocol"] == "connect-udp"
        # The response came back through the proxy, not around it.
        assert masque_proxy.stats.datagrams_to_target > 0
        assert masque_proxy.stats.datagrams_to_client > 0

    async def test_async_client_goes_through_the_tunnel(
        self, masque_proxy, h3_server_url, server_ca
    ):
        client = lkrequest.Client(
            quic_profile="chrome_153",
            verify=False,
            masque=lkrequest.MasqueConfig(ca_cert_pem=server_ca),
        )
        session = client.session(proxy=masque_proxy.url, http3_only=True)
        resp = await session.get(f"{h3_server_url}/get", timeout=_TIMEOUT)

        assert resp.status_code == 200
        assert resp.version == lkrequest.HttpVersion.H3
        assert masque_proxy.stats.datagrams_to_client > 0

    def test_the_default_protocol_policy_goes_through_the_tunnel(
        self, masque_proxy, h3_server_url, server_ca
    ):
        # No `http3_only`: the protocol decision must reach HTTP/3 on its own.
        # Upstream used to size the first tunnel before the proxy acknowledged
        # the outer connection's path-MTU probe, which aioquic, the double's
        # stack, acknowledges only when its ACK timer fires; the tunnel came out
        # too narrow, and under this policy the failure quarantined the route,
        # sending every later request to TCP, which MASQUE cannot carry.
        session = _masque_client(server_ca).session(proxy=masque_proxy.url)
        for _ in range(2):
            resp = session.get(f"{h3_server_url}/get", timeout=_TIMEOUT)
            assert resp.status_code == 200
            assert resp.version == lkrequest.HttpVersion.H3
        assert masque_proxy.stats.datagrams_to_client > 0

    def test_streaming_request_goes_through_the_tunnel(
        self, masque_proxy, h3_server_url, server_ca
    ):
        # Streaming requests take their own connection path upstream, and it
        # lagged behind the buffered one for MASQUE: a transient tunnel-capacity
        # failure quarantined the route and tried TCP, which MASQUE cannot carry.
        # The streaming response has no `version`; the proxy's record shows the
        # request went through the tunnel.
        session = _masque_client(server_ca).session(proxy=masque_proxy.url)
        resp = session.send_streaming("GET", f"{h3_server_url}/get", timeout=_TIMEOUT)

        assert resp.status_code == 200
        assert "headers" in json.loads(resp.bytes())
        [connect] = masque_proxy.stats.connects
        assert connect.target == ("127.0.0.1", _port(h3_server_url))
        assert masque_proxy.stats.datagrams_to_client > 0

    def test_http2_through_a_masque_proxy_fails_instead_of_going_direct(
        self, masque_proxy, server_url, server_ca
    ):
        # MASQUE carries UDP only. A TCP request must fail loudly rather than
        # quietly leave from this host's own address.
        session = _masque_client(server_ca).session(
            proxy=masque_proxy.url, http2_only=True
        )
        with pytest.raises(lkrequest.ProxyError):
            session.get(f"{server_url}/get", timeout=_TIMEOUT)
        assert masque_proxy.stats.connects == []

    def test_outer_hop_does_not_inherit_the_clients_verify(
        self, masque_proxy, h3_server_url
    ):
        # `verify=False` governs the origin only. The proxy's self-signed
        # certificate is not in the system store, so the outer handshake must
        # still fail — before any tunnel is requested.
        client = BlockingClient(
            quic_profile="chrome_153", verify=False, masque=lkrequest.MasqueConfig()
        )
        with pytest.raises(lkrequest.RequestError):
            client.session(proxy=masque_proxy.url, http3_only=True).get(
                f"{h3_server_url}/get", timeout=_TIMEOUT
            )
        assert masque_proxy.stats.connects == []

    def test_outer_verify_false_skips_the_proxy_certificate_check(
        self, masque_proxy, h3_server_url
    ):
        client = BlockingClient(
            quic_profile="chrome_153",
            verify=False,
            masque=lkrequest.MasqueConfig(use_native_certs=False, verify=False),
        )
        session = client.session(proxy=masque_proxy.url, http3_only=True)
        assert session.get(f"{h3_server_url}/get", timeout=_TIMEOUT).status_code == 200

    def test_http_credential_reaches_the_proxy_in_the_chosen_header(
        self, masque_proxy, h3_server_url, server_ca
    ):
        masque_proxy.reset(required_header=("authorization", "Bearer token-123"))
        proxy = (
            lkrequest.ProxyConfig(masque_proxy.url)
            .with_http_auth("Bearer", "token-123")
            .with_auth_header("authorization")
        )
        session = _masque_client(server_ca).session(proxy=proxy, http3_only=True)
        assert session.get(f"{h3_server_url}/get", timeout=_TIMEOUT).status_code == 200

        # The proxy only answers 200 when `authorization` carries the token.
        assert masque_proxy.stats.connects
        for connect in masque_proxy.stats.connects:
            assert connect.status == 200
            assert "proxy-authorization" not in connect.headers

    def test_a_rejected_credential_raises_proxy_error(
        self, masque_proxy, h3_server_url, server_ca
    ):
        masque_proxy.reset(required_header=("proxy-authorization", "Bearer right"))
        proxy = lkrequest.ProxyConfig(masque_proxy.url).with_http_auth(
            "Bearer", "wrong"
        )
        with pytest.raises(lkrequest.ProxyError):
            _masque_client(server_ca).session(proxy=proxy, http3_only=True).get(
                f"{h3_server_url}/get", timeout=_TIMEOUT
            )
        [connect] = masque_proxy.stats.connects
        assert connect.status == 407
