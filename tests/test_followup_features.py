"""Tests for features added while tracking the lkrequest core update:

new browser presets (chrome_145/146/147/148), request priority, protocol
policy / HTTP intent, session resumption, per-request preferred HTTP version /
idempotency, and the QUIC/H3 surface.

These are construction/type tests plus localhost-only kwarg-acceptance checks,
so they do not depend on external network reachability.
"""

import json

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

NEW_CHROME_PRESETS = [
    "chrome_145",
    "chrome_146",
    "chrome_147",
    "chrome_148",
    "chrome_149",
    "chrome_150",
    "chrome_151",
]


class TestNewPresets:
    @pytest.mark.parametrize("name", NEW_CHROME_PRESETS)
    def test_client_preset(self, name):
        client = getattr(lkrequest.Client, name)()
        assert "Client" in repr(client)

    @pytest.mark.parametrize("name", NEW_CHROME_PRESETS)
    def test_blocking_client_preset(self, name):
        client = getattr(BlockingClient, name)()
        assert "Client" in repr(client)

    @pytest.mark.parametrize("name", NEW_CHROME_PRESETS)
    def test_string_resolution(self, name):
        client = lkrequest.Client(tls_profile=name, h2_profile=name)
        info = client.fingerprint_info()
        assert info["tls_profile"]

    @pytest.mark.parametrize("name", NEW_CHROME_PRESETS)
    def test_tls_and_h2_profile_presets(self, name):
        assert getattr(lkrequest.TlsProfile, name)() is not None
        assert getattr(lkrequest.H2Profile, name)() is not None

    def test_fingerprint_info_reports_version(self):
        info = lkrequest.Client.chrome_148().fingerprint_info()
        assert "148" in info["tls_profile"]

    def test_chrome_151_reuses_chrome_150_tcp_shape(self):
        # Python mirror of upstream's `chrome_151_matches_chrome_150_tcp_stable_
        # fields`: Chrome 151 reuses Chrome 150's TCP capture, so the serialized
        # TLS profiles differ only by `name` and the H2 profiles (which carry no
        # name) are identical. Guards against a future upstream capture
        # diverging without a matching binding/doc update here.
        tls150 = json.loads(lkrequest.TlsProfile.chrome_150().to_json())
        tls151 = json.loads(lkrequest.TlsProfile.chrome_151().to_json())
        assert (tls150.pop("name"), tls151.pop("name")) == ("Chrome 150", "Chrome 151")
        assert tls150 == tls151
        assert (
            lkrequest.H2Profile.chrome_151().to_json()
            == lkrequest.H2Profile.chrome_150().to_json()
        )

    def test_quic_tls_presets_differ_from_their_tcp_counterparts(self):
        # The QUIC-TLS presets are the ClientHello Chrome sends inside QUIC; they
        # are plain TLS profiles (no quic-h3 feature needed) and must not be
        # confused with the TCP profile of the same version.
        for name in ("chrome_146", "chrome_150", "chrome_151"):
            tcp = json.loads(getattr(lkrequest.TlsProfile, name)().to_json())
            quic = json.loads(getattr(lkrequest.TlsProfile, f"{name}_quic")().to_json())
            assert quic["name"] == f"{tcp['name']} QUIC"
            assert quic != tcp
            # Usable where a QUIC-specific fingerprint is expected.
            client = lkrequest.Client(
                quic_fingerprint=getattr(lkrequest.TlsProfile, f"{name}_quic")()
            )
            assert "Client" in repr(client)

    def test_chrome_151_quic_omits_ml_dsa_signature_algorithms(self):
        # Python mirror of upstream's
        # `chrome_151_quic_matches_public_h3_capture_signature_algorithms`: real
        # Chrome 151 H3 captures drop the three ML-DSA codepoints that Chrome 150
        # sends, while Chrome 151's TCP profile keeps them.
        ml_dsa = {0x0904, 0x0905, 0x0906}
        sig_algs = {
            name: json.loads(getattr(lkrequest.TlsProfile, name)().to_json())[
                "signature_algorithms"
            ]
            for name in ("chrome_151", "chrome_150_quic", "chrome_151_quic")
        }
        assert ml_dsa.issubset(sig_algs["chrome_151"])
        assert ml_dsa.issubset(sig_algs["chrome_150_quic"])
        assert ml_dsa.isdisjoint(sig_algs["chrome_151_quic"])
        assert sig_algs["chrome_151_quic"] == [
            0x0403,
            0x0804,
            0x0401,
            0x0503,
            0x0805,
            0x0501,
            0x0806,
            0x0601,
            0x0201,
        ]

    def test_unknown_preset_still_errors(self):
        with pytest.raises(ValueError, match="Unknown TLS profile"):
            lkrequest.Client(tls_profile="chrome_999")

    @pytest.mark.parametrize(
        "name",
        [
            "chrome_131",
            "chrome_144",
            "chrome_145",
            "chrome_146",
            "chrome_147",
            "chrome_148",
            "chrome_149",
            "chrome_150",
            "chrome_151",
            "firefox_133",
            "firefox_147",
            "safari_18",
            "safari_26",
        ],
    )
    def test_static_preset_methods(self, name):
        # Covers every Client/BlockingClient preset static method (the request
        # tests build clients via the constructor with verify=False).
        assert "Client" in repr(getattr(lkrequest.Client, name)())
        assert "Client" in repr(getattr(BlockingClient, name)())


class TestRequestPriority:
    def test_preset_urgencies(self):
        assert lkrequest.RequestPriority.navigation().urgency == 0
        assert lkrequest.RequestPriority.fetch().urgency == 1
        assert lkrequest.RequestPriority.fetch().incremental is True
        assert lkrequest.RequestPriority.image().urgency == 2
        assert lkrequest.RequestPriority.background().urgency == 3

    def test_custom(self):
        p = lkrequest.RequestPriority(5, incremental=True)
        assert p.urgency == 5
        assert p.incremental is True

    def test_urgency_is_clamped(self):
        assert lkrequest.RequestPriority(99).urgency == 7

    def test_header_value(self):
        # Test the formatter directly (preset incremental flags may change upstream).
        assert (
            lkrequest.RequestPriority(1, incremental=True).to_header_value() == "u=1, i"
        )
        assert (
            lkrequest.RequestPriority(2, incremental=False).to_header_value() == "u=2"
        )

    def test_accepted_as_request_kwarg(self):
        session = BlockingClient.chrome_144().session()
        # Connect to a refused local port: proves the kwarg is accepted (no
        # TypeError) and the request was actually built/sent.
        with pytest.raises(Exception) as exc:
            session.get(
                "http://127.0.0.1:1",
                priority=lkrequest.RequestPriority.image(),
                timeout=2.0,
            )
        assert not isinstance(exc.value, TypeError)


class TestProtocolPolicy:
    @pytest.mark.parametrize(
        "ctor",
        ["chrome_standard", "chrome_conservative", "crawler_throughput", "h3_strict"],
    )
    def test_presets(self, ctor):
        policy = getattr(lkrequest.ProtocolPolicy, ctor)()
        assert "ProtocolPolicy" in repr(policy)

    def test_with_intent(self):
        policy = lkrequest.ProtocolPolicy.chrome_standard().with_intent(
            lkrequest.HttpIntent.H2Only
        )
        assert policy.intent == lkrequest.HttpIntent.H2Only

    def test_client_accepts_protocol_policy(self):
        client = lkrequest.Client(
            protocol_policy=lkrequest.ProtocolPolicy.crawler_throughput()
        )
        assert "Client" in repr(client)

    def test_session_accepts_policy_and_intent(self):
        session = lkrequest.Client.chrome_144().session(
            protocol_policy=lkrequest.ProtocolPolicy.chrome_conservative(),
            http_intent=lkrequest.HttpIntent.H2Only,
        )
        assert "Session" in repr(session)


class TestSessionResumption:
    def test_disabled_preset(self):
        cfg = lkrequest.SessionResumptionConfig.disabled()
        assert cfg.tls13_psk is False
        assert cfg.tls12_session_ticket is False
        assert cfg.store_tickets is False

    def test_chrome_preset(self):
        cfg = lkrequest.SessionResumptionConfig.chrome()
        assert cfg.tls13_psk is True

    def test_custom(self):
        cfg = lkrequest.SessionResumptionConfig(
            tls13_psk=False, tls12_session_ticket=True, max_tickets_per_host=2
        )
        assert cfg.tls13_psk is False
        assert cfg.tls12_session_ticket is True
        assert cfg.max_tickets_per_host == 2

    def test_client_accepts_config(self):
        client = lkrequest.Client(
            session_resumption=lkrequest.SessionResumptionConfig.disabled()
        )
        assert "Client" in repr(client)


class TestPreferredHttpVersionAndIdempotency:
    def test_enum_members_exist(self):
        assert lkrequest.PreferredHttpVersion.Http2Only is not None
        assert lkrequest.PreferredHttpVersion.Http3WithFallback is not None
        assert lkrequest.Idempotency.Idempotent is not None
        assert lkrequest.Idempotency.NotIdempotent is not None

    def test_accepted_as_request_kwargs(self):
        session = BlockingClient.chrome_144().session()
        with pytest.raises(Exception) as exc:
            session.post(
                "http://127.0.0.1:1",
                json={"x": 1},
                preferred_http_version=lkrequest.PreferredHttpVersion.Http2Only,
                idempotency=lkrequest.Idempotency.Idempotent,
                timeout=2.0,
            )
        assert not isinstance(exc.value, TypeError)


class TestQuicSurface:
    def test_broken_quic_policy_enum(self):
        assert lkrequest.BrokenQuicPolicy.Strict is not None
        assert lkrequest.BrokenQuicPolicy.Resilient is not None
        assert lkrequest.BrokenQuicPolicy.Disabled is not None

    def test_session_accepts_quic_kwargs(self):
        session = lkrequest.Client.chrome_146().session(
            http3_with_fallback=True,
            broken_quic_policy=lkrequest.BrokenQuicPolicy.Resilient,
        )
        assert "Session" in repr(session)

    def test_client_disable_http3(self):
        assert "Client" in repr(lkrequest.Client(disable_http3=True))

    def test_client_quic_fingerprint(self):
        # quic_fingerprint is a TLS profile -> available without the feature.
        assert "Client" in repr(lkrequest.Client(quic_fingerprint="chrome_146"))

    def test_quic_profile_without_feature_errors(self):
        # The default build has no quic-h3 feature; quic_profile must report a
        # clear error rather than silently doing nothing.
        if hasattr(lkrequest, "QuicProfile"):
            pytest.skip("built with the quic-h3 feature")
        with pytest.raises(RuntimeError, match="quic-h3"):
            lkrequest.Client(quic_profile="chrome_146")

    def test_quic_profile_with_feature(self):
        # Only runs when built with `maturin develop --features quic-h3`.
        if not hasattr(lkrequest, "QuicProfile"):
            pytest.skip("built without the quic-h3 feature")
        profiles = {}
        for name in ("chrome_146", "chrome_150", "chrome_151"):
            qp = getattr(lkrequest.QuicProfile, name)()
            assert qp.connection_id_length >= 0
            qp.validate()  # raises on invalid
            assert "QuicProfile" in repr(qp)
            # round-trip JSON
            restored = lkrequest.QuicProfile.from_json(qp.to_json())
            assert restored.connection_id_length == qp.connection_id_length
            # usable on a Client, both as object and as preset name
            assert "Client" in repr(lkrequest.Client(quic_profile=qp))
            assert "Client" in repr(lkrequest.Client(quic_profile=name))
            profiles[name] = qp.to_json()

        assert profiles["chrome_150"] != profiles["chrome_146"]
        # Chrome 151 keeps Chrome 150's QUIC transport parameters and H3
        # SETTINGS verbatim; the two presets differ only in their QUIC-TLS
        # signature algorithms (Chrome 151 drops the three ML-DSA codepoints),
        # which live in the QUIC-TLS profile rather than in QuicProfile. That
        # profile is reachable only through `Client.chrome_151()`, so the
        # difference is not observable on QuicProfile itself.
        assert profiles["chrome_151"] == profiles["chrome_150"]


# ==========================================================================
# Fingerprint randomization (Randomize / Layers)
# ==========================================================================


class TestRandomize:
    """Tier 0/1 randomization policy — always available."""

    def test_off_and_extension_order_exist(self):
        assert lkrequest.Randomize.off() is not None
        assert lkrequest.Randomize.extension_order() is not None

    def test_repr(self):
        assert "off" in repr(lkrequest.Randomize.off())
        assert "extension_order" in repr(lkrequest.Randomize.extension_order())

    def test_client_accepts_randomize(self):
        client = lkrequest.Client(
            tls_profile="chrome_146",
            randomize=lkrequest.Randomize.extension_order(),
            verify=False,
        )
        assert "Client" in repr(client)

    def test_blocking_client_accepts_randomize(self):
        client = BlockingClient(
            tls_profile="chrome_146",
            randomize=lkrequest.Randomize.off(),
            verify=False,
        )
        assert "BlockingClient" in repr(client)

    def test_session_from_randomized_client_builds(self):
        # The policy is applied at the client level; session() must still build.
        client = lkrequest.Client(
            tls_profile="chrome_146",
            randomize=lkrequest.Randomize.extension_order(),
            verify=False,
        )
        assert client.session() is not None

    def test_synthetic_tiers_absent_without_feature(self):
        # recombine/full + Layers + NegotiabilityFloor require synthetic-fp.
        if hasattr(lkrequest, "Layers"):
            pytest.skip("built with the synthetic-fp feature")
        assert not hasattr(lkrequest.Randomize, "recombine")
        assert not hasattr(lkrequest, "NegotiabilityFloor")


@pytest.mark.skipif(
    not hasattr(lkrequest, "Layers"),
    reason="synthetic fingerprint tiers require the synthetic-fp build feature",
)
class TestSyntheticFingerprint:
    """Tier 3a/3b synthesis (Randomize.recombine/full + the Layers mask) — only
    present with `maturin develop --features synthetic-fp`."""

    def test_layers_constants(self):
        assert lkrequest.Layers.TLS is not None
        assert lkrequest.Layers.H2 is not None
        assert lkrequest.Layers.QUIC is not None
        assert lkrequest.Layers.all() is not None

    def test_layers_or_composition(self):
        combined = lkrequest.Layers.TLS | lkrequest.Layers.H2
        rendered = repr(combined)
        assert "TLS" in rendered and "H2" in rendered

    def test_layers_equality(self):
        assert lkrequest.Layers.TLS == lkrequest.Layers.TLS
        assert (lkrequest.Layers.TLS == lkrequest.Layers.H2) is False

    @pytest.mark.parametrize("ctor", ["recombine", "full"])
    def test_whole_identity_constructors(self, ctor):
        assert getattr(lkrequest.Randomize, ctor)() is not None

    @pytest.mark.parametrize("ctor", ["recombine_layers", "full_layers"])
    def test_layered_constructors(self, ctor):
        policy = getattr(lkrequest.Randomize, ctor)(
            lkrequest.Layers.TLS | lkrequest.Layers.H2
        )
        # repr is "Randomize.recombine_layers(...)" / "Randomize.full_layers(...)"
        assert ctor.split("_")[0] in repr(policy)

    def test_recombine_client_and_sessions_build(self):
        # A synthetic client materializes a fresh identity per session; both
        # sessions must build without error.
        client = lkrequest.Client(
            tls_profile="chrome_146",
            randomize=lkrequest.Randomize.recombine(),
            verify=False,
        )
        assert client.session() is not None
        assert client.session() is not None

    def test_blocking_recombine_layers_client_builds(self):
        client = BlockingClient(
            tls_profile="chrome_146",
            randomize=lkrequest.Randomize.recombine_layers(lkrequest.Layers.TLS),
            verify=False,
        )
        assert "BlockingClient" in repr(client)

    # -- Negotiability floor (sig-alg guarantee for synthetic policies) --------

    def test_negotiability_floor_constants(self):
        assert lkrequest.NegotiabilityFloor.UNIVERSAL is not None
        assert lkrequest.NegotiabilityFloor.PRESET_FAMILY is not None
        assert "UNIVERSAL" in repr(lkrequest.NegotiabilityFloor.UNIVERSAL)
        assert "PRESET_FAMILY" in repr(lkrequest.NegotiabilityFloor.PRESET_FAMILY)

    def test_negotiability_floor_custom(self):
        floor = lkrequest.NegotiabilityFloor.custom([0x0804, 0x0403])
        assert "custom" in repr(floor)

    def test_negotiability_floor_equality(self):
        universal = lkrequest.NegotiabilityFloor.UNIVERSAL
        assert universal == lkrequest.NegotiabilityFloor.UNIVERSAL
        assert (universal == lkrequest.NegotiabilityFloor.PRESET_FAMILY) is False
        assert lkrequest.NegotiabilityFloor.custom([0x0804]) == (
            lkrequest.NegotiabilityFloor.custom([0x0804])
        )

    def test_negotiability_builder_returns_new_policy(self):
        # `negotiability` does not mutate the receiver; it returns a new policy
        # whose repr records the floor.
        policy = lkrequest.Randomize.recombine().negotiability(
            lkrequest.NegotiabilityFloor.PRESET_FAMILY
        )
        assert "negotiability" in repr(policy)
        assert "PRESET_FAMILY" in repr(policy)

    def test_negotiability_client_builds(self):
        client = lkrequest.Client(
            tls_profile="chrome_146",
            randomize=lkrequest.Randomize.recombine().negotiability(
                lkrequest.NegotiabilityFloor.custom([0x0804])
            ),
            verify=False,
        )
        assert client.session() is not None
