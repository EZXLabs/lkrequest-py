"""Tests for features added while tracking the lkrequest core update:

new browser presets (chrome_145 through chrome_154, firefox_156), request
priority, protocol
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
    "chrome_152",
    "chrome_153",
    "chrome_154",
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

    def test_signature_algorithm_grease_starts_at_chrome_152(self):
        # Python mirror of upstream's `chrome_152_is_first_chromium_profile_with_
        # signature_algorithm_grease`. GREASE placement is a fingerprint-visible
        # difference, so a preset silently gaining/losing it must fail here.
        # Chrome 152 introduced it and Chrome 153 and 154 keep it.
        greased = {
            name
            for name in NEW_CHROME_PRESETS + ["chrome_131", "chrome_144"]
            if json.loads(getattr(lkrequest.TlsProfile, name)().to_json())["grease"][
                "signature_algorithms"
            ]
        }
        assert greased == {"chrome_152", "chrome_153", "chrome_154"}

    def test_chrome_152_carries_trust_anchor_ids(self):
        # Python mirror of upstream's `chrome_152_adds_capture_verified_trust_
        # anchor_ids`: Chrome 152 is the first preset to send extension 0xca34,
        # whose payload the binding must expose as a shuffled id list.
        specs = {
            name: [
                e
                for e in json.loads(getattr(lkrequest.TlsProfile, name)().to_json())[
                    "extensions"
                ]
                if e["extension_type"] == lkrequest.ExtType.TRUST_ANCHOR_IDS
            ]
            for name in ("chrome_151", "chrome_152")
        }
        assert specs["chrome_151"] == []
        assert len(specs["chrome_152"]) == 1
        source = specs["chrome_152"][0]["source"]
        assert source["type"] == "trust_anchor_ids"
        assert source["shuffle"] is True
        assert len(source["ids"]) > 1
        # Every id must be a hex string the extension can actually serialize.
        assert all(bytes.fromhex(i) for i in source["ids"])

    def test_chrome_152_h2_is_unchanged_from_chrome_151(self):
        # Upstream ships Chrome 152 with Chrome 151's H2 shape verbatim; if a
        # future capture diverges this must be a deliberate, reviewed change.
        assert (
            lkrequest.H2Profile.chrome_152().to_json()
            == lkrequest.H2Profile.chrome_151().to_json()
        )

    def test_chrome_153_h2_is_unchanged_from_chrome_152(self):
        # The Chrome 153 capture reproduced Chrome 152's SETTINGS order, window
        # update, pseudo-header order and navigation priority.
        assert (
            lkrequest.H2Profile.chrome_153().to_json()
            == lkrequest.H2Profile.chrome_152().to_json()
        )

    def test_chrome_153_narrows_the_trust_anchor_list(self):
        # The only fingerprint-visible TLS difference from Chrome 152: the
        # shuffled 0xca34 identifier set drops from 32 to 28. Named explicitly
        # because a capture that silently regrows the list is a detectable
        # mismatch against real Chrome 153, not a harmless refresh.
        def anchors(name):
            specs = [
                e
                for e in json.loads(getattr(lkrequest.TlsProfile, name)().to_json())[
                    "extensions"
                ]
                if e["extension_type"] == lkrequest.ExtType.TRUST_ANCHOR_IDS
            ]
            assert len(specs) == 1
            return specs[0]["source"]["ids"]

        ids152, ids153 = anchors("chrome_152"), anchors("chrome_153")
        assert (len(ids152), len(ids153)) == (32, 28)
        assert set(ids152) - set(ids153) == {
            "d6790902",
            "d6790903",
            "d6790909",
            "d679090e",
        }
        assert set(ids153) - set(ids152) == set()

        # Everything else about the TLS profile is Chrome 152's, name aside.
        tls152 = json.loads(lkrequest.TlsProfile.chrome_152().to_json())
        tls153 = json.loads(lkrequest.TlsProfile.chrome_153().to_json())
        assert (tls152.pop("name"), tls153.pop("name")) == ("Chrome 152", "Chrome 153")
        assert [k for k in tls152 if tls152[k] != tls153[k]] == ["extensions"]

    def test_chrome_153_quic_tls_drops_grease_and_ml_dsa(self):
        # Chrome 153's QUIC ClientHello differs from its TCP one in two ways that
        # show on the wire: no ordinary TLS GREASE slots at all, and the nine
        # classic signature algorithms without TCP's three ML-DSA codepoints.
        tcp = json.loads(lkrequest.TlsProfile.chrome_153().to_json())
        quic = json.loads(lkrequest.TlsProfile.chrome_153_quic().to_json())
        assert any(tcp["grease"].values())
        assert not any(quic["grease"].values())
        assert {0x0904, 0x0905, 0x0906}.issubset(tcp["signature_algorithms"])
        assert quic["signature_algorithms"] == [
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

    def test_chrome_154_is_chrome_153_under_a_new_name(self):
        # Python mirror of upstream's `chrome_154_matches_capture_verified_
        # chrome_153_tls_shape`: the Chrome 154.0.8037.58 capture reproduced
        # Chrome 153's TCP and QUIC ClientHellos and its H2 shape, so anything
        # beyond the profile name drifting apart is an unreviewed change.
        for prev, cur in (
            ("chrome_153", "chrome_154"),
            ("chrome_153_quic", "chrome_154_quic"),
        ):
            old = json.loads(getattr(lkrequest.TlsProfile, prev)().to_json())
            new = json.loads(getattr(lkrequest.TlsProfile, cur)().to_json())
            assert new.pop("name") == old.pop("name").replace("153", "154")
            assert new == old
        assert (
            lkrequest.H2Profile.chrome_154().to_json()
            == lkrequest.H2Profile.chrome_153().to_json()
        )

    def test_firefox_156_matches_the_public_capture(self):
        # Python mirror of upstream's `firefox_156_matches_public_cloudflare_
        # capture`. Against Firefox 147 exactly four things move: the name, two
        # ECDSA CBC suites (0xc00a / 0xc009) and both FFDHE groups (256 / 257)
        # dropped, and an ECH GREASE switched to AES-128-GCM with a fixed
        # 240-byte payload.
        ff147 = json.loads(lkrequest.TlsProfile.firefox_147().to_json())
        ff156 = json.loads(lkrequest.TlsProfile.firefox_156().to_json())
        assert ff156["name"] == "Firefox 156"
        assert [k for k in ff156 if ff156[k] != ff147[k]] == [
            "name",
            "cipher_suites",
            "supported_groups",
            "ech",
        ]
        assert ff156["cipher_suites"] == [
            4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200,
            49171, 49172, 156, 157, 47, 53,
        ]  # fmt: skip
        assert set(ff147["cipher_suites"]) - set(ff156["cipher_suites"]) == {
            0xC00A,
            0xC009,
        }
        assert ff156["supported_groups"] == [4588, 29, 23, 24, 25]
        assert ff156["key_share_curves"] == [4588, 29, 23]
        assert ff156["signature_algorithms"] == [
            1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513,
        ]  # fmt: skip
        ech = ff156["ech"]
        assert ech["type"] == "grease"
        assert (
            ech["aead_id"] == 1
        )  # AES-128-GCM; Firefox 147 sent 3 (ChaCha20-Poly1305)
        assert (ech["payload_length_min"], ech["payload_length_max"]) == (240, 240)
        # H2 was captured unchanged from Firefox 147.
        assert (
            lkrequest.H2Profile.firefox_156().to_json()
            == lkrequest.H2Profile.firefox_147().to_json()
        )

    def test_firefox_156_claims_no_quic(self):
        # Upstream captured Firefox 156's QUIC Initial but ships the preset
        # TLS/H2-only, because the transport cannot reproduce every observed
        # Firefox QUIC field; the preset turns HTTP/3 off rather than send
        # Chrome's QUIC under Firefox's name. Nothing here may offer one.
        assert not hasattr(lkrequest.TlsProfile, "firefox_156_quic")
        if not hasattr(lkrequest, "QuicProfile"):
            pytest.skip("built without the quic-h3 feature")
        assert not hasattr(lkrequest.QuicProfile, "firefox_156")
        with pytest.raises(ValueError, match="Unknown QUIC profile: 'firefox_156'"):
            lkrequest.Client(quic_profile="firefox_156")

    def test_quic_tls_presets_differ_from_their_tcp_counterparts(self):
        # The QUIC-TLS presets are the ClientHello Chrome sends inside QUIC; they
        # are plain TLS profiles (no quic-h3 feature needed) and must not be
        # confused with the TCP profile of the same version.
        for name in (
            "chrome_146",
            "chrome_150",
            "chrome_151",
            "chrome_152",
            "chrome_153",
            "chrome_154",
        ):
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
            "chrome_152",
            "chrome_153",
            "chrome_154",
            "firefox_133",
            "firefox_147",
            "firefox_156",
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
        for name in (
            "chrome_146",
            "chrome_150",
            "chrome_151",
            "chrome_153",
            "chrome_154",
        ):
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
        # Chrome 154 is Chrome 153's QUIC and H3 verbatim: the Initial flight
        # matched, and the H3 SETTINGS carry over because the public capture
        # path never received a QUIC response (upstream's
        # `chrome_154_matches_public_initial_capture_and_inherits_h3_baseline`).
        assert profiles["chrome_154"] == profiles["chrome_153"]

    def test_chrome_152_quic_drops_google_initial_rtt(self):
        # Unlike Chrome 151 (identical to 150), Chrome 152 is the first preset
        # whose QUIC transport parameters actually differ: it stops sending the
        # obsolete Google-private `initial_rtt` parameter (0x3127 / 12583).
        if not hasattr(lkrequest, "QuicProfile"):
            pytest.skip("built without the quic-h3 feature")
        google_initial_rtt = 0x3127
        params = {
            name: json.loads(getattr(lkrequest.QuicProfile, name)().to_json())[
                "transport_params"
            ]
            for name in ("chrome_151", "chrome_152")
        }
        for name, present in (("chrome_151", True), ("chrome_152", False)):
            ids = {p[0] for p in params[name]["extra_transport_parameters"]}
            assert (google_initial_rtt in ids) is present
            assert (
                google_initial_rtt in params[name]["transport_parameter_order"]
            ) is present

    def test_captured_chromium_presets_generate_grease_per_connection(self):
        # Chromium re-derives its GREASE values for every connection, so a fixed
        # value in the profile would itself be a fingerprint. Three flags say the
        # profile defers to Chromium's generation rules instead: `chromium_grease`
        # for the reserved H3 SETTINGS and control-stream frame,
        # `randomize_grease_shape` for the reserved transport parameters, and
        # `initial_packet_chaos` for the Initial packet layout. They are
        # `#[serde(default)]` and off when absent, which is what keeps a profile
        # loaded from JSON on the old fixed behaviour — so read them with `.get`.
        if not hasattr(lkrequest, "QuicProfile"):
            pytest.skip("built without the quic-h3 feature")
        captured = (
            "chrome_146",
            "chrome_150",
            "chrome_151",
            "chrome_152",
            "chrome_153",
            "chrome_154",
        )
        for name in captured + ("chrome",):
            p = json.loads(getattr(lkrequest.QuicProfile, name)().to_json())
            assert p["h3"].get("chromium_grease") is True, name
            # The generic profile models no specific capture, so only the H3
            # rules apply to it.
            expected = name in captured
            assert (
                p["transport_params"].get("randomize_grease_shape", False) is expected
            ), name
            assert p["packetization"].get("initial_packet_chaos", False) is expected, (
                name
            )

    def test_quic_profile_json_without_the_grease_flags_stays_fixed(self):
        # A `QuicProfile` a caller saved before upstream added the flags, or built
        # by hand, must keep its old behaviour rather than silently start
        # randomizing — that is the point of defaulting them to off.
        if not hasattr(lkrequest, "QuicProfile"):
            pytest.skip("built without the quic-h3 feature")
        p = json.loads(lkrequest.QuicProfile.chrome_153().to_json())
        del p["h3"]["chromium_grease"]
        del p["transport_params"]["randomize_grease_shape"]
        del p["packetization"]["initial_packet_chaos"]
        restored = json.loads(lkrequest.QuicProfile.from_json(json.dumps(p)).to_json())
        # Absent in the output too: they serialize only when set.
        assert "chromium_grease" not in restored["h3"]
        assert "randomize_grease_shape" not in restored["transport_params"]
        assert "initial_packet_chaos" not in restored["packetization"]


# ==========================================================================
# Browser network session policies (upstream `network_partition`)
# ==========================================================================


class TestNetworkSessionPolicies:
    """TLS ticket resumption / cache partitioning / browsing context.

    Construction and client-wiring only — the partition key itself is derived
    inside the Rust core and has no Python-visible surface.
    """

    def test_resumption_policy_variants(self):
        browser_default = lkrequest.TlsSessionResumptionPolicy.BROWSER_DEFAULT
        assert browser_default == lkrequest.TlsSessionResumptionPolicy.BROWSER_DEFAULT
        assert browser_default != lkrequest.TlsSessionResumptionPolicy.DISABLED
        assert lkrequest.TlsSessionResumptionPolicy.enabled(
            2
        ) == lkrequest.TlsSessionResumptionPolicy.enabled(2)
        assert lkrequest.TlsSessionResumptionPolicy.enabled(
            2
        ) != lkrequest.TlsSessionResumptionPolicy.enabled(3)

    def test_resumption_policy_rejects_zero_tickets(self):
        # Upstream asserts on zero inside ClientBuilder, which would surface as a
        # panic; the binding must reject it up front with a clean ValueError.
        with pytest.raises(ValueError, match="greater than zero"):
            lkrequest.TlsSessionResumptionPolicy.enabled(0)

    def test_client_reports_its_resumption_policy(self):
        assert (
            lkrequest.Client().tls_session_resumption_policy
            == lkrequest.TlsSessionResumptionPolicy.BROWSER_DEFAULT
        )
        client = lkrequest.Client(
            tls_session_resumption_policy=lkrequest.TlsSessionResumptionPolicy.enabled(
                5
            )
        )
        assert (
            client.tls_session_resumption_policy
            == lkrequest.TlsSessionResumptionPolicy.enabled(5)
        )

    @pytest.mark.parametrize(
        "name",
        [
            "UNPARTITIONED",
            "TOP_LEVEL_SITE",
            "TOP_LEVEL_AND_FRAME_SITE",
            "CHROMIUM",
            "FIREFOX",
        ],
    )
    def test_partition_policy_accepted_by_client(self, name):
        policy = getattr(lkrequest.TlsSessionCachePartitionPolicy, name)
        assert name in repr(policy)
        assert "Client" in repr(
            lkrequest.Client(tls_session_cache_partition_policy=policy)
        )

    def test_partition_context_builders_do_not_mutate(self):
        base = lkrequest.NetworkPartitionContext(
            "https://top.example", "https://frame.example"
        )
        with_nonce = base.nonce("n1")
        with_both = with_nonce.browser_context("ctx")
        assert base != with_nonce
        assert with_nonce != with_both
        assert base == lkrequest.NetworkPartitionContext(
            "https://top.example", "https://frame.example"
        )

    def test_session_accepts_partition_context(self):
        context = lkrequest.NetworkPartitionContext(
            "https://top.example", "https://frame.example"
        ).browser_context("ctx")
        session = lkrequest.Client.chrome_152().session(
            network_partition_context=context
        )
        assert "Session" in repr(session)

    def test_require_close_notify_defaults_off_and_is_settable(self):
        assert lkrequest.Client().require_close_notify is False
        assert lkrequest.Client(require_close_notify=True).require_close_notify is True


class TestH2DataFramePolicy:
    def test_variants_and_equality(self):
        assert (
            lkrequest.H2DataFramePolicy.BROWSER_DEFAULT
            != lkrequest.H2DataFramePolicy.PEER_MAX_FRAME_SIZE
        )
        assert lkrequest.H2DataFramePolicy.fixed_payload(
            1024
        ) == lkrequest.H2DataFramePolicy.fixed_payload(1024)
        assert lkrequest.H2DataFramePolicy.socket_write_aligned(
            4096
        ) != lkrequest.H2DataFramePolicy.fixed_payload(4096)

    @pytest.mark.parametrize(
        ("factory", "bad_value", "message"),
        [
            ("fixed_payload", 0, "greater than zero"),
            ("socket_write_aligned", 9, "9-byte"),
        ],
    )
    def test_rejects_values_upstream_would_panic_on(self, factory, bad_value, message):
        with pytest.raises(ValueError, match=message):
            getattr(lkrequest.H2DataFramePolicy, factory)(bad_value)

    def test_accepted_by_client(self):
        for policy in (
            lkrequest.H2DataFramePolicy.BROWSER_DEFAULT,
            lkrequest.H2DataFramePolicy.PEER_MAX_FRAME_SIZE,
            lkrequest.H2DataFramePolicy.fixed_payload(8192),
            lkrequest.H2DataFramePolicy.socket_write_aligned(16384),
        ):
            assert "Client" in repr(lkrequest.Client(h2_data_frame_policy=policy))


class TestTrustAnchorIdsExtensionSpec:
    def test_round_trips_ids_and_shuffle(self):
        spec = lkrequest.ExtensionSpec(
            lkrequest.ExtType.TRUST_ANCHOR_IDS,
            source="trust_anchor_ids",
            trust_anchor_ids=["aabb", "ccdd"],
            shuffle=True,
        )
        assert spec.extension_type == lkrequest.ExtType.TRUST_ANCHOR_IDS
        assert spec.source == "trust_anchor_ids"
        assert spec.trust_anchor_ids == ["aabb", "ccdd"]
        assert spec.shuffle is True

    def test_ids_are_required_for_that_source(self):
        with pytest.raises(ValueError, match="trust_anchor_ids"):
            lkrequest.ExtensionSpec(
                lkrequest.ExtType.TRUST_ANCHOR_IDS, source="trust_anchor_ids"
            )

    def test_other_sources_report_none(self):
        spec = lkrequest.ExtensionSpec(lkrequest.ExtType.SNI)
        assert spec.source == "auto"
        assert spec.trust_anchor_ids is None
        assert spec.shuffle is None


# ==========================================================================
# Cookie-jar regressions carried over from the upstream RFC-compliance batch
# ==========================================================================


class TestCookiePrefixesAndSecureChannel:
    """`__Secure-` / `__Host-` prefixes and Secure-over-plaintext rejection.

    Exercised through `set_cookie_raw`, which feeds the same jar path a real
    `Set-Cookie` header takes, so these need no server.
    """

    @staticmethod
    def _jar(url, headers):
        session = lkrequest.Client.chrome_152().session()
        for header in headers:
            session.set_cookie_raw(url, header)
        return dict(session.get_cookies(url))

    @pytest.mark.parametrize(
        ("header", "accepted"),
        [
            ("__Secure-ok=1; Secure", True),
            ("__Secure-bad=1", False),  # prefix requires the Secure attribute
            ("__Host-ok=1; Secure; Path=/", True),
            ("__Host-nosecure=1; Path=/", False),
            ("__Host-domain=1; Secure; Path=/; Domain=example.com", False),
            ("__Host-subpath=1; Secure; Path=/sub", False),
        ],
    )
    def test_cookie_name_prefixes_are_enforced(self, header, accepted):
        name = header.split("=", 1)[0]
        jar = self._jar("https://example.com/", ["control=1", header])
        assert jar.get("control") == "1", "control cookie must always be stored"
        assert (name in jar) is accepted

    def test_secure_cookie_is_ignored_over_plaintext(self):
        jar = self._jar(
            "http://example.com/", ["plain=1", "secure-over-http=1; Secure"]
        )
        assert jar == {"plain": "1"}

    def test_secure_cookie_from_https_is_not_sent_over_http(self):
        session = lkrequest.Client.chrome_152().session()
        session.set_cookie_raw("https://example.com/", "s=1; Secure")
        session.set_cookie_raw("https://example.com/", "p=1")
        assert dict(session.get_cookies("https://example.com/")) == {"s": "1", "p": "1"}
        assert dict(session.get_cookies("http://example.com/")) == {"p": "1"}


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
