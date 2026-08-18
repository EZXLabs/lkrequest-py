"""Advanced tests covering all remaining lkrequest features."""

import json
import pytest
import lkrequest
from lkrequest.blocking import Client as BlockingClient

# Redirected to the local hypercorn httpbin server by the autouse fixture below,
# so requests in this module never depend on the public httpbin.org.
BASE = "https://httpbin.org"


@pytest.fixture(autouse=True)
def _redirect_to_local_server(server_url):
    global BASE
    BASE = server_url
    yield


# ==========================================================================
# Fingerprint Configuration Types (v0.6.0)
# ==========================================================================


class TestExtType:
    def test_extension_type_constants(self):
        assert lkrequest.ExtType.SNI is not None
        assert lkrequest.ExtType.ALPN is not None
        assert lkrequest.ExtType.SUPPORTED_GROUPS is not None
        assert lkrequest.ExtType.SIGNATURE_ALGORITHMS is not None
        assert lkrequest.ExtType.KEY_SHARE is not None
        assert lkrequest.ExtType.SUPPORTED_VERSIONS is not None
        assert lkrequest.ExtType.PSK_KEY_EXCHANGE_MODES is not None
        assert lkrequest.ExtType.SESSION_TICKET is not None
        assert lkrequest.ExtType.EC_POINT_FORMATS is not None
        assert lkrequest.ExtType.ENCRYPT_THEN_MAC is not None
        assert lkrequest.ExtType.EXTENDED_MASTER_SECRET is not None
        assert lkrequest.ExtType.STATUS_REQUEST is not None
        assert lkrequest.ExtType.SIGNED_CERTIFICATE_TIMESTAMP is not None
        assert lkrequest.ExtType.COMPRESS_CERTIFICATE is not None
        assert lkrequest.ExtType.APPLICATION_SETTINGS is not None
        assert lkrequest.ExtType.APPLICATION_SETTINGS_NEW is not None
        assert lkrequest.ExtType.RENEGOTIATION_INFO is not None
        assert lkrequest.ExtType.DELEGATED_CREDENTIALS is not None
        assert lkrequest.ExtType.RECORD_SIZE_LIMIT is not None
        assert lkrequest.ExtType.PADDING is not None
        assert lkrequest.ExtType.ENCRYPTED_CLIENT_HELLO is not None

    def test_extension_types_are_integers(self):
        assert isinstance(lkrequest.ExtType.SNI, int)
        assert isinstance(lkrequest.ExtType.ALPN, int)
        assert isinstance(lkrequest.ExtType.KEY_SHARE, int)


class TestExtensionSpec:
    def test_basic_creation(self):
        spec = lkrequest.ExtensionSpec(lkrequest.ExtType.SNI)
        assert spec.extension_type == lkrequest.ExtType.SNI
        assert spec.source == "auto"

    def test_with_source(self):
        spec = lkrequest.ExtensionSpec(lkrequest.ExtType.ALPN, source="auto")
        assert spec.source == "auto"

    def test_with_raw_data(self):
        spec = lkrequest.ExtensionSpec(
            lkrequest.ExtType.SESSION_TICKET,
            source="raw_bytes",
            raw_data="0000",
        )
        assert spec.extension_type == lkrequest.ExtType.SESSION_TICKET


class TestGreaseConfig:
    def test_default(self):
        gc = lkrequest.GreaseConfig()
        assert gc is not None

    def test_all_enabled(self):
        gc = lkrequest.GreaseConfig(
            cipher_suite=True,
            extensions=True,
            supported_groups=True,
            supported_versions=True,
            signature_algorithms=True,
            key_share=True,
        )
        assert gc is not None

    def test_partial(self):
        gc = lkrequest.GreaseConfig(extensions=True, key_share=True)
        assert gc is not None


class TestPaddingStrategy:
    def test_block_align(self):
        ps = lkrequest.PaddingStrategy.block_align(128, 512)
        assert ps is not None

    def test_fixed_target(self):
        ps = lkrequest.PaddingStrategy.fixed_target(517)
        assert ps is not None

    def test_no_padding(self):
        ps = lkrequest.PaddingStrategy.no_padding()
        assert ps is not None


class TestRandomizationConfig:
    def test_default(self):
        rc = lkrequest.RandomizationConfig()
        assert rc is not None

    def test_with_shuffle(self):
        rc = lkrequest.RandomizationConfig(shuffle_extensions=True)
        assert rc is not None


class TestTlsProfile:
    def test_preset_chrome_131(self):
        p = lkrequest.TlsProfile.chrome_131()
        assert p.name is not None
        assert len(p.cipher_suites) > 0
        assert len(p.supported_groups) > 0
        assert len(p.signature_algorithms) > 0
        assert len(p.alpn_protocols) > 0

    def test_preset_chrome_144(self):
        p = lkrequest.TlsProfile.chrome_144()
        assert p.name is not None

    def test_preset_firefox_133(self):
        p = lkrequest.TlsProfile.firefox_133()
        assert p.name is not None

    def test_preset_firefox_147(self):
        p = lkrequest.TlsProfile.firefox_147()
        assert p.name is not None

    def test_preset_safari_18(self):
        p = lkrequest.TlsProfile.safari_18()
        assert p.name is not None

    def test_preset_safari_26(self):
        p = lkrequest.TlsProfile.safari_26()
        assert p.name is not None

    def test_to_json_and_back(self):
        original = lkrequest.TlsProfile.chrome_144()
        json_str = original.to_json()
        assert len(json_str) > 0
        restored = lkrequest.TlsProfile.from_json(json_str)
        assert restored.name == original.name
        assert restored.cipher_suites == original.cipher_suites

    def test_to_dict(self):
        p = lkrequest.TlsProfile.chrome_144()
        d = p.to_dict()
        assert isinstance(d, dict)
        assert "name" in d

    def test_custom_tls_profile(self):
        profile = lkrequest.TlsProfile(
            "my_custom",
            cipher_suites=[0x1301, 0x1302, 0x1303],
            alpn_protocols=["h2", "http/1.1"],
            grease=lkrequest.GreaseConfig(extensions=True),
            padding=lkrequest.PaddingStrategy.block_align(128, 512),
        )
        assert profile.name == "my_custom"
        assert 0x1301 in profile.cipher_suites

    def test_custom_with_extensions(self):
        extensions = [
            lkrequest.ExtensionSpec(lkrequest.ExtType.SNI),
            lkrequest.ExtensionSpec(lkrequest.ExtType.ALPN),
            lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_GROUPS),
            lkrequest.ExtensionSpec(lkrequest.ExtType.KEY_SHARE),
            lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_VERSIONS),
            lkrequest.ExtensionSpec(lkrequest.ExtType.SIGNATURE_ALGORITHMS),
        ]
        profile = lkrequest.TlsProfile(
            "with_ext",
            extensions=extensions,
            cipher_suites=[0x1301, 0x1302],
            alpn_protocols=["h2", "http/1.1"],
        )
        assert profile.name == "with_ext"

    def test_use_tls_profile_object_in_client(self):
        profile = lkrequest.TlsProfile.chrome_144()
        client = lkrequest.Client(tls_profile=profile)
        assert "Client" in repr(client)


class TestH2Setting:
    def test_creation_with_string_id(self):
        s = lkrequest.H2Setting("header_table_size", 65536)
        assert s.value == 65536

    def test_creation_with_int_id(self):
        s = lkrequest.H2Setting(1, 65536)
        assert s.value == 65536


class TestHeadersPriority:
    def test_creation(self):
        hp = lkrequest.HeadersPriority(0, 255, True)
        assert hp is not None


class TestPriorityFrame:
    def test_creation(self):
        pf = lkrequest.PriorityFrame(3, 0, 201, False)
        assert pf is not None


class TestH2Profile:
    def test_preset_chrome_144(self):
        p = lkrequest.H2Profile.chrome_144()
        assert p is not None

    def test_preset_firefox_147(self):
        p = lkrequest.H2Profile.firefox_147()
        assert p is not None

    def test_preset_safari_26(self):
        p = lkrequest.H2Profile.safari_26()
        assert p is not None

    def test_to_json_and_back(self):
        original = lkrequest.H2Profile.chrome_144()
        json_str = original.to_json()
        assert len(json_str) > 0
        restored = lkrequest.H2Profile.from_json(json_str)
        assert restored is not None

    def test_to_dict(self):
        p = lkrequest.H2Profile.chrome_144()
        d = p.to_dict()
        assert isinstance(d, dict)

    def test_custom_h2_profile(self):
        settings = [
            lkrequest.H2Setting("header_table_size", 65536),
            lkrequest.H2Setting("max_concurrent_streams", 1000),
            lkrequest.H2Setting("initial_window_size", 6291456),
            lkrequest.H2Setting("max_header_list_size", 262144),
        ]
        priority = lkrequest.HeadersPriority(0, 255, True)
        profile = lkrequest.H2Profile(
            settings,
            15663105,
            ["method", "authority", "scheme", "path"],
            headers_priority=priority,
        )
        assert profile is not None

    def test_custom_with_priority_frames(self):
        settings = [lkrequest.H2Setting("header_table_size", 65536)]
        frames = [
            lkrequest.PriorityFrame(3, 0, 201, False),
            lkrequest.PriorityFrame(5, 0, 101, False),
        ]
        profile = lkrequest.H2Profile(
            settings,
            15663105,
            ["method", "authority", "scheme", "path"],
            priority_frames=frames,
        )
        assert profile is not None

    def test_custom_with_priority_config(self):
        settings = [lkrequest.H2Setting("header_table_size", 65536)]
        order = ["method", "authority", "scheme", "path"]
        profile = lkrequest.H2Profile(
            settings, 15663105, order, priority_config=lkrequest.PriorityConfig.chrome()
        )
        assert profile.priority_config.auto_priority_header is True
        assert profile.priority_config.stream_dep_policy == "chain"
        # Omitting priority_config yields the neutral default (the #7 fix lets
        # callers opt into browser-accurate priority that was previously fixed).
        default_profile = lkrequest.H2Profile(settings, 15663105, order)
        assert default_profile.priority_config.auto_priority_header is False
        assert default_profile.priority_config.urgency_weights is None

    def test_use_h2_profile_object_in_client(self):
        profile = lkrequest.H2Profile.chrome_144()
        client = lkrequest.Client(h2_profile=profile)
        assert "Client" in repr(client)


class TestPriorityConfig:
    def test_chrome_preset(self):
        pc = lkrequest.PriorityConfig.chrome()
        assert pc.auto_priority_header is True
        assert pc.exclusive is True
        assert pc.urgency_weights == [255, 219, 146, 110, 73, 36, 0, 0]
        assert pc.stream_dep_policy == "chain"

    def test_default_and_firefox(self):
        assert lkrequest.PriorityConfig.default_config().auto_priority_header is False
        assert lkrequest.PriorityConfig.default_config().urgency_weights is None
        assert lkrequest.PriorityConfig.firefox().auto_priority_header is True
        assert lkrequest.PriorityConfig.firefox().urgency_weights is None

    def test_custom(self):
        pc = lkrequest.PriorityConfig(
            urgency_weights=[1, 2, 3, 4, 5, 6, 7, 8],
            exclusive=True,
            stream_dep_policy="chain",
            auto_priority_header=True,
            default_urgency=1,
            default_incremental=True,
        )
        assert pc.urgency_weights == [1, 2, 3, 4, 5, 6, 7, 8]
        assert pc.stream_dep_policy == "chain"
        assert pc.default_urgency == 1
        assert pc.default_incremental is True

    def test_invalid_urgency_weights_length(self):
        with pytest.raises(ValueError):
            lkrequest.PriorityConfig(urgency_weights=[1, 2, 3])

    def test_invalid_stream_dep_policy(self):
        with pytest.raises(ValueError):
            lkrequest.PriorityConfig(stream_dep_policy="bogus")


class TestTcpFingerprint:
    def test_preset_chrome(self):
        tcp = lkrequest.TcpFingerprint.chrome()
        assert tcp is not None

    def test_preset_chrome_win(self):
        tcp = lkrequest.TcpFingerprint.chrome_win()
        assert tcp is not None

    def test_preset_chrome_linux(self):
        tcp = lkrequest.TcpFingerprint.chrome_linux()
        assert tcp is not None

    def test_preset_chrome_macos(self):
        tcp = lkrequest.TcpFingerprint.chrome_macos()
        assert tcp is not None

    def test_preset_firefox(self):
        tcp = lkrequest.TcpFingerprint.firefox()
        assert tcp is not None

    def test_preset_firefox_win(self):
        tcp = lkrequest.TcpFingerprint.firefox_win()
        assert tcp is not None

    def test_preset_firefox_linux(self):
        tcp = lkrequest.TcpFingerprint.firefox_linux()
        assert tcp is not None

    def test_preset_firefox_macos(self):
        tcp = lkrequest.TcpFingerprint.firefox_macos()
        assert tcp is not None

    def test_preset_safari(self):
        tcp = lkrequest.TcpFingerprint.safari()
        assert tcp is not None

    def test_custom_tcp_fingerprint(self):
        tcp = lkrequest.TcpFingerprint(
            window_size=65535,
            mss=1460,
            window_scale=8,
            ttl=128,
            tcp_nodelay=True,
        )
        assert tcp is not None

    def test_use_tcp_fingerprint_object_in_client(self):
        tcp = lkrequest.TcpFingerprint.chrome_win()
        client = lkrequest.Client(tcp_fingerprint=tcp)
        assert "Client" in repr(client)

    def test_full_custom_client(self):
        tls = lkrequest.TlsProfile.chrome_144()
        h2 = lkrequest.H2Profile.chrome_144()
        tcp = lkrequest.TcpFingerprint.chrome_win()
        client = lkrequest.Client(
            tls_profile=tls,
            h2_profile=h2,
            tcp_fingerprint=tcp,
        )
        assert "Client" in repr(client)


# ==========================================================================
# ClientPool
# ==========================================================================


class TestClientPool:
    def test_creation(self):
        clients = [
            lkrequest.Client(
                tls_profile="chrome_144", h2_profile="chrome_144", verify=False
            ),
            lkrequest.Client.firefox_147(),
            lkrequest.Client.safari_26(),
        ]
        pool = lkrequest.ClientPool(clients)
        assert len(pool) == 3

    def test_round_robin(self):
        clients = [
            lkrequest.Client(
                tls_profile="chrome_144", h2_profile="chrome_144", verify=False
            ),
            lkrequest.Client.firefox_147(),
        ]
        pool = lkrequest.ClientPool(clients, rotation="round_robin")
        c1 = pool.acquire()
        c2 = pool.acquire()
        assert c1 is not None
        assert c2 is not None

    def test_add_client(self):
        clients = [
            lkrequest.Client(
                tls_profile="chrome_144", h2_profile="chrome_144", verify=False
            )
        ]
        pool = lkrequest.ClientPool(clients)
        assert len(pool) == 1
        pool.add(lkrequest.Client.firefox_147())
        assert len(pool) == 2

    def test_random_rotation(self):
        clients = [
            lkrequest.Client(
                tls_profile="chrome_144", h2_profile="chrome_144", verify=False
            ),
            lkrequest.Client.firefox_147(),
        ]
        pool = lkrequest.ClientPool(clients, rotation="random")
        c = pool.acquire()
        assert c is not None


# ==========================================================================
# Fingerprint Info & Randomize
# ==========================================================================


class TestFingerprintInfo:
    def test_fingerprint_info(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        info = client.fingerprint_info()
        assert isinstance(info, dict)

    def test_blocking_fingerprint_info(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        info = client.fingerprint_info()
        assert isinstance(info, dict)

    def test_randomize_fingerprint(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        randomized = client.randomize_fingerprint(shuffle_extensions=True)
        assert "Client" in repr(randomized)

    def test_blocking_randomize_fingerprint(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        randomized = client.randomize_fingerprint(shuffle_extensions=True)
        assert "BlockingClient" in repr(randomized)


# ==========================================================================
# Validate Fingerprint Consistency
# ==========================================================================


class TestValidateFingerprint:
    def test_valid_chrome(self):
        result = lkrequest.validate_fingerprint_consistency(
            tls_profile="chrome_144",
            h2_profile="chrome_144",
            tcp_fingerprint="chrome_win",
        )
        assert isinstance(result, dict)
        assert "valid" in result

    def test_mixed_fingerprints(self):
        result = lkrequest.validate_fingerprint_consistency(
            tls_profile="chrome_144",
            h2_profile="firefox_147",
        )
        assert isinstance(result, dict)

    def test_partial_validation(self):
        result = lkrequest.validate_fingerprint_consistency(
            tls_profile="chrome_144",
        )
        assert isinstance(result, dict)


# ==========================================================================
# Advanced Cookie Management
# ==========================================================================


class TestAdvancedCookies:
    @pytest.fixture
    def session(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        return client.session()

    def test_set_and_get_cookie(self, session):
        session.set_cookie("https://example.com", "name", "value")
        val = session.get_cookie("https://example.com", "name")
        assert val == "value"

    def test_get_cookies_list(self, session):
        session.set_cookie("https://example.com", "a", "1")
        session.set_cookie("https://example.com", "b", "2")
        cookies = session.get_cookies("https://example.com")
        assert isinstance(cookies, list)
        assert len(cookies) >= 2

    def test_cookie_header(self, session):
        session.set_cookie("https://example.com", "token", "abc")
        header = session.cookie_header("https://example.com")
        assert header is not None
        assert "token=abc" in header

    def test_remove_cookie(self, session):
        session.set_cookie("https://example.com", "temp", "val")
        assert session.get_cookie("https://example.com", "temp") == "val"
        session.remove_cookie("https://example.com", "temp")
        assert session.get_cookie("https://example.com", "temp") is None

    def test_clear_cookies(self, session):
        session.set_cookie("https://example.com", "a", "1")
        session.set_cookie("https://example.com", "b", "2")
        session.clear_cookies()
        assert session.get_cookie("https://example.com", "a") is None
        assert session.get_cookie("https://example.com", "b") is None

    def test_set_cookie_with_attrs(self, session):
        session.set_cookie_with_attrs(
            "https://example.com",
            "secure_cookie",
            "secret",
            path="/api",
            domain="example.com",
            secure=True,
            http_only=True,
        )
        val = session.get_cookie("https://example.com/api", "secure_cookie")
        assert val is not None

    def test_cookie_override_in_request(self, session):
        session.set_cookie(f"{BASE}", "original", "old_value")
        resp = session.get(
            f"{BASE}/cookies",
            cookie_override={"original": "new_value"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cookies"]["original"] == "new_value"


# ==========================================================================
# Advanced HTTP Methods
# ==========================================================================


class TestHTTPMethods:
    @pytest.fixture
    def session(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        return client.session()

    def test_put(self, session):
        resp = session.put(
            f"{BASE}/put",
            json={"key": "value"},
        )
        assert resp.status_code == 200
        assert resp.json()["json"]["key"] == "value"

    def test_delete(self, session):
        resp = session.delete(f"{BASE}/delete")
        assert resp.status_code == 200

    def test_head(self, session):
        resp = session.head(f"{BASE}/get")
        assert resp.status_code == 200
        assert len(resp.content) == 0

    def test_patch(self, session):
        resp = session.patch(
            f"{BASE}/patch",
            json={"patched": True},
        )
        assert resp.status_code == 200
        assert resp.json()["json"]["patched"] is True

    def test_options(self, session):
        resp = session.options(f"{BASE}/get")
        assert resp.status_code == 200

    def test_post_raw_body(self, session):
        resp = session.post(
            f"{BASE}/post",
            body=b"raw binary data",
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 200


class TestAsyncHTTPMethods:
    @pytest.fixture
    def session(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        return client.session()

    @pytest.mark.asyncio
    async def test_async_put(self, session):
        resp = await session.put(f"{BASE}/put", json={"key": "value"})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_delete(self, session):
        resp = await session.delete(f"{BASE}/delete")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_head(self, session):
        resp = await session.head(f"{BASE}/get")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_patch(self, session):
        resp = await session.patch(f"{BASE}/patch", json={"patched": True})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_options(self, session):
        resp = await session.options(f"{BASE}/get")
        assert resp.status_code == 200


# ==========================================================================
# Response Details
# ==========================================================================


class TestResponseDetails:
    @pytest.fixture
    def session(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        return client.session()

    def test_response_version(self, session):
        resp = session.get(f"{BASE}/get")
        assert resp.version in (
            lkrequest.HttpVersion.HTTP11,
            lkrequest.HttpVersion.H2,
        )

    def test_response_url(self, session):
        resp = session.get(f"{BASE}/get")
        assert resp.url.startswith(BASE)

    def test_response_content_length(self, session):
        resp = session.get(f"{BASE}/get")
        cl = resp.content_length
        assert cl is None or cl >= 0

    def test_response_headers_list(self, session):
        resp = session.get(f"{BASE}/get")
        hl = resp.headers_list
        assert isinstance(hl, list)
        assert len(hl) > 0
        assert isinstance(hl[0], tuple)
        assert len(hl[0]) == 2

    def test_response_cookies_property(self, session):
        resp = session.get(
            f"{BASE}/cookies/set?test_key=test_val",
        )
        cookies = resp.cookies
        assert isinstance(cookies, dict)

    def test_response_was_redirected(self, session):
        resp = session.get(f"{BASE}/redirect/1")
        assert resp.was_redirected is True

        resp2 = session.get(f"{BASE}/get")
        assert resp2.was_redirected is False

    def test_allow_redirects_false_returns_3xx(self):
        # With redirects disabled the 3xx response is returned as-is instead of
        # being followed (the allow_redirects=False / RedirectPolicy::None path).
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(allow_redirects=False)
        resp = session.get(f"{BASE}/redirect/1")
        assert 300 <= resp.status_code < 400
        assert resp.was_redirected is False
        assert resp.headers.get("location")

    def test_allow_redirects_false_takes_precedence_over_max_redirects(self):
        # allow_redirects=False wins over max_redirects and must NOT raise
        # TooManyRedirectsError the way max_redirects=0 (Follow(0)) would.
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(allow_redirects=False, max_redirects=5)
        resp = session.get(f"{BASE}/redirect/5")
        assert 300 <= resp.status_code < 400
        assert resp.was_redirected is False

    def test_response_bool(self, session):
        resp = session.get(f"{BASE}/get")
        assert bool(resp) is True

        resp_err = session.get(f"{BASE}/status/500")
        assert bool(resp_err) is False

    def test_response_len(self, session):
        resp = session.get(f"{BASE}/get")
        assert len(resp) > 0

    def test_memoryview_access(self, session):
        resp = session.get(f"{BASE}/get")
        try:
            mv = memoryview(resp)
        except TypeError:
            # abi3 wheels omit the raw buffer protocol (limited Python ABI
            # does not expose Py_buffer); resp.content still works.
            pytest.skip("buffer protocol unavailable in abi3 build")
        assert len(mv) > 0
        assert bytes(mv[:4]) in resp.content

    def test_text_caching(self, session):
        resp = session.get(f"{BASE}/html")
        t1 = resp.text()
        t2 = resp.text()
        assert t1 == t2

    def test_json_caching(self, session):
        resp = session.get(f"{BASE}/get")
        j1 = resp.json()
        j2 = resp.json()
        assert j1 == j2


# ==========================================================================
# HeaderMap Advanced
# ==========================================================================


class TestHeaderMapAdvanced:
    @pytest.fixture
    def headers(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/get")
        return resp.headers

    def test_to_dict(self, headers):
        d = headers.to_dict()
        assert isinstance(d, dict)
        assert "content-type" in d or "Content-Type" in d

    def test_get_all(self, headers):
        values = headers.get_all("content-type")
        assert isinstance(values, list)
        assert len(values) >= 1

    def test_iteration(self, headers):
        keys = list(headers)
        assert len(keys) > 0
        assert all(isinstance(k, str) for k in keys)

    def test_items(self, headers):
        items = headers.items()
        assert len(items) > 0
        for k, v in items:
            assert isinstance(k, str)
            assert isinstance(v, str)


# ==========================================================================
# Multipart Advanced
# ==========================================================================


class TestMultipartAdvanced:
    def test_multipart_file(self):
        mp = lkrequest.Multipart()
        mp.text("field1", "value1")
        mp.file("upload", "test.txt", "text/plain", b"file content here")
        assert repr(mp) == "<Multipart>"

    def test_multipart_multiple_files(self):
        mp = lkrequest.Multipart()
        mp.file("file1", "a.txt", "text/plain", b"aaa")
        mp.file("file2", "b.png", "image/png", b"\x89PNG...")
        mp.text("description", "two files")
        assert repr(mp) == "<Multipart>"

    def test_part_class(self):
        part = lkrequest.Part("data", b"binary content")
        part.filename("report.pdf")
        part.content_type("application/pdf")
        assert part is not None

    def test_multipart_upload(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        mp = lkrequest.Multipart()
        mp.text("name", "test_file")
        mp.file("file", "hello.txt", "text/plain", b"Hello, World!")
        resp = session.post(f"{BASE}/post", multipart=mp)
        assert resp.status_code == 200
        data = resp.json()
        assert "file" in data.get("files", {})
        assert data["form"]["name"] == "test_file"


# ==========================================================================
# Timeout on Request Level
# ==========================================================================


class TestRequestTimeout:
    def test_request_with_timeout(self):
        client = BlockingClient(
            tls_profile="chrome_144", total_timeout=30.0, verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/get", timeout=30.0)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_request_with_timeout(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = await session.get(f"{BASE}/get", timeout=30.0)
        assert resp.status_code == 200


# ==========================================================================
# Header / Cookie Order at Session and Request Levels
# ==========================================================================


class TestHeaderCookieOrderLevels:
    """``header_order`` / ``cookie_order`` are settable at the client (covered in
    TestClientConfiguration), session, and per-request levels, each overriding the
    one above it. These exercise the session- and request-level plumbing end to
    end; the wire order itself is a core-library concern verified upstream."""

    ORDER = ["host", "user-agent", "accept", "accept-encoding", "cookie"]
    COOKIE_ORDER = ["session_id", "csrf_token"]

    def test_session_level_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session(
            header_order=self.ORDER, cookie_order=self.COOKIE_ORDER
        )
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_session_level_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(
            header_order=self.ORDER, cookie_order=self.COOKIE_ORDER
        )
        resp = await session.get(f"{BASE}/get")
        assert resp.status_code == 200

    def test_request_level_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        resp = session.get(
            f"{BASE}/get", header_order=self.ORDER, cookie_order=self.COOKIE_ORDER
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_request_level_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = await session.post(
            f"{BASE}/post",
            json={"k": "v"},
            header_order=self.ORDER,
            cookie_order=self.COOKIE_ORDER,
        )
        assert resp.status_code == 200


# ==========================================================================
# Ordered / Repeated headers, params, and form data
# ==========================================================================


class TestOrderedAndRepeatedFields:
    """``headers`` / ``params`` / ``data`` accept a dict (insertion order kept)
    or a ``list[tuple[str, str]]`` (order + duplicate keys). The local httpbin
    echoes repeated query/form keys back as JSON arrays in received order, which
    proves both duplicates and ordering survive the wire."""

    def test_repeated_query_params_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        resp = session.get(f"{BASE}/get", params=[("tag", "a"), ("tag", "b")])
        assert resp.status_code == 200
        assert resp.json()["args"]["tag"] == ["a", "b"]

    def test_repeated_form_fields_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        resp = session.post(f"{BASE}/post", data=[("k", "1"), ("k", "2")])
        assert resp.status_code == 200
        assert resp.json()["form"]["k"] == ["1", "2"]

    def test_list_tuple_headers_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        resp = session.get(f"{BASE}/headers", headers=[("X-A", "1"), ("X-B", "2")])
        assert resp.status_code == 200
        echoed = {k.lower(): v for k, v in resp.json()["headers"].items()}
        assert echoed.get("x-a") == "1"
        assert echoed.get("x-b") == "2"

    def test_dict_inputs_still_work_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        resp = session.get(f"{BASE}/get", params={"x": "y"})
        assert resp.status_code == 200
        assert resp.json()["args"]["x"] == "y"

    @pytest.mark.asyncio
    async def test_repeated_query_params_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = await session.get(f"{BASE}/get", params=[("tag", "a"), ("tag", "b")])
        assert resp.status_code == 200
        assert resp.json()["args"]["tag"] == ["a", "b"]


# ==========================================================================
# Gap-fill: base_url, request(), pool_clear, https_only, per-request protocol
# ==========================================================================


class TestNewlyExposedFeatures:
    """base_url, generic request(), pool_clear(), https_only, and per-request
    h3_header_order / protocol_policy / http_intent."""

    def test_base_url_relative_and_absolute_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session(base_url=BASE)
        # relative path is joined onto base_url
        resp = session.get("/get", params={"x": "y"})
        assert resp.status_code == 200
        assert resp.json()["args"]["x"] == "y"
        # an absolute URL overrides base_url
        resp = session.get(f"{BASE}/headers")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_base_url_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(base_url=BASE)
        resp = await session.get("/get")
        assert resp.status_code == 200

    def test_generic_request_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        resp = session.request("GET", f"{BASE}/get")
        assert resp.status_code == 200
        # lowercase method is normalized to upper-case
        resp = session.request("post", f"{BASE}/post", json={"a": 1})
        assert resp.status_code == 200
        assert resp.json()["json"] == {"a": 1}

    @pytest.mark.asyncio
    async def test_generic_request_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = await session.request("GET", f"{BASE}/get")
        assert resp.status_code == 200

    def test_pool_clear_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        session.get(f"{BASE}/get")
        session.pool_clear()  # must not raise

    def test_https_only_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session(https_only=True)
        resp = session.get(f"{BASE}/get")  # already https
        assert resp.status_code == 200

    def test_per_request_protocol_options_blocking(self):
        client = BlockingClient(tls_profile="chrome_144", verify=False)
        session = client.session()
        resp = session.get(
            f"{BASE}/get",
            h3_header_order=["host", "user-agent", "accept"],
            protocol_policy=lkrequest.ProtocolPolicy.chrome_standard(),
            http_intent=lkrequest.HttpIntent.H2Only,
        )
        assert resp.status_code == 200

    def test_client_and_session_h3_header_order_accepted(self):
        client = BlockingClient(
            tls_profile="chrome_144",
            verify=False,
            h3_header_order=["host", "user-agent"],
        )
        session = client.session(h3_header_order=["host", "user-agent"])
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200

    def test_dos_limits_and_quic_timeout_construct(self):
        client = lkrequest.Client(
            max_header_count=100,
            max_header_size=16384,
            max_headers_total_size=131072,
            min_transfer_rate=1,
            min_transfer_rate_window=10.0,
            quic_connect_timeout=5.0,
        )
        assert "Client" in repr(client)

    def test_dos_limits_allow_normal_request_blocking(self):
        # Lenient limits must not block an ordinary fast response.
        client = BlockingClient(
            tls_profile="chrome_144",
            verify=False,
            max_header_count=200,
            max_header_size=32768,
            min_transfer_rate=1,
            min_transfer_rate_window=10.0,
            quic_connect_timeout=5.0,
        )
        session = client.session()
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200


# ==========================================================================
# Client Configuration Options
# ==========================================================================


class TestClientConfiguration:
    def test_default_headers(self):
        client = lkrequest.Client(
            default_headers={"X-App": "lkrequest", "Accept-Language": "zh-CN"},
        )
        assert "Client" in repr(client)

    def test_header_order(self):
        client = lkrequest.Client(
            header_order=["Host", "User-Agent", "Accept", "Accept-Encoding"],
        )
        assert "Client" in repr(client)

    def test_cookie_order(self):
        client = lkrequest.Client(
            cookie_order=["session_id", "csrf_token"],
        )
        assert "Client" in repr(client)

    def test_h2_fallback_h1(self):
        client = lkrequest.Client(h2_fallback_h1=True)
        assert "Client" in repr(client)

    def test_proxy_fallback_direct(self):
        client = lkrequest.Client(proxy_fallback_direct=True)
        assert "Client" in repr(client)

    def test_retry_on_connection_close(self):
        client = lkrequest.Client(retry_on_connection_close=True)
        assert "Client" in repr(client)

    def test_all_timeouts(self):
        client = lkrequest.Client(
            dns_timeout=5.0,
            tcp_connect_timeout=10.0,
            tls_handshake_timeout=10.0,
            ttfb_timeout=15.0,
            total_timeout=30.0,
        )
        assert "Client" in repr(client)

    def test_resource_limits(self):
        client = lkrequest.Client(
            max_response_body_size=10 * 1024 * 1024,
            max_connections_per_session=16,
        )
        assert "Client" in repr(client)

    @pytest.mark.parametrize("cls", [lkrequest.Client, BlockingClient])
    def test_max_pending_h2_requests(self, cls):
        # Bounds how many HTTP/2 requests may queue for a remote stream slot.
        # Omitting it keeps upstream's default, which is unbounded.
        assert "Client" in repr(cls(max_pending_h2_requests=8))
        assert "Client" in repr(cls())

    @pytest.mark.parametrize("cls", [lkrequest.Client, BlockingClient])
    def test_max_pending_h2_requests_rejects_zero(self, cls):
        # Upstream asserts on zero, which would escape as a panic rather than a
        # Python exception, so the binding rejects it up front.
        with pytest.raises(ValueError, match="greater than 0"):
            cls(max_pending_h2_requests=0)

    @pytest.mark.parametrize("cls", [lkrequest.Client, BlockingClient])
    def test_system_dns_cache(self, cls):
        # Enables a positive-result cache on the OS resolver. A zero TTL is
        # valid upstream (disables caching while keeping in-flight coalescing),
        # so it must not be rejected like max_pending's zero is.
        assert "Client" in repr(cls(system_dns_cache_ttl=30.0))
        assert "Client" in repr(
            cls(system_dns_cache_ttl=30.0, system_dns_cache_max_entries=4096)
        )
        assert "Client" in repr(cls(system_dns_cache_ttl=0.0))

    @pytest.mark.parametrize("cls", [lkrequest.Client, BlockingClient])
    def test_system_dns_cache_conflicts_with_dns(self, cls):
        # The cache implies the system resolver; pairing it with an explicit
        # dns= would let one silently override the other, so it is rejected.
        with pytest.raises(ValueError, match="cannot be combined with dns"):
            cls(system_dns_cache_ttl=30.0, dns="google")

    @pytest.mark.parametrize("cls", [lkrequest.Client, BlockingClient])
    def test_system_dns_cache_max_entries_needs_ttl(self, cls):
        # max_entries only configures the cache the TTL turns on, so on its own
        # it is a no-op that almost certainly signals a mistake.
        with pytest.raises(ValueError, match="requires system_dns_cache_ttl"):
            cls(system_dns_cache_max_entries=100)


# ==========================================================================
# Session Configuration Options
# ==========================================================================


class TestSessionConfiguration:
    def test_max_connections(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(max_connections=32)
        assert repr(session) == "<Session>"

    def test_idle_timeout(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(idle_timeout=60.0)
        assert repr(session) == "<Session>"

    def test_http2_only(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(http2_only=True)
        assert repr(session) == "<Session>"


# ==========================================================================
# Event Hooks
# ==========================================================================


class TestEventHooks:
    def test_on_request_hook_at_creation(self):
        called = []

        def on_req(method, url, headers):
            called.append((method, url))

        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(on_request=on_req)
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200
        assert len(called) >= 1
        assert called[0][0] == "GET"

    def test_on_response_hook_at_creation(self):
        called = []

        def on_resp(status_code, url, elapsed):
            called.append((status_code, url, elapsed))

        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(on_response=on_resp)
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200
        assert len(called) >= 1
        assert called[0][0] == 200

    def test_on_request_hook_dynamic(self):
        called = []

        def on_req(method, url, headers):
            called.append(method)

        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        session.on_request(on_req)
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200
        assert "GET" in called

    def test_on_response_hook_dynamic(self):
        called = []

        def on_resp(status_code, url, elapsed):
            called.append(status_code)

        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        session.on_response(on_resp)
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200
        assert 200 in called

    @pytest.mark.asyncio
    async def test_async_event_hooks(self):
        req_log = []
        resp_log = []

        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(
            on_request=lambda m, u, h: req_log.append(m),
            on_response=lambda s, u, e: resp_log.append(s),
        )
        resp = await session.get(f"{BASE}/get")
        assert resp.status_code == 200
        assert "GET" in req_log
        assert 200 in resp_log


# ==========================================================================
# Metrics
# ==========================================================================


class TestMetrics:
    def test_enable_metrics(self):
        collector = lkrequest.enable_metrics()
        assert collector is not None

    def test_snapshot(self):
        collector = lkrequest.enable_metrics()
        snap = collector.snapshot()
        assert isinstance(snap, dict)

    def test_prometheus_text(self):
        collector = lkrequest.enable_metrics()
        text = collector.prometheus_text()
        assert isinstance(text, str)

    def test_reset(self):
        collector = lkrequest.enable_metrics()
        collector.reset()
        snap = collector.snapshot()
        assert isinstance(snap, dict)

    def test_metrics_after_request(self):
        collector = lkrequest.enable_metrics()
        collector.reset()
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        session.get(f"{BASE}/get")
        snap = collector.snapshot()
        assert isinstance(snap, dict)


# ==========================================================================
# Preconnect & Prefetch
# ==========================================================================


class TestPreconnect:
    def test_blocking_preconnect(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        session.preconnect(f"{BASE}")

    def test_blocking_preconnect_many(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        results = session.preconnect_many([f"{BASE}"])
        assert isinstance(results, list)

    def test_blocking_prefetch(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        results = session.prefetch([f"{BASE}"])
        assert isinstance(results, list)
        assert len(results) >= 1

    @pytest.mark.asyncio
    async def test_async_preconnect(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        await session.preconnect(f"{BASE}")

    @pytest.mark.asyncio
    async def test_async_preconnect_many(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        results = await session.preconnect_many([f"{BASE}"])
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_async_prefetch(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        results = await session.prefetch([f"{BASE}"])
        assert isinstance(results, list)


# ==========================================================================
# Streaming Response
# ==========================================================================


class TestStreamingResponse:
    @pytest.mark.asyncio
    async def test_streaming_bytes(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = await session.send_streaming("GET", f"{BASE}/get")
        assert stream.status_code == 200
        assert stream.headers is not None
        body = await stream.bytes()
        assert len(body) > 0

    @pytest.mark.asyncio
    async def test_streaming_text(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = await session.send_streaming("GET", f"{BASE}/html")
        text = await stream.text()
        assert "<!DOCTYPE html>" in text

    @pytest.mark.asyncio
    async def test_streaming_chunks(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = await session.send_streaming("GET", f"{BASE}/get")
        chunks = []
        async for chunk in stream:
            chunks.append(chunk)
        assert len(chunks) > 0

    @pytest.mark.asyncio
    async def test_streaming_full_body_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = await session.send_streaming("GET", f"{BASE}/get")
        assert stream.status_code == 200
        body = await stream.bytes()
        assert len(body) > 0

    def test_blocking_streaming_bytes(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = session.send_streaming("GET", f"{BASE}/get")
        assert stream.status_code == 200
        # Blocking streaming must be consumable synchronously (no event loop).
        body = stream.bytes()
        assert isinstance(body, (bytes, bytearray))
        assert len(body) > 0

    def test_blocking_streaming_iter(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = session.send_streaming("GET", f"{BASE}/get")
        chunks = [chunk for chunk in stream]
        assert all(isinstance(c, (bytes, bytearray)) for c in chunks)
        assert sum(len(c) for c in chunks) > 0

    def test_blocking_streaming_post_body(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = session.send_streaming("POST", f"{BASE}/post", json={"hello": "world"})
        payload = json.loads(stream.text())
        assert payload["json"] == {"hello": "world"}

    @pytest.mark.asyncio
    async def test_streaming_body_and_auth_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stream = await session.send_streaming(
            "POST", f"{BASE}/post", data={"k": "v"}, bearer_auth="tok123"
        )
        payload = json.loads(await stream.text())
        assert payload["form"] == {"k": "v"}
        assert payload["headers"].get("Authorization") == "Bearer tok123"


# ==========================================================================
# SessionPool
# ==========================================================================


class TestBlockingSessionPool:
    def test_creation(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        pool = lkrequest.BlockingSessionPool(
            client,
            ["http://127.0.0.1:8080"],
            max_sessions=5,
            idle_timeout=60.0,
        )
        assert pool is not None

    def test_stats(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        pool = lkrequest.BlockingSessionPool(
            client,
            ["http://127.0.0.1:8080"],
        )
        stats = pool.stats()
        assert isinstance(stats, lkrequest.SessionPoolStats)
        assert stats.idle_sessions >= 0

    def test_creation_with_proxy_chain(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        chain = lkrequest.ProxyConfig.parse_chain(
            ["socks5://hop1.example:1080", "socks5://hop2.example:1080"]
        )
        pool = lkrequest.BlockingSessionPool(client, [chain])
        assert pool is not None


class TestAsyncSessionPool:
    def test_creation(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        pool = lkrequest.SessionPool(
            client,
            ["http://127.0.0.1:8080"],
            max_sessions=5,
            idle_timeout=60.0,
        )
        assert pool is not None

    @pytest.mark.asyncio
    async def test_stats(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        pool = lkrequest.SessionPool(
            client,
            ["http://127.0.0.1:8080"],
        )
        stats = await pool.stats()
        assert isinstance(stats, lkrequest.SessionPoolStats)

    def test_creation_with_proxy_chain(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        chain = lkrequest.ProxyConfig.parse_chain(
            ["socks5://hop1.example:1080", "socks5://hop2.example:1080"]
        )
        pool = lkrequest.SessionPool(client, [chain])
        assert pool is not None


# ==========================================================================
# Logging
# ==========================================================================


class TestLogging:
    def test_set_log_level_warn(self):
        lkrequest.set_log_level("warn")

    def test_set_log_level_error(self):
        lkrequest.set_log_level("error")

    def test_set_log_level_trace(self):
        lkrequest.set_log_level("trace")

    def test_set_log_level_off(self):
        lkrequest.set_log_level("off")

    def test_set_log_level_with_format(self):
        lkrequest.set_log_level("info", format="compact")


# ==========================================================================
# Exception Hierarchy
# ==========================================================================


class TestExceptionHierarchy:
    def test_tls_error_is_request_error(self):
        assert issubclass(lkrequest.TlsError, lkrequest.RequestError)

    def test_proxy_error_is_request_error(self):
        assert issubclass(lkrequest.ProxyError, lkrequest.RequestError)

    def test_http_status_error_is_request_error(self):
        assert issubclass(lkrequest.HttpStatusError, lkrequest.RequestError)

    def test_connection_error_is_request_error(self):
        assert issubclass(lkrequest.LkConnectionError, lkrequest.RequestError)

    def test_timeout_error_is_request_error(self):
        assert issubclass(lkrequest.LkTimeoutError, lkrequest.RequestError)

    def test_too_many_redirects_is_request_error(self):
        assert issubclass(lkrequest.TooManyRedirectsError, lkrequest.RequestError)

    def test_resource_limit_error_is_request_error(self):
        assert issubclass(lkrequest.ResourceLimitError, lkrequest.RequestError)

    def test_error_for_status_raises_http_status_error(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/status/500")
        with pytest.raises(lkrequest.HttpStatusError):
            resp.error_for_status()

    def test_too_many_redirects(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(max_redirects=1)
        with pytest.raises(lkrequest.TooManyRedirectsError):
            session.get(f"{BASE}/redirect/5")
