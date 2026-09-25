"""Tests for lkrequest Client and basic functionality."""

import os
import asyncio
import json
import pytest
import lkrequest
from lkrequest.blocking import Client as BlockingClient

# The WebSocket tests below talk to the public wss://echo.websocket.org, which
# is unstable (its TLS handshake is frequently dropped by the remote). Skip them
# by default so the suite is deterministic; run with LKREQUEST_WS_LIVE=1 to
# exercise the live WebSocket path explicitly.
requires_live_ws = pytest.mark.skipif(
    not os.environ.get("LKREQUEST_WS_LIVE"),
    reason="live WebSocket echo server is unstable; set LKREQUEST_WS_LIVE=1 to run",
)

# Redirected to the local hypercorn httpbin server by the autouse fixture below,
# so requests in this module never depend on the public httpbin.org.
BASE = "https://httpbin.org"


@pytest.fixture(autouse=True)
def _redirect_to_local_server(server_url):
    global BASE
    BASE = server_url
    yield


class TestClientCreation:
    def test_default_client(self):
        client = lkrequest.Client()
        assert "Client" in repr(client)

    def test_chrome_131(self):
        client = lkrequest.Client.chrome_131()
        assert "Client" in repr(client)

    def test_chrome_144(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        assert "Client" in repr(client)

    def test_firefox_133(self):
        client = lkrequest.Client.firefox_133()
        assert "Client" in repr(client)

    def test_firefox_147(self):
        client = lkrequest.Client.firefox_147()
        assert "Client" in repr(client)

    def test_safari_18(self):
        client = lkrequest.Client.safari_18()
        assert "Client" in repr(client)

    def test_safari_26(self):
        client = lkrequest.Client.safari_26()
        assert "Client" in repr(client)

    def test_custom_profile(self):
        client = lkrequest.Client(
            tls_profile="chrome_144",
            h2_profile="chrome_144",
            tcp_fingerprint="chrome_win",
        )
        assert "Client" in repr(client)

    def test_with_timeouts(self):
        client = lkrequest.Client(
            tls_profile="chrome_131",
            total_timeout=30.0,
            tcp_connect_timeout=10.0,
            dns_timeout=5.0,
        )
        assert "Client" in repr(client)

    def test_invalid_tls_profile(self):
        with pytest.raises(ValueError, match="Unknown TLS profile"):
            lkrequest.Client(tls_profile="nonexistent")

    def test_invalid_h2_profile(self):
        with pytest.raises(ValueError, match="Unknown H2 profile"):
            lkrequest.Client(h2_profile="nonexistent")

    def test_client_with_middleware(self):
        mw = lkrequest.Middleware("test_mw")
        client = lkrequest.Client(middleware=[mw])
        assert "Client" in repr(client)


class TestSessionCreation:
    def test_basic_session(self):
        client = lkrequest.Client.chrome_131()
        session = client.session()
        assert repr(session) == "<Session>"

    def test_session_with_proxy(self):
        client = lkrequest.Client.chrome_131()
        session = client.session(proxy="http://127.0.0.1:8080")
        assert repr(session) == "<Session>"

    def test_session_http1_only(self):
        client = lkrequest.Client.chrome_131()
        session = client.session(http1_only=True)
        assert repr(session) == "<Session>"

    def test_session_with_max_redirects(self):
        client = lkrequest.Client.chrome_131()
        session = client.session(max_redirects=5)
        assert repr(session) == "<Session>"

    def test_session_with_allow_redirects_false(self):
        client = lkrequest.Client.chrome_131()
        session = client.session(allow_redirects=False)
        assert repr(session) == "<Session>"

    def test_session_with_retry_exponential(self):
        client = lkrequest.Client.chrome_131()
        retry = lkrequest.ExponentialBackoff(max_retries=3, base_delay=0.5)
        session = client.session(retry=retry)
        assert repr(session) == "<Session>"

    def test_session_with_retry_fixed(self):
        client = lkrequest.Client.chrome_131()
        retry = lkrequest.FixedInterval(max_retries=2, interval=1.0)
        session = client.session(retry=retry)
        assert repr(session) == "<Session>"

    def test_session_with_middleware(self):
        client = lkrequest.Client.chrome_131()
        mw = lkrequest.Middleware("session_mw", on_request=lambda req: req)
        session = client.session(middleware=[mw])
        assert repr(session) == "<Session>"

    def test_session_with_retry_invalid_type(self):
        client = lkrequest.Client.chrome_131()
        with pytest.raises(TypeError, match="retry must be"):
            client.session(retry="not_a_retry")

    def test_session_with_callable_retry(self):
        client = lkrequest.Client.chrome_131()

        def my_retry(attempt, error, status):
            if attempt < 3:
                return 0.1
            return None

        session = client.session(retry=my_retry)
        assert repr(session) == "<Session>"

    def test_session_with_lambda_retry(self):
        client = lkrequest.Client.chrome_131()
        session = client.session(retry=lambda a, e, s: 0.5 if a < 2 else None)
        assert repr(session) == "<Session>"


class TestBlockingRequests:
    @pytest.fixture
    def session(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        return client.session()

    def test_get(self, session):
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200
        assert resp.ok

    def test_get_with_params(self, session):
        resp = session.get(f"{BASE}/get", params={"key": "value"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["args"]["key"] == "value"

    def test_post_json(self, session):
        resp = session.post(f"{BASE}/post", json={"hello": "world"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["json"]["hello"] == "world"

    def test_post_form(self, session):
        resp = session.post(f"{BASE}/post", data={"field": "value"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["form"]["field"] == "value"

    def test_custom_headers(self, session):
        resp = session.get(f"{BASE}/headers", headers={"X-Test": "custom-value"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["headers"]["X-Test"] == "custom-value"

    def test_bearer_auth(self, session):
        resp = session.get(f"{BASE}/bearer", bearer_auth="test-token")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["token"] == "test-token"

    def test_basic_auth(self, session):
        resp = session.get(
            f"{BASE}/basic-auth/user/pass",
            basic_auth=("user", "pass"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["user"] == "user"

    def test_error_for_status(self, session):
        resp = session.get(f"{BASE}/status/404")
        assert resp.status_code == 404
        assert not resp.ok
        with pytest.raises(lkrequest.HttpStatusError):
            resp.error_for_status()

    def test_cookies(self, session):
        session.set_cookie(f"{BASE}", "test_cookie", "test_value")
        resp = session.get(f"{BASE}/cookies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cookies"]["test_cookie"] == "test_value"

    def test_response_content(self, session):
        resp = session.get(f"{BASE}/html")
        assert resp.status_code == 200
        text = resp.text()
        assert "<!DOCTYPE html>" in text
        assert len(resp.content) > 0
        assert len(resp) > 0

    def test_blocking_session_with_retry(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        retry = lkrequest.ExponentialBackoff(max_retries=2)
        session = client.session(retry=retry)
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200

    def test_response_elapsed(self, session):
        resp = session.get(f"{BASE}/get")
        assert resp.elapsed > 0
        assert isinstance(resp.elapsed, float)

    def test_response_encoding(self, session):
        resp = session.get(f"{BASE}/html")
        # httpbin returns Content-Type: text/html; charset=utf-8
        assert resp.encoding is None or isinstance(resp.encoding, str)
        # Regardless of how encoding is reported, the body must decode to text.
        assert "<html" in resp.text().lower()

    def test_response_headermap(self, session):
        resp = session.get(f"{BASE}/get")
        headers = resp.headers

        assert isinstance(headers, lkrequest.HeaderMap)
        assert "content-type" in headers
        assert "Content-Type" in headers

        ct = headers["content-type"]
        assert "json" in ct.lower()

        ct2 = headers.get("Content-Type")
        assert ct == ct2

        assert headers.get("x-nonexistent") is None
        assert headers.get("x-nonexistent", "fallback") == "fallback"

        with pytest.raises(KeyError):
            _ = headers["x-nonexistent"]

        assert len(headers) > 0
        assert len(headers.keys()) == len(headers)
        assert len(headers.values()) == len(headers)
        assert len(headers.items()) == len(headers)

        for key in headers:
            assert isinstance(key, str)
            break

    def test_no_decompress(self, session):
        resp = session.get(
            f"{BASE}/gzip",
            no_decompress=True,
        )
        assert resp.status_code == 200


class TestAsyncRequests:
    @pytest.fixture
    def session(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        return client.session()

    @pytest.mark.asyncio
    async def test_async_get(self, session):
        resp = await session.get(f"{BASE}/get")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_post_json(self, session):
        resp = await session.post(f"{BASE}/post", json={"async": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["json"]["async"] is True

    @pytest.mark.asyncio
    async def test_async_concurrent(self, session):
        urls = [f"{BASE}/get?i={i}" for i in range(3)]
        tasks = [session.get(url) for url in urls]
        responses = await asyncio.gather(*tasks)
        for i, resp in enumerate(responses):
            assert resp.status_code == 200
            data = resp.json()
            assert data["args"]["i"] == str(i)

    @pytest.mark.asyncio
    async def test_async_basic_auth(self, session):
        resp = await session.get(
            f"{BASE}/basic-auth/user/pass",
            basic_auth=("user", "pass"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True

    @pytest.mark.asyncio
    async def test_async_elapsed(self, session):
        resp = await session.get(f"{BASE}/get")
        assert resp.elapsed > 0

    @pytest.mark.asyncio
    async def test_async_headermap(self, session):
        resp = await session.get(f"{BASE}/get")
        headers = resp.headers
        assert isinstance(headers, lkrequest.HeaderMap)
        assert "content-type" in headers


class TestWebSocketMessage:
    def test_ws_message_text(self):
        msg = lkrequest.WsMessage.text("hello")
        assert msg.is_text()
        assert not msg.is_binary()
        assert not msg.is_close()
        assert "hello" in repr(msg)

    def test_ws_message_binary(self):
        msg = lkrequest.WsMessage.binary(b"data")
        assert msg.is_binary()
        assert not msg.is_text()


class TestTypes:
    def test_timeout_config(self):
        tc = lkrequest.TimeoutConfig(total=30.0, tcp_connect=10.0)
        assert "total=Some(30s)" in repr(tc)
        assert "tcp_connect=Some(10s)" in repr(tc)

    def test_resource_limits(self):
        rl = lkrequest.ResourceLimits(max_response_body_size=1024)
        assert rl is not None

    def test_http_version(self):
        assert lkrequest.HttpVersion.H2 == 2
        assert lkrequest.HttpVersion.HTTP11 == 1

    @pytest.mark.parametrize(
        "enum_name",
        [
            "HttpVersion",
            "HttpIntent",
            "PreferredHttpVersion",
            "Idempotency",
            "BrokenQuicPolicy",
            "WsMessage",
        ],
    )
    def test_public_enums_are_hashable(self, enum_name):
        # A pyclass that declares `eq` without `hash` gets `__hash__ = None`
        # from CPython, so mapping a member to something — the obvious use for
        # an enum — raised `TypeError: unhashable type`.
        cls = getattr(lkrequest, enum_name)
        if enum_name == "WsMessage":
            members = [cls.text("a"), cls.binary(b"b")]
        else:
            members = [v for v in vars(cls).values() if isinstance(v, cls)]
        assert len(members) >= 2, f"{enum_name} exposes too few members to test"

        lookup = {member: index for index, member in enumerate(members)}
        assert len(lookup) == len(members), "distinct members collided in a dict"
        assert len(set(members)) == len(members)
        for index, member in enumerate(members):
            assert lookup[member] == index
        # Equal values must hash equally, or dict lookups by a fresh instance
        # would miss.
        assert hash(members[0]) == hash(members[0])

    def test_exponential_backoff(self):
        eb = lkrequest.ExponentialBackoff(max_retries=5, base_delay=0.5)
        assert "max_retries=5" in repr(eb)

    def test_fixed_interval(self):
        fi = lkrequest.FixedInterval(max_retries=3, interval=2.0)
        assert "max_retries=3" in repr(fi)

    def test_multipart(self):
        mp = lkrequest.Multipart()
        mp.text("name", "value")
        assert repr(mp) == "<Multipart>"


class TestMiddleware:
    def test_middleware_creation(self):
        mw = lkrequest.Middleware("logging")
        assert repr(mw) == "<Middleware 'logging'>"

    def test_middleware_with_on_request(self):
        def on_req(req_dict):
            return req_dict

        mw = lkrequest.Middleware("request_mw", on_request=on_req)
        assert repr(mw) == "<Middleware 'request_mw'>"

    def test_middleware_with_both_callbacks(self):
        mw = lkrequest.Middleware(
            "full_mw",
            on_request=lambda req: req,
            on_response=lambda resp: resp,
        )
        assert repr(mw) == "<Middleware 'full_mw'>"

    def test_client_with_middleware(self):
        mw = lkrequest.Middleware("client_mw", on_request=lambda req: req)
        client = lkrequest.Client(middleware=[mw])
        session = client.session()
        assert repr(session) == "<Session>"

    def test_session_with_middleware(self):
        client = lkrequest.Client.chrome_131()
        mw = lkrequest.Middleware("session_mw", on_response=lambda resp: resp)
        session = client.session(middleware=[mw])
        assert repr(session) == "<Session>"


class TestProxyConfig:
    def test_parse_single_proxy(self):
        proxy = lkrequest.ProxyConfig(
            "socks5://YOUR_PROXY_USER:YOUR_PROXY_PASS@proxy.example.com:1080"
        )

        assert proxy.hop_count() == 1
        assert str(proxy) == "socks5://proxy.example.com:1080"
        assert "YOUR_PROXY_PASS" not in repr(proxy)

        # identity() is an opaque pooling / failure-tracking key, so assert the
        # properties upstream guarantees rather than the exact encoding: every
        # hop's protocol, host, port and username, and never the password. The
        # credential fragment carries a kind prefix (``user:`` here) whose exact
        # spelling is upstream's business, so only the username is pinned.
        [hop] = json.loads(proxy.identity())
        assert hop[:3] == ["socks5", "proxy.example.com", 1080]
        assert "YOUR_PROXY_USER" in hop[3]
        assert "YOUR_PROXY_PASS" not in proxy.identity()

    def test_parse_chain_preserves_order(self):
        chain = lkrequest.ProxyConfig.parse_chain(
            [
                "socks5://hop1.example:1080",
                "socks5h://hop2.example:1081",
                "http://final.example:8080",
            ]
        )

        assert chain.hop_count() == 3
        assert str(chain) == (
            "socks5://hop1.example:1080 -> "
            "socks5h://hop2.example:1081 -> "
            "http://final.example:8080"
        )
        assert json.loads(chain.identity()) == [
            ["socks5", "hop1.example", 1080, None],
            ["socks5h", "hop2.example", 1081, None],
            ["http", "final.example", 8080, None],
        ]

    def test_identity_distinguishes_dns_mode(self):
        # socks5 and socks5h differ only in who resolves the hostname, which the
        # old delimiter-joined identity could not express — two chains that route
        # differently must not share a cooldown/failure key.
        local = lkrequest.ProxyConfig("socks5://hop.example:1080")
        remote = lkrequest.ProxyConfig("socks5h://hop.example:1080")

        assert local.identity() != remote.identity()

    def test_through_returns_new_config(self):
        final = lkrequest.ProxyConfig.parse("socks5://final.example:1080")
        chain = final.through(
            [
                "http://hop1.example:8080",
                lkrequest.ProxyConfig("socks5://hop2.example:1081"),
            ]
        )

        assert final.hop_count() == 1
        assert chain.hop_count() == 3
        assert str(chain).startswith("http://hop1.example:8080 -> socks5://hop2")

    def test_credential_setters_return_new_configs(self):
        plain = lkrequest.ProxyConfig("http://proxy.example:8080")
        bearer = plain.with_http_auth("Bearer", "token-123")

        assert json.loads(plain.identity())[0][3] is None
        assert bearer is not plain
        assert bearer.with_auth_header("authorization") is not bearer

    def test_identity_separates_credentials_without_exposing_them(self):
        # Two tokens on one gateway are two proxies: sharing a key would let
        # one failing credential blacklist the other.
        proxy = lkrequest.ProxyConfig("http://proxy.example:8080")
        first = proxy.with_http_auth("Bearer", "token-one").identity()
        second = proxy.with_http_auth("Bearer", "token-two").identity()

        assert first != second
        assert "token-one" not in first

    def test_with_user_pass_replaces_the_url_credential(self):
        proxy = lkrequest.ProxyConfig("http://old:secret@proxy.example:8080")
        [hop] = json.loads(proxy.with_user_pass("new", "pw").identity())
        assert "new" in hop[3]
        assert "old" not in hop[3]

    def test_socks5_cannot_carry_an_http_credential(self):
        with pytest.raises(ValueError):
            lkrequest.ProxyConfig("socks5://proxy.example:1080").with_http_auth(
                "Bearer", "token"
            )

    def test_unknown_auth_header_is_rejected(self):
        with pytest.raises(ValueError, match="proxy-authorization"):
            lkrequest.ProxyConfig("http://proxy.example:8080").with_auth_header(
                "x-proxy-token"
            )

    @pytest.mark.parametrize(
        ("header", "expected"),
        [(None, "proxy-authorization"), ("Authorization", "authorization")],
    )
    def test_http_credential_is_sent_on_connect(self, header, expected):
        # A one-shot HTTP CONNECT proxy that records the request and refuses it,
        # which is all it takes to see which header the credential went out in.
        import socket
        import threading

        seen = {}
        listener = socket.create_server(("127.0.0.1", 0))

        def _serve():
            conn, _ = listener.accept()
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                for line in data.decode().split("\r\n")[1:]:
                    if ":" in line:
                        name, value = line.split(":", 1)
                        seen[name.strip().lower()] = value.strip()
                conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        proxy = lkrequest.ProxyConfig(
            f"http://127.0.0.1:{listener.getsockname()[1]}"
        ).with_http_auth("Bearer", "token-123")
        if header is not None:
            proxy = proxy.with_auth_header(header)

        try:
            with pytest.raises(lkrequest.ProxyError):
                BlockingClient.chrome_131().session(proxy=proxy).get(
                    "https://target.example/", timeout=5.0
                )
        finally:
            thread.join(5)
            listener.close()

        assert seen[expected] == "Bearer token-123"
        other = {"proxy-authorization", "authorization"} - {expected}
        assert not other & seen.keys()

    def test_parse_chain_rejects_empty_input(self):
        with pytest.raises(ValueError, match="at least one proxy"):
            lkrequest.ProxyConfig.parse_chain([])

    def test_parse_chain_accepts_generator(self):
        urls = (
            url
            for url in [
                "socks5://hop1.example:1080",
                "socks5://hop2.example:1080",
            ]
        )
        assert lkrequest.ProxyConfig.parse_chain(urls).hop_count() == 2

    def test_proxy_input_rejects_wrong_type(self):
        client = lkrequest.Client.chrome_131()
        with pytest.raises(TypeError, match="str or ProxyConfig"):
            client.session(proxy=object())

    def test_invalid_proxy_string_preserves_existing_session_behavior(self):
        client = lkrequest.Client.chrome_131()
        assert repr(client.session(proxy="not a proxy URL")) == "<Session>"

    def test_async_and_blocking_sessions_accept_proxy_config(self):
        chain = lkrequest.ProxyConfig.parse_chain(
            ["socks5://hop1.example:1080", "socks5://hop2.example:1080"]
        )

        assert repr(lkrequest.Client.chrome_131().session(proxy=chain)) == "<Session>"
        assert (
            repr(BlockingClient.chrome_131().session(proxy=chain))
            == "<BlockingSession>"
        )

    def test_quic_chain_session_builds_with_feature(self):
        if not hasattr(lkrequest, "QuicProfile"):
            pytest.skip("built without the quic-h3 feature")

        chain = lkrequest.ProxyConfig.parse_chain(
            ["socks5://hop1.example:1080", "socks5h://hop2.example:1080"]
        )
        client = lkrequest.Client(quic_profile="chrome_146")
        session = client.session(proxy=chain, http3_with_fallback=True)
        assert repr(session) == "<Session>"


class TestProxyPoolConfig:
    def test_bad_proxy_config(self):
        bpc = lkrequest.BadProxyConfig(
            failure_threshold=5,
            window=120.0,
            cooldown_duration=600.0,
        )
        assert "failure_threshold=5" in repr(bpc)

    def test_health_check_config(self):
        hc = lkrequest.HealthCheckConfig(
            interval=30.0,
            timeout=3.0,
            target_host="example.com",
            target_port=443,
        )
        assert "example.com" in repr(hc)

    def test_proxy_pool_with_config(self):
        bpc = lkrequest.BadProxyConfig(failure_threshold=5)
        pool = lkrequest.ProxyPool(
            ["http://127.0.0.1:8080"],
            rotation="round_robin",
            bad_proxy_config=bpc,
        )
        assert repr(pool) == "<ProxyPool>"

    def test_proxy_pool_random_rotation(self):
        pool = lkrequest.ProxyPool(
            ["http://127.0.0.1:8080", "http://127.0.0.1:8081"],
            rotation="random",
        )
        assert repr(pool) == "<ProxyPool>"

    def test_proxy_pool_accepts_proxy_chain(self):
        chain = lkrequest.ProxyConfig.parse_chain(
            ["socks5://hop1.example:1080", "socks5://hop2.example:1080"]
        )
        pool = lkrequest.ProxyPool([chain], rotation="round_robin")
        assert repr(pool) == "<ProxyPool>"

    def test_proxy_pool_invalid_rotation(self):
        with pytest.raises(ValueError, match="Unknown rotation strategy"):
            lkrequest.ProxyPool(
                ["http://127.0.0.1:8080"],
                rotation="invalid",
            )


class TestCallableRetry:
    def test_callable_retry_creation(self):
        client = lkrequest.Client.chrome_131()

        def custom_retry(attempt, error, status):
            if attempt <= 3:
                return 0.1
            return None

        session = client.session(retry=custom_retry)
        assert repr(session) == "<Session>"

    def test_callable_retry_blocking(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        call_log = []

        def retry_logger(attempt, error, status):
            call_log.append((attempt, error, status))
            return None

        session = client.session(retry=retry_logger)
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200


@requires_live_ws
class TestWebSocketBlocking:
    # echo.websocket.org 外部服务不稳定，TLS 握手阶段经常被远端关闭连接
    def test_ws_connect_blocking(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        ws = session.ws_connect(
            "wss://echo.websocket.org",
            headers={"Origin": "https://echo.websocket.org"},
        )
        assert repr(ws) == "<BlockingWsConnection>"

        # The echo server sends a greeting on connect
        greeting = ws.recv()
        assert greeting.is_text()

        ws.send_text("hello from lkrequest")
        echo = ws.recv()
        assert echo.is_text()

        ws.close()


@requires_live_ws
class TestWebSocketAsync:
    # echo.websocket.org 外部服务不稳定，TLS 握手阶段经常被远端关闭连接
    @pytest.mark.asyncio
    async def test_ws_connect_async(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        ws = await session.ws_connect(
            "wss://echo.websocket.org",
            headers={"Origin": "https://echo.websocket.org"},
        )
        assert repr(ws) == "<WsConnection>"

        greeting = await ws.recv()
        assert greeting.is_text()

        await ws.send_text("hello async")
        echo = await ws.recv()
        assert echo.is_text()

        await ws.close()


# ==========================================================================
# v0.4.0 New Feature Tests
# ==========================================================================


class TestAcceptEncoding:
    def test_accept_encoding_constants(self):
        ae = lkrequest.AcceptEncoding
        assert ae.GZIP is not None
        assert ae.BR is not None
        assert ae.DEFLATE is not None
        assert ae.ZSTD is not None
        assert ae.ALL is not None

    def test_accept_encoding_combine(self):
        ae = lkrequest.AcceptEncoding
        combined = ae.GZIP | ae.BR
        assert "gzip" in repr(combined)
        assert "br" in repr(combined)

    def test_accept_encoding_all_repr(self):
        ae = lkrequest.AcceptEncoding.ALL
        r = repr(ae)
        assert "gzip" in r
        assert "br" in r

    def test_session_with_accept_encoding(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(accept_encoding=lkrequest.AcceptEncoding.GZIP)
        assert repr(session) == "<Session>"

    def test_blocking_session_with_accept_encoding(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(
            accept_encoding=lkrequest.AcceptEncoding.GZIP | lkrequest.AcceptEncoding.BR
        )
        assert repr(session) == "<BlockingSession>"

    def test_request_level_accept_encoding(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(
            f"{BASE}/get",
            accept_encoding=lkrequest.AcceptEncoding.GZIP,
        )
        assert resp.status_code == 200


class TestCertificateManagement:
    def test_client_with_ca_cert_der(self):
        client = lkrequest.Client(ca_cert_der=b"dummy-der-data")
        assert "Client" in repr(client)

    def test_client_with_ca_cert_pem(self):
        client = lkrequest.Client(
            ca_cert_pem=b"-----BEGIN CERTIFICATE-----\nZHVtbXk=\n-----END CERTIFICATE-----\n"
        )
        assert "Client" in repr(client)

    def test_client_with_ca_cert_file_not_found(self):
        with pytest.raises(OSError):
            lkrequest.Client(ca_cert="/nonexistent/path/to/cert.pem")

    def test_blocking_client_with_ca_cert_der(self):
        client = BlockingClient(ca_cert_der=b"dummy-der-data")
        assert "BlockingClient" in repr(client)

    def test_client_verify_false(self):
        client = lkrequest.Client(verify=False)
        assert "Client" in repr(client)

    def test_blocking_client_verify_false(self):
        client = BlockingClient(verify=False)
        assert "BlockingClient" in repr(client)

    def test_client_use_native_certs(self):
        client = lkrequest.Client(use_native_certs=True)
        assert "Client" in repr(client)

    def test_blocking_client_use_native_certs(self):
        client = BlockingClient(use_native_certs=True)
        assert "BlockingClient" in repr(client)

    def test_verify_false_request_succeeds(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200


class TestECH:
    def test_client_with_ech_config(self):
        client = lkrequest.Client(ech_config=b"\x00\x01\x02\x03")
        assert "Client" in repr(client)

    def test_blocking_client_with_ech_config(self):
        client = BlockingClient(ech_config=b"\x00\x01\x02\x03")
        assert "BlockingClient" in repr(client)

    def test_session_with_ech_config(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(ech_config=b"\x00\x01\x02\x03")
        assert repr(session) == "<Session>"

    def test_blocking_session_with_ech_config(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session(ech_config=b"\x00\x01\x02\x03")
        assert repr(session) == "<BlockingSession>"


class TestPoolStats:
    def test_blocking_pool_stats_empty(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stats = session.pool_stats()
        assert isinstance(stats, lkrequest.PoolStats)
        assert stats.total == 0
        assert stats.h2_connections == 0
        assert stats.h1_connections == 0
        assert stats.at_capacity is False

    def test_blocking_pool_stats_after_request(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200
        stats = session.pool_stats()
        assert stats.total >= 1

    @pytest.mark.asyncio
    async def test_async_pool_stats(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stats = session.pool_stats()
        assert isinstance(stats, lkrequest.PoolStats)
        assert stats.total == 0

    def test_pool_stats_repr(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        stats = session.pool_stats()
        r = repr(stats)
        assert "PoolStats" in r
        assert "h2=" in r
        assert "h1=" in r


class TestSetLogLevel:
    def test_set_log_level_info(self):
        lkrequest.set_log_level("info")

    def test_set_log_level_debug(self):
        lkrequest.set_log_level("debug")

    def test_set_log_level_filter_directive(self):
        lkrequest.set_log_level("lkrequest=debug,lktls=trace")


class TestRedirectHistory:
    def test_no_redirect_history_empty(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/get")
        assert resp.status_code == 200
        assert resp.history == []

    def test_redirect_history_populated(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/redirect/2")
        assert resp.status_code == 200
        assert len(resp.history) == 2
        for hop in resp.history:
            assert isinstance(hop, lkrequest.RedirectRecord)
            assert hop.status_code in (301, 302, 307, 308)
            assert hop.url
            assert hop.redirect_to
            assert hop.headers is not None

    def test_redirect_record_repr(self):
        client = BlockingClient(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = session.get(f"{BASE}/redirect/1")
        assert len(resp.history) == 1
        r = repr(resp.history[0])
        assert "<RedirectRecord" in r

    @pytest.mark.asyncio
    async def test_async_redirect_history(self):
        client = lkrequest.Client(
            tls_profile="chrome_144", h2_profile="chrome_144", verify=False
        )
        session = client.session()
        resp = await session.get(f"{BASE}/redirect/1")
        assert resp.status_code == 200
        assert len(resp.history) == 1
        hop = resp.history[0]
        assert hop.status_code in (301, 302, 307, 308)
