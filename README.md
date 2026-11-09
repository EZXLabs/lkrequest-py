# lkrequest

A Python HTTP client with TLS/HTTP2/TCP fingerprint control. Powered by Rust for high performance.

[English](https://github.com/EZXLabs/lkrequest-py/blob/main/README.md) | [简体中文](https://github.com/EZXLabs/lkrequest-py/blob/main/README-zh.md)

## Features

- **Browser fingerprint emulation** — TLS/HTTP2/TCP fingerprint presets for Chrome, Firefox, and Safari
- **Custom fingerprints** — Fully programmable `TlsProfile` / `H2Profile` / `TcpFingerprint`, with JSON serialization
- **Fingerprint randomization** — `Client(randomize=Randomize.extension_order())` permutes TLS extension order per connection (drifts JA3, keeps JA4 stable, still a real browser); `client.randomize_fingerprint()` generates a unique variant to reduce correlation risk
- **Client pool** — `ClientPool` automatically rotates across multiple fingerprints
- **Async & sync APIs** — Both `asyncio` async and traditional synchronous calls
- **WebSocket** — wss:// connections with consistent fingerprinting
- **Streaming responses** — `send_streaming()` receives large files chunk by chunk
- **Cookie management** — Automatic cookie jar, with manual management, attribute setting, and overrides
- **Proxy support** — HTTP CONNECT / SOCKS5 proxies, authentication (username/password or a static HTTP credential such as `Bearer`), and ordered multi-hop chains; QUIC/H3 works over all-SOCKS5 chains
- **Proxy pool & session pool** — Built-in proxy rotation, bad-proxy marking, and session management
- **Multipart** — File upload support
- **Retry strategies** — Exponential backoff / fixed interval / custom callable retries
- **Middleware** — Request/response interception and modification (onion model)
- **Event hooks** — Lightweight request/response callbacks
- **Connection prewarming** — `preconnect()` / `prefetch()` to batch-establish connections
- **Prometheus metrics** — Built-in request counters, latency histograms, exposition-format export
- **Request diagnostics** — `response.diagnostics` exposes per-request phase timings (DNS/TCP/TLS/TTFB/total) plus remote_addr/protocol/cipher_suite and the trust-anchor negotiation
- **Runtime metrics snapshot** — `metrics_snapshot()` pulls process-level wire bytes / connection / request counters (for host-side collection; real values require the `telemetry` feature)
- **Zero-copy Response** — `bytes::Bytes` + PyBuffer protocol + text/json caching
- **Automatic decompression** — Brotli / gzip / deflate / zstd, with controllable `AcceptEncoding`
- **Certificate management** — Custom CA / disable verification / system certificates
- **ECH** — Encrypted Client Hello support, including TLS/QUIC HelloRetryRequest handling
- **Trust Anchor Identifiers** — Chrome 152+ presets advertise the roots they accept (extension `0xca34`); `Client(trust_anchor_advertisement="trusted", trust_anchor_recovery="once")` advertises the roots you trust and retries once with an ID the server names
- **Request priority** — `RequestPriority` (RFC 9218 urgency/incremental), `session.get(url, priority=...)`; `h2_priority_weight=` sets the weight (0–255) in the legacy priority field of an HTTP/2 HEADERS frame, independently of the `priority` header
- **Protocol policy** — `ProtocolPolicy` / `HttpIntent` control H2/H3 selection, acquisition (including a tunable TCP/QUIC race), upgrade, and fallback (client / session / request level)
- **Session resumption control** — `SessionResumptionConfig` controls TLS1.3 PSK / TLS1.2 ticket resumption (fingerprint shape); `Client(tls_session_resumption_policy=..., tls_session_cache_partition_policy=...)` controls whether tickets are *stored* and how the cache is keyed, and `session(network_partition_context=NetworkPartitionContext(top_level_site, frame_site))` reproduces the browser's per-site partitioning
- **H2 DATA framing** — `Client(h2_data_frame_policy=H2DataFramePolicy.BROWSER_DEFAULT / PEER_MAX_FRAME_SIZE / fixed_payload(n) / socket_write_aligned(n))` chooses how request bodies are split into DATA frames
- **Streaming uploads** — `session.post(url, body_stream=..., content_length=...)` uploads without buffering the body: a file-like object (`read(n)`), any iterable of `bytes`, or — on the async client — an async iterable. Omit `content_length` for an unknown-length body (chunked on HTTP/1.1, DATA frames on HTTP/2 and HTTP/3). The source is single-use, so it cannot be replayed for an automatic retry, a protocol fallback, or a redirect that must preserve the body
- **TLS close_notify** — `Client(require_close_notify=True)` rejects a response whose body was truncated without a TLS close_notify alert
- **HTTP/1.1 header casing** — `Client(http1_title_case_headers=False)` sends lowercase HTTP/1.1 header names (`content-type`) except for `Host`, which keeps its capital `H`. The default is Title-Case (`Content-Type`). Generated headers, requests, streamed requests, preconnected connections and WebSocket handshakes follow the same rule. HTTP/2 and HTTP/3 always send lowercase names
- **Request-level protocol override** — `preferred_http_version` / `idempotency` (0-RTT replay-safety declaration)
- **QUIC / HTTP3** — Optional feature (`maturin develop --features quic-h3`): `session(http3_only=True / http3_with_fallback=True / broken_quic_policy=BrokenQuicPolicy.Resilient)`, or cooldowns of your own for an origin whose QUIC connection failed with `broken_quic_policy=BrokenQuicConfig(initial_cooldown=2.0, max_cooldown=30.0)`; `Client(quic_fingerprint=..., quic_profile="chrome_150", disable_http3=True)`; dedicated Chrome 146/150/151/152/153/154/155/156/157 `QuicProfile` presets (available only when the feature is enabled). The QUIC-specific ClientHello is a separate TLS profile — pass `quic_fingerprint=TlsProfile.chrome_151_quic()` when building a client manually, otherwise HTTP/3 reuses the main TLS profile
- **HTTP/3 retries** — `session(h3_retry_mode=H3RetryMode.Chrome155ProtocolErrors)` retries selected HTTP/3 protocol errors up to twice, before response headers arrive, as Chrome 155 does. It replays buffered requests, **POST included**, so a request the server already processed can be processed again; send `idempotency=Idempotency.NotIdempotent` to opt a request out. Off by default (`H3RetryMode.Safe`); anything but `Safe` needs the `quic-h3` feature
- **MASQUE proxies (experimental)** — Optional feature (`maturin develop --features masque`, implies `quic-h3`): `session(proxy="masque://proxy:443", http3_only=True)` carries the QUIC connection to the target over an RFC 9298 CONNECT-UDP tunnel; `Client(masque=MasqueConfig(...))` configures trust for the hop to the proxy, independently of `verify`; `HealthCheckConfig(tunnel_probe=True, masque=...)` probes MASQUE proxies in a pool with a real tunnel
- **Synthetic fingerprints (advanced)** — Optional feature (`maturin develop --features synthetic-fp`): `Client(randomize=Randomize.recombine())` synthesizes a cross-layer (TLS+H2+H3) unique identity per session; `Randomize.full()` additionally draws out-of-corpus values for H2/QUIC; the `Layers` mask (e.g. `Randomize.recombine_layers(Layers.TLS | Layers.H2)`) restricts which layers are synthesized. Synthetic fingerprints match no real browser and are only for blocklist (negative-model) targets — against an allowlist they fail instantly

## Installation

Using pip:

```bash
pip install lkrequest
```

In a project managed by uv:

```bash
uv add lkrequest
```

### Development environment

Using venv and pip:

```bash
git clone https://github.com/EZXLabs/lkrequest-py
cd lkrequest-py
python3 -m venv .venv                 # Linux/macOS
# py -m venv .venv                    # Windows
source .venv/bin/activate             # Linux/macOS
# .venv\Scripts\Activate.ps1          # Windows PowerShell
python -m pip install --upgrade pip
python -m pip install maturin
python -m pip install -e ".[test,lint]"
```

Using uv (creates and manages `.venv` automatically):

```bash
git clone https://github.com/EZXLabs/lkrequest-py
cd lkrequest-py
uv sync --extra test --extra lint
```

## Quick Start

### Async API

```python
import asyncio
import lkrequest

async def main():
    client = lkrequest.Client.chrome_144()
    session = client.session()

    # GET request
    resp = await session.get("https://httpbin.org/get", params={"key": "value"})
    print(resp.status_code)  # 200
    print(resp.json())

    # POST JSON
    resp = await session.post("https://httpbin.org/post", json={"hello": "world"})
    print(resp.json())

    # Concurrent requests
    urls = [f"https://httpbin.org/get?id={i}" for i in range(5)]
    responses = await asyncio.gather(*[session.get(url) for url in urls])

asyncio.run(main())
```

### Sync API

```python
from lkrequest.blocking import Client

client = Client.chrome_131()
session = client.session()

resp = session.get("https://httpbin.org/get")
print(resp.status_code)
print(resp.text())
print(resp.json())
```

### All HTTP methods

```python
session.get(url)
session.post(url, json={"key": "value"})
session.put(url, json={"key": "value"})
session.patch(url, json={"field": "new_value"})
session.delete(url)
session.head(url)
session.options(url)
```

### Authentication

```python
# Bearer Token
resp = session.get("https://httpbin.org/bearer", bearer_auth="my-token")

# Basic Auth
resp = session.get(
    "https://httpbin.org/basic-auth/user/pass",
    basic_auth=("user", "pass"),
)
```

### Custom client

```python
client = lkrequest.Client(
    tls_profile="chrome_144",
    h2_profile="chrome_144",
    tcp_fingerprint="chrome_win",
    default_headers={"Accept-Language": "zh-CN"},
    header_order=["Host", "User-Agent", "Accept"],
    total_timeout=30.0,
    tcp_connect_timeout=10.0,
    max_connections_per_session=16,
    h2_fallback_h1=True,
    proxy_fallback_direct=True,
)
```

### Retry strategies

```python
# Exponential backoff retry
session = client.session(
    retry=lkrequest.ExponentialBackoff(max_retries=3, base_delay=0.5, max_delay=30.0, jitter=True)
)

# Fixed interval retry
session = client.session(
    retry=lkrequest.FixedInterval(max_retries=5, interval=1.0)
)

# Custom retry strategy (callable)
def my_retry(attempt: int, error: str | None, status: int | None) -> float | None:
    if status == 429:
        return min(2 ** attempt, 30)
    if attempt < 3:
        return 1.0
    return None  # give up

session = client.session(retry=my_retry)
```

A callable that also takes `exception=` is given the exception the failure raises, with the attributes listed under [Error handling](#error-handling), or `None` when it is a status being retried:

```python
def retry_when_worth_it(attempt, error, status, exception=None):
    if exception is not None and exception.retryable and attempt < 3:
        return 1.0
    return None
```

### Middleware

```python
def log_request(req_dict):
    print(f"{req_dict['method']} {req_dict['url']}")
    return req_dict

def log_response(resp_dict):
    print(f"  → {resp_dict['status']}")
    return resp_dict

# Client-level middleware
client = lkrequest.Client(
    middleware=[lkrequest.Middleware("logger", on_request=log_request, on_response=log_response)]
)

# Session-level middleware
session = client.session(
    middleware=[lkrequest.Middleware("auth", on_request=inject_auth)]
)
```

### Event hooks

A lighter-weight callback mechanism than middleware, for observing requests/responses without modifying them.

```python
def on_req(method, url, headers):
    print(f"→ {method} {url}")

def on_resp(status_code, url, elapsed):
    print(f"← {status_code} {url} ({elapsed:.3f}s)")

# Bind when creating the session
session = client.session(on_request=on_req, on_response=on_resp)

# Or add dynamically
session.on_request(on_req)
session.on_response(on_resp)
```

### Session lifecycle and memory

Connections, cookies and event hooks belong to the `Session`, not to the `Client` that made it. Create a session once and keep using it: a reused session keeps its connections open between requests, while one created per request pays a TCP and TLS handshake every time.

When a session is no longer needed, close it with a context manager, or by hand:

```python
with client.session() as session:          # BlockingClient
    session.get(url)

async with client.session() as session:    # Client
    await session.get(url)

session.close()                            # the same, without a block
```

`close()` aborts the pooled connections, abandons requests still in flight (they raise `RuntimeError`), drops the event hooks and the callbacks of session-level middleware, and makes the session refuse further requests with `RuntimeError`. Closing twice is harmless, `session.closed` tells whether it happened, and cookies stay readable. To drop only the connections and keep using the session, call `session.pool_clear()`.

A session that nothing refers to any more is freed on its own, connections included. A few things are worth knowing:

- **Hooks may refer back to their owner.** `session.on_response(self.log)` in a class that keeps `self.session` makes a reference cycle, which Python's cycle collector reclaims. It runs periodically rather than at once, so until it does, the session's connections stay open; `close()` releases them immediately.
- **Middleware callbacks are the exception.** They are held on the Rust side, out of the collector's sight, so a callback that refers back to its own session or client (a closure over it, a method of an object that holds it) is not reclaimed on its own. `session.close()` releases the callbacks of session-level middleware; those of `Client(middleware=...)` live as long as the client does, so create such a client once rather than per request.
- **The connection pool is unbounded by default.** An idle connection is dropped after 300 seconds, but only when the session is next used; until then a session that visited many different hosts keeps one connection per host, on the order of 100 KB each. `client.session(max_connections=..., idle_timeout=...)` and `Client(max_connections_per_session=...)` set the limits, and `close()` or `pool_clear()` releases them at once.
- **Freed memory is not always returned to the operating system.** A process's resident size can stay at its high-water mark after the connections are gone: the allocator keeps the pages for reuse. That is not a leak.

### Cookie management

```python
# Basic operations
session.set_cookie("https://example.com", "token", "abc123")
val = session.get_cookie("https://example.com", "token")
cookies = session.get_cookies("https://example.com")
header = session.cookie_header("https://example.com")

# With attributes
session.set_cookie_with_attrs(
    "https://example.com", "secure_token", "xyz",
    path="/api", domain="example.com", secure=True, http_only=True,
)
session.set_cookie_raw("https://example.com", "sid=abc; Path=/; Secure; SameSite=Lax")

# Remove and clear
session.remove_cookie("https://example.com", "token")
session.clear_cookies()

# Request-level cookie override
resp = session.get(url, cookie_override={"token": "override_value"})
```

Reading attributes back — `get_cookies()` returns `(name, value)` pairs, which
cannot tell two cookies sharing a name at different paths apart:

```python
for cookie in session.get_cookies_with_attrs("https://example.com/api"):
    print(cookie.name, cookie.value, cookie.path, cookie.domain,
          cookie.secure, cookie.http_only, cookie.same_site, cookie.expires)

# The whole jar, across every domain — what to persist or hand to a browser
for cookie in session.get_all_cookies():
    if cookie.is_persistent:       # has an expiry; a session cookie has none
        save(cookie)
```

`Cookie` is hashable, so two jars can be diffed with set operations.
`get_all_cookies()` lists cookies oldest first, and the `Cookie` header follows
Chrome's order — longer paths first, then older cookies first — so setting a
saved jar back into a fresh session reproduces the same headers on the wire.

### Multipart file upload

```python
mp = lkrequest.Multipart()
mp.text("title", "File upload")
mp.file("document", "report.pdf", "application/pdf", pdf_bytes)
# A Part says what text() and file() cannot, such as bytes without a filename
mp.part(lkrequest.Part("checksum", digest_bytes))
resp = session.post("https://example.com/upload", multipart=mp)
```

### Streaming uploads

Upload without holding the whole body in memory. Pass `content_length` when the
exact size is known; omit it for an unknown-length body.

```python
# A file on disk, exact length known
with open("archive.zip", "rb") as f:
    resp = await session.post(
        "https://example.com/upload",
        body_stream=f,
        content_length=os.path.getsize("archive.zip"),
    )

# A generator of chunks, unknown length (chunked on HTTP/1.1, DATA frames on H2/H3)
def chunks():
    for block in blocks:
        yield block

resp = await session.post("https://example.com/upload", body_stream=chunks())

# An async iterable — forward another response without buffering it
async def relay():
    stream = await session.send_streaming("GET", src)
    async for chunk in stream:
        yield chunk

resp = await session.post(dst, body_stream=relay())
```

A supplied `content_length` is exact: a source that ends short or runs long
fails the request. The source is single-use, so an automatic retry, a protocol
fallback, or a redirect that must preserve the body cannot replay it — recreate
the source and send again. The blocking client accepts a file-like object or a
synchronous iterable; an async iterable needs the async client.

### Streaming responses

```python
# Async
stream = await session.send_streaming("GET", "https://example.com/large-file")
async for chunk in stream:
    process(chunk)

# Or read all at once
body = await stream.bytes()
text = await stream.text()
```

### Connection prewarming

Establish TLS connections ahead of time to reduce first-request latency.

```python
# Batch prewarming
results = await session.prefetch([
    "https://api.example.com",
    "https://cdn.example.com",
])
for r in results:
    print(f"{r['url']}: {'ok' if r['success'] else r['error']} ({r['duration_ms']:.0f}ms)")

# Single-connection prewarming
await session.preconnect("https://api.example.com")

# Sync version
session.preconnect("https://api.example.com")
results = session.prefetch(["https://api.example.com"])
```

### WebSocket

```python
# Async
ws = await session.ws_connect("wss://echo.websocket.events")
await ws.send_text("hello")
msg = await ws.recv()
async for msg in ws:
    print(msg)
    break
await ws.close()

# Sync
ws = session.ws_connect("wss://echo.websocket.events")
ws.send_text("hello")
msg = ws.recv()
ws.close()
```

`send_text()`, `send_binary()` and `close()` can be called while another task (or, with the sync client, another thread) is waiting in `recv()`; closing hands that waiting `recv()` the closing handshake. Once a connection is closed, every operation on it raises `RuntimeError` and iterating it just ends.

```python
ws = await session.ws_connect(url, protocols=["chat"], extensions=["x-my-extension"])
await ws.ping(b"heartbeat")    # the pong comes back through recv(); at most 125 bytes
await ws.pong()                # an unsolicited pong
ws.url                         # still readable after close()
```

`extensions` are offered in the upgrade's `Sec-WebSocket-Extensions` header, which is part of what a browser's handshake looks like. The frames are always read and written plain, so only an extension that leaves them alone can be used: once a server accepts `permessage-deflate`, the compression Chrome offers, every compressed message it sends fails to be received.

### Proxy

```python
# Single proxy
session = client.session(proxy="socks5://user:pass@host:1080")

# Multi-hop chain: client -> hop1 -> hop2 -> target
chain = lkrequest.ProxyConfig.parse_chain([
    "socks5://user:pass@hop1:1080",
    "socks5h://user:pass@hop2:1080",
])
session = client.session(proxy=chain, http3_with_fallback=True)

# Request-level proxy override
resp = await session.get("https://example.com", proxy="http://other-proxy:8080")

# Proxy pool
pool = lkrequest.ProxyPool(
    ["socks5://proxy1:1080", "socks5://proxy2:1080", "http://proxy3:8080"],
    rotation="round_robin",  # or "random"
    bad_proxy_config=lkrequest.BadProxyConfig(
        failure_threshold=5, window=120.0, cooldown_duration=300.0, max_cooldowns=5,
    ),
    health_check=lkrequest.HealthCheckConfig(
        interval=30.0, timeout=3.0, target_host="www.google.com", target_port=443,
    ),
)
async with await pool.acquire() as lease:
    session = client.session(proxy=lease.proxy)  # a ProxyConfig, credentials included
    resp = await session.get("https://example.com")
    if resp.status_code == 403:
        lease.mark_bad()
```

A proxy URL that does not parse raises `ValueError` wherever it is given — `session(proxy=...)`, a request's `proxy=`, `ProxyConfig(...)` or a pool's list — so a typo never leaves a session quietly connecting direct.

`acquire()` hands out a `ProxyLease`. It holds one of the pool's `max_proxies` shares (default 100) until it is released — with `release()`, at the end of a `with` or `async with` block, or when it is garbage collected — so `max_proxies` caps how many proxies are in use at once, and `pool.max_concurrent` reads it back. `mark_bad()` on a lease, or `pool.mark_bad(proxy.identity())`, feeds the pool's failure counter; `acquire_fresh(lease)` does that, releases the lease and leases another proxy.

A pool that has proxies never hands back "no proxy" (which a caller would take for a direct connection): `await pool.acquire()` waits while every proxy is cooling down, so bound the wait with `asyncio.wait_for` if you need to. Only a pool created with an empty list hands out a lease whose `proxy` is `None`.

In place of the list, a pool takes a function, called for every proxy it hands out — the way to use a gateway that picks the exit by a session id in the username:

```python
pool = lkrequest.ProxyPool(
    lambda: f"http://user-session-{uuid.uuid4().hex[:8]}:pass@gateway.example:7777",
    max_proxies=50,
    proxy_buffer=20,  # optional: keep 20 proxies made ahead of time
)
```

The function returns a URL or a `ProxyConfig`, and must be a plain function rather than an `async def`. What it raises comes out of the `acquire()` that called it, and so does a `ValueError` for a URL that does not parse. Every proxy it makes is a new one, so `rotation`, `bad_proxy_config` and `health_check` do not apply: nothing is cooled down or checked. The async pools call it on a worker thread that waits for it, so keep it quick; `proxy_buffer=n` has `n` proxies made ahead of time on a thread of their own, where a failure is only logged and the function is called again a second later.

`lkrequest.blocking.ProxyPool` takes the same arguments; its `acquire()` blocks, and hands out the same `ProxyLease`, released with `release()` or a `with` block.

To check one proxy, without a pool, a client sets a tunnel up through it and says how long that took:

```python
latency = await client.check_proxy("socks5://user:pass@host:1080")   # seconds
latency = blocking_client.check_proxy(proxy, "example.com", 443, timeout=3.0)
```

Nothing is sent through the tunnel. The defaults are a pool's health check's — `www.google.com:443`, 5 seconds — and names are resolved as the client resolves them, `dns=` included. A refused or unreachable proxy raises `ProxyError`, and one too slow `TimeoutError`.

A `ProxyConfig` reads back as `host` and `port`, those of the hop that connects to the target, and `forbids_direct_fallback`, true for a MASQUE route, which never falls back to a direct connection.

TCP-based HTTP supports mixed HTTP CONNECT and SOCKS5 hops. QUIC/HTTP3 requires
every hop in the chain to be SOCKS5; a chain containing an HTTP hop falls back
to H2 when `http3_with_fallback=True`.

Credentials other than a URL's `user:pass` are set on a `ProxyConfig`; each
setter returns a new config:

```python
proxy = (
    lkrequest.ProxyConfig("http://gateway:8080")
    .with_http_auth("Bearer", "token")      # sent as-is after the scheme
    .with_auth_header("authorization")      # default: "proxy-authorization"
)
proxy = lkrequest.ProxyConfig("http://gateway:8080").with_user_pass("user", "pass")
proxy = lkrequest.ProxyConfig("http://gateway:8080").with_custom_auth(
    "account-1",                          # stable and not secret; part of identity()
    lambda: f"Bearer {tokens.fresh()}",   # called for each connection
)
```

`with_custom_auth()` is for a credential that has to be worked out for each connection. The function returns the header's value or `None`, and runs on the thread setting the connection up, which waits for it; if it raises, the connection goes without a credential and a warning is logged.

### MASQUE proxy (experimental)

> **Experimental.** MASQUE support is experimental upstream and in this binding.
> `MasqueConfig`, the `masque=` / `tunnel_probe=` parameters and how `masque://`
> routes behave may change in any release without a deprecation period, and
> interoperability has so far been checked only against test proxies, not
> against independent production MASQUE deployments. Pin the version if you
> depend on it.

Requires the `masque` feature. A `masque://` proxy (port 443 by default) carries
the QUIC connection to the target inside an RFC 9298 CONNECT-UDP tunnel, over an
HTTP/3 connection to the proxy. The target is named in the tunnel request, so
DNS is resolved proxy-side, as with `socks5h`.

```python
masque = lkrequest.MasqueConfig(
    ca_cert="proxy-ca.pem",      # or ca_cert_pem=b"...", ca_cert_der=b"...", server_name="proxy.example"
    tunnel_idle_timeout=120.0,   # None: never retire an idle tunnel
    max_idle_tunnels=256,        # 0: no cap
)
client = lkrequest.Client(quic_profile="chrome_153", masque=masque)
session = client.session(proxy="masque://proxy.example:443", http3_only=True)

# Probe MASQUE proxies in a pool with a real CONNECT-UDP tunnel. Without
# tunnel_probe they are skipped by the health check (a TCP connect proves nothing).
health = lkrequest.HealthCheckConfig(tunnel_probe=True, masque=masque)
```

- Trust for the hop to the proxy is configured only in `MasqueConfig`: the
  client's `verify` / `ca_cert*` govern the origin and are never inherited.
  `MasqueConfig(verify=False)` is for development only — anything answering on
  the proxy's address then sees every tunnel's target.
- UDP only: HTTP/1.1 and HTTP/2 requests through a MASQUE proxy raise
  `ProxyError`, and a failed tunnel never falls back to a direct connection,
  even with `proxy_fallback_direct=True`. A MASQUE proxy cannot be a chain hop.
- The connection to the proxy is not a browser fingerprint; the tunneled
  connection to the origin is. DNS-discovered ECH configs and H3 hints are not
  available on a MASQUE route (an explicit `ech_config` still applies).

### Session pool

```python
# Async
pool = lkrequest.SessionPool(client=client, proxies=[...], max_sessions=10)
guard = await pool.acquire()
async with guard as session:
    resp = await session.get("https://example.com")

# Sync
from lkrequest.blocking import Client, SessionPool
pool = SessionPool(client=client, proxies=[...])
with pool.acquire() as session:
    resp = session.get("https://example.com")
```

Both take `rotation=`, `bad_proxy_config=`, `health_check=` and `proxy_buffer=` as `ProxyPool` does, and a function in place of the list; `max_sessions` is its `max_proxies`.

### Client pool

Automatically rotate across multiple fingerprints to reduce fingerprint correlation.

```python
pool = lkrequest.ClientPool(
    [lkrequest.Client.chrome_144(), lkrequest.Client.firefox_147(), lkrequest.Client.safari_26()],
    rotation="round_robin",  # or "random"
)
client = pool.acquire()
pool.add(lkrequest.Client.chrome_131())  # add dynamically
print(len(pool))  # 4
```

### Custom fingerprints

Fully programmable TLS, HTTP/2, and TCP fingerprint configuration.

```python
# Custom TLS Profile
tls = lkrequest.TlsProfile(
    "my_browser",
    cipher_suites=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
    extensions=[
        lkrequest.ExtensionSpec(lkrequest.ExtType.SNI),
        lkrequest.ExtensionSpec(lkrequest.ExtType.ALPN),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_GROUPS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.KEY_SHARE),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_VERSIONS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SIGNATURE_ALGORITHMS),
    ],
    alpn_protocols=["h2", "http/1.1"],
    grease=lkrequest.GreaseConfig(extensions=True, key_share=True),
    padding=lkrequest.PaddingStrategy.block_align(128, 512),
    tls_client_hello_style="chromium_boringssl",  # the TLS stack's own rules: generic (default), chromium_boringssl, firefox_nss, …
    ech=lkrequest.EchMode.grease(payload_length_min=128, payload_length_max=224),  # ECH GREASE as Chrome sends it; also EchMode.real(config_list), EchMode.disabled()
)

# Custom H2 Profile
h2 = lkrequest.H2Profile(
    [
        lkrequest.H2Setting("header_table_size", 65536),
        lkrequest.H2Setting("initial_window_size", 6291456),
        lkrequest.H2Setting("max_header_list_size", 262144),
    ],
    15663105,  # window_update
    ["method", "authority", "scheme", "path"],
    headers_priority=lkrequest.HeadersPriority(0, 255, True),
    initial_stream_id=1,  # the first request's stream: odd, 1 for most browsers, 3 for Firefox 156
)
h2.validate()  # raises ValueError if it breaks a rule of HTTP/2; nothing else checks

# Custom TCP Fingerprint. These are socket settings the library asks the OS for, on
# new direct connections and the hop to the first proxy; the OS still builds the SYN,
# so window size/scale only steer the receive buffer and MSS is applied on Linux only.
tcp = lkrequest.TcpFingerprint(window_size=65535, mss=1460, window_scale=8, ttl=128)
# The SYN's option order (JA4T part B, as kind numbers) only describes the target
# and shows in to_ja4t(); keep-alive is set on the socket.
tcp = lkrequest.TcpFingerprint(
    window_size=64240, tcp_options=[2, 1, 3, 1, 1, 4], mss=1460, window_scale=8,
    keepalive_idle=30.0, keepalive_interval=5.0,
)
tcp.to_ja4t()   # "64240_2-1-3-1-1-4_1460_8"
tcp.to_dict()   # every setting, None where the OS decides
lkrequest.TcpFingerprint.safari_ios(), lkrequest.TcpFingerprint.none()

# Combine them
client = lkrequest.Client(tls_profile=tls, h2_profile=h2, tcp_fingerprint=tcp)

# Serialize / deserialize
json_str = tls.to_json()
restored = lkrequest.TlsProfile.from_json(json_str)

# Fingerprint randomization: a copy whose TLS profile shuffles its extensions per
# connection; every other option of the client carries over
randomized = client.randomize_fingerprint(shuffle_extensions=True)

# Randomization strategy (Randomize): pass to Client(randomize=...)
# Tier 1 (always available): permute TLS extension order per connection, drift JA3 but stay a real browser
client = lkrequest.Client(tls_profile="chrome_146",
                          randomize=lkrequest.Randomize.extension_order())

# Tier 3a/3b (requires the synthetic-fp feature): synthesize a cross-layer unique identity per session
#   from lkrequest import Randomize, Layers
#   client = lkrequest.Client(tls_profile="chrome_146",
#                             randomize=Randomize.recombine())                 # all layers
#   client = lkrequest.Client(tls_profile="chrome_146",
#                             randomize=Randomize.recombine_layers(Layers.TLS | Layers.H2))
```

### Fingerprint consistency validation

```python
result = lkrequest.validate_fingerprint_consistency(
    tls_profile="chrome_144", h2_profile="chrome_144", tcp_fingerprint="chrome_win",
)
print(result["valid"])     # True
print(result["warnings"])  # []
```

### Timeout configuration

```python
# Client-level timeouts
client = lkrequest.Client(
    dns_timeout=5.0,
    tcp_connect_timeout=10.0,
    tls_handshake_timeout=10.0,
    ttfb_timeout=15.0,
    total_timeout=30.0,
)

# Request-level timeout override
resp = session.get("https://example.com", timeout=5.0)
```

### AcceptEncoding control

```python
ae = lkrequest.AcceptEncoding

# Session level
session = client.session(accept_encoding=ae.GZIP | ae.BR)

# Request level
resp = session.get(url, accept_encoding=ae.GZIP)

# Disable automatic decompression
resp = session.get(url, no_decompress=True)
```

### Header / Cookie order

`header_order` (header send order) and `cookie_order` (ordering within the `Cookie` header) can be set at three levels, with lower levels overriding higher ones:

```python
# Client level (applies to all sessions of this client)
client = lkrequest.Client(
    header_order=["host", "user-agent", "accept", "accept-encoding", "cookie"],
    cookie_order=["session_id", "csrf_token"],
)

# Session level (overrides client level)
session = client.session(
    header_order=["host", "user-agent", "accept"],
    cookie_order=["session_id", "csrf_token"],
)

# Request level (overrides session and client levels)
resp = await session.get(
    url,
    header_order=["host", "user-agent", "accept"],
    cookie_order=["session_id", "csrf_token"],
)
```

### Ordered / duplicate headers, params, data

`headers`, `params`, and `data` accept either a `dict` (preserves insertion order) or a
`list[tuple[str, str]]` (preserves order and allows duplicate keys, for repeated params like `?tag=a&tag=b`):

```python
# Duplicate query params: ?tag=a&tag=b
resp = session.get(url, params=[("tag", "a"), ("tag", "b")])

# Duplicate form fields
resp = session.post(url, data=[("k", "1"), ("k", "2")])

# Explicit header ordering (a dict is also sent in insertion order)
resp = session.get(url, headers=[("user-agent", "..."), ("accept", "*/*")])
```

### base_url, generic request(), connection pool cleanup

```python
# base_url: relative paths are auto-joined; passing an absolute URL overrides base_url
session = client.session(base_url="https://api.example.com")
resp = await session.get("/v1/users", params={"page": "1"})

# Generic request(): specify the method explicitly (any case)
resp = await session.request("PATCH", "/v1/users/1", json={"name": "x"})

# Only allow redirects to HTTPS; clear the connection pool
session = client.session(https_only=True)
session.pool_clear()
```

### HSTS / http→https upgrade policy

Browsers upgrade `http://` requests to `https://` before connecting for known HSTS (or preloaded)
hosts. The default (no `hsts`) is a stateless "first visit" that performs no upgrade. Host matching
is suffix-based (equivalent to HSTS `includeSubDomains`).

```python
# Dynamically learn HSTS hosts from response Strict-Transport-Security headers (like a long-running browser)
hsts = lkrequest.Hsts.dynamic()
session = client.session(hsts=hsts)
other = client.session(hsts=hsts)     # shares what `session` learns, as one browser profile does
hsts.should_upgrade("example.com")    # what a session would decide now

# Seed known HSTS hosts (e.g. replay state learned in a previous session)
session = client.session(hsts=lkrequest.Hsts.dynamic(seed=["example.com"]))

# Fixed allowlist; preloaded_tlds=True also upgrades Chrome's fully-preloaded gTLDs (.dev/.app/…)
session = client.session(hsts=lkrequest.Hsts.static_(["example.com"], preloaded_tlds=True))

# A policy of your own; record_sts(host, header) is optional
session = client.session(hsts=lkrequest.Hsts.custom(lambda host: host.endswith(".internal")))
```

The functions of `Hsts.custom()` run on the thread running the request, which waits for them: `should_upgrade` for each `http://` URL, and `record_sts` for each `Strict-Transport-Security` header received over HTTPS from a host that is not an IP address. They must be plain functions; one that raises is logged as a warning, and the URL is not upgraded.

### Request-level protocol override

```python
# Each request can override session-level protocol policy / intent, plus HTTP/3-specific header order
resp = await session.get(
    url,
    protocol_policy=lkrequest.ProtocolPolicy.chrome_conservative(),
    http_intent=lkrequest.HttpIntent.H2Only,
    h3_header_order=["host", "user-agent", "accept"],
)
```

`h3_header_order` can also be set on `Client(...)` and `session(...)` (same three levels as `header_order`).

A policy has four axes — the intent, how a new connection is acquired, whether to upgrade to HTTP/3, and whether to fall back from it — each of which can be read and replaced on a copy:

```python
policy = (
    lkrequest.ProtocolPolicy.chrome_conservative()
    .with_acquisition(lkrequest.RacePolicy(tcp_delay=0.1))   # or AcquisitionPolicy.EstablishBestAvailable
    .with_upgrade(lkrequest.UpgradePolicy.ProbeOnly)
    .with_fallback(lkrequest.FallbackPolicy.NoFallback)
)
policy.acquisition, policy.upgrade, policy.fallback
```

A `RacePolicy` races TCP against QUIC; what it leaves out keeps `RacePolicy.chrome_like()`, which starts QUIC at once and TCP 0.3 s later, for an origin that has advertised HTTP/3. Axes that contradict one another — an H3-only intent that falls back, a race of neither TCP nor QUIC — raise `ValueError` from `policy.validate()`, and from the client, session or request the policy is given to, before anything is sent.

### Prometheus metrics

```python
collector = lkrequest.enable_metrics()

# View stats after making requests
stats = collector.snapshot()
print(collector.prometheus_text())
collector.reset()
```

### Request diagnostics & runtime metrics

`response.diagnostics` returns per-request phase timings (no OpenTelemetry dependency, collected directly by the Rust engine):

```python
resp = await session.get("https://example.com")
print(resp.diagnostics)
# {'dns_ms': 3, 'tcp_ms': 0, 'tls_ms': 423, 'ttfb_ms': 193, 'total_ms': 621,
#  'remote_addr': '93.184.216.34:443', 'protocol': 'h2', 'cipher_suite': '0x1301'}
# dns_ms/tcp_ms/tls_ms are None on a reused connection (that phase did not occur)
```

`diagnostics["trust_anchor"]` describes the [Trust Anchor Identifiers](#trust-anchor-identifiers) negotiation of the TLS connection a request opened, and is `None` on a reused one.

`metrics_snapshot()` pulls process-level runtime counters for you to feed into your own Prometheus / OTel pipeline:

```python
snap = lkrequest.metrics_snapshot()
# {'bytes_in': ..., 'bytes_out': ..., 'requests_total': ...,
#  'requests_failed': ..., 'active_connections': ..., 'total_connections': ...}
```

> Counters are all 0 by default; only building with the `telemetry` feature (`maturin build --features telemetry`) enables transport-layer byte counting.

### Draining before shutdown

A result that arrives after its event loop has closed has nowhere to go and is dropped. If requests may still be running when you tear the loop down, wait for them:

```python
await lkrequest.drain_pending()            # wait indefinitely
await lkrequest.drain_pending(timeout=5)   # -> False if it did not finish in time
lkrequest.pending_requests()               # how many are still in flight
lkrequest.blocking_drain_pending(5)        # same, outside an event loop
```

Counts are process-wide and cover every async call, not just requests. Cancelling a request releases it immediately — the underlying work is abandoned, not awaited.

### Certificate management

```python
client = lkrequest.Client(ca_cert="/path/to/ca.pem")       # file path
client = lkrequest.Client(ca_cert_pem=pem_bytes)            # PEM bytes
client = lkrequest.Client(ca_cert_der=der_bytes)            # DER bytes
client = lkrequest.Client(verify=False)                      # disable verification (dev only)
client = lkrequest.Client(use_native_certs=True)             # system certificates
client = lkrequest.Client(ech_config=ech_bytes)              # ECH support
```

### Trust Anchor Identifiers

Chrome 152 and later tell the server which roots they accept, as IDs in the `trust_anchors` ClientHello extension (`0xca34`, draft-ietf-tls-trust-anchor-ids), so that it can pick a certificate chain ending in one of them. `Client.chrome_155()` to `Client.chrome_157()`, and so the default fingerprint, send their 28 IDs in one fixed, sorted order, as those Chrome versions do; the Chrome 152 to 154 presets shuffle them on every handshake. Three client options change what is sent and what happens next:

```python
root = open("private-root.der", "rb").read()
client = lkrequest.Client(
    tls_profile="chrome_157",
    h2_profile="chrome_157",
    ca_cert_der=root,
    trust_anchor_advertisement="trusted",  # the sorted IDs of the roots this client trusts
    trust_anchor_recovery="once",          # one more try with an ID the server names
    trust_anchor_bindings={"81fd5901": lkrequest.trust_anchor_identity(root)},
)
```

- `trust_anchor_advertisement`: `"profile"` (the default) sends the IDs the TLS profile lists, in its order; `"trusted"` sends the sorted IDs of the roots this client trusts instead: the bundled IDs of Chrome 157's root store for the roots that have one, plus `trust_anchor_bindings`.
- `trust_anchor_recovery`: with `"once"`, when a server lists the IDs it can serve and then its certificate chain fails to verify, or it ends the handshake, the client opens one more connection asking for the first of those IDs it trusts. That happens at most once per request, sends no HTTP bytes on the rejected connection and turns 0-RTT off; it needs `verify` on and cannot be combined with `proxy_fallback_direct=True`. `"disabled"` is the default.
- `trust_anchor_bindings`: `{id: anchor_identity}` for roots of your own, the ID in hex as your CA assigned it, bound to `lkrequest.trust_anchor_identity(root_der)`. The root still has to be loaded with `ca_cert*`.

The IDs never change which certificates are trusted. Only the profiles that have the extension (Chrome 152–157) accept `"trusted"` or `"once"`, and TLS synthesis (`Randomize.recombine()` / `Randomize.full()`) refuses them; a setting upstream rejects raises `ValueError`. `diagnostics["trust_anchor"]` shows what a new connection requested, what the server offered, which root verified it and, after a recovery, the first attempt.

### DNS

```python
client = lkrequest.Client(dns="cloudflare")         # or "google", "quad9", "cloudflare_https", ...
client = lkrequest.Client(dns="192.168.1.1")        # a DNS server of your own, port 53
client = lkrequest.Client(dns="[2606:4700::1111]:53")
```

`dns` defaults to `"system"`, the operating system's resolver. The named public resolvers are asked over UDP (and TCP for long answers), the `*_https` variants over DNS-over-HTTPS (the `doh` build feature). Any other value is the address of a DNS server, `"ip"` for port 53 or `"ip:port"`, an IPv6 address with a port in brackets. A DNS server, unlike the system resolver, also answers HTTPS records, which is how the client learns a site's ECH configuration and HTTP/3 support from DNS.

`dns` may also be Python code that looks names up:

```python
def resolve(host: str, port: int) -> list[str]:
    return ["192.0.2.10"]        # each an IP, or "ip:port" to dial another port

client = lkrequest.Client(dns=resolve)

class Resolver:                  # or an object, which may answer HTTPS records too
    def resolve(self, host, port):
        return ["192.0.2.10"]

    def lookup_https(self, host):   # optional; None for no record
        return {"alpn": ["h3", "h2"], "ech_config_list": ech_bytes}

client = lkrequest.Client(dns=Resolver())
```

A record may hold `alpn`, `no_default_alpn`, `target`, `port`, `ech_config_list`, `ipv4_hints` and `ipv6_hints`. The code must be synchronous — an `async def` raises `TypeError` — and runs on a thread of the runtime's blocking pool, so a slow lookup holds up no other request. `dns_timeout` bounds each call and `ip_family` filters the answers. What `resolve` raises becomes the `__cause__` of the request's `ConnectionError`, so its traceback shows where it failed; a failing `lookup_https` is logged and counts as no record.

### Address family

On a dual-stack host the OS resolver orders IPv6 first, so a target with an AAAA
record is reached over IPv6 whenever IPv6 works. `ip_family` pins it, which
matters when a session must present one source address to the target rather than
leaving over two different families:

```python
client = lkrequest.Client(ip_family="ipv4")   # never IPv6
client = lkrequest.Client(ip_family="ipv6")   # never IPv4
client = lkrequest.Client(ip_family="any")    # resolver's own order (default)
```

An address outside the family raises rather than falling back — not even to a
direct connection under `proxy_fallback_direct=True` — so the setting cannot be
defeated silently. `"ipv6"` also refuses IPv4-mapped addresses
(`::ffff:a.b.c.d`). The setting covers every address **this process** picks:

| Case | With `ip_family="ipv4"` |
|---|---|
| Direct connection | IPv4 only; a host with no A record fails |
| The proxy's own address, a SOCKS5 UDP relay | IPv4 only |
| `socks5://` target (resolved locally) | IPv4 only |
| HTTP `CONNECT`, `socks5h://` or MASQUE, hostname target | resolved by the proxy, which may still dial IPv6 |
| The resolver's own DNS / DoH queries | not restricted |

To choose what a proxy dials, map the origin to an address with `connect_to`:

```python
client = lkrequest.Client(
    ip_family="ipv4",
    connect_to={"example.com:443": "192.0.2.1:443"},  # IPv6 as "[2001:db8::1]:443"
)
session = client.session(proxy="http://proxy.example:8080")
# The proxy receives `CONNECT 192.0.2.1:443`; TLS SNI, certificate checks,
# the Host header and cookies still use example.com.
```

The mapping is fixed — nothing re-resolves or refreshes it. It applies to direct,
proxied and HTTP/3 connections alike, ahead of Alt-Svc / SVCB endpoints, and
never to the proxy's own address. It pins the target the proxy dials, not the
proxy provider's public egress address; behind a proxy `diagnostics["remote_addr"]`
is the proxy's address, so check the egress with the target's own echo.

### Zero-copy Response

```python
resp = session.get("https://example.com")

mv = memoryview(resp)       # zero-copy access to body
text = resp.text()          # cached after first decode
data = resp.json()          # cached after first parse
```

### Text decoding

`text()` decodes with the charset from `Content-Type`, falling back to UTF-8
when the response declares none. Malformed bytes become U+FFFD instead of
raising, so a single bad byte never costs you the whole body — reach for
`content` when the exact bytes matter.

```python
resp = session.get("https://example.com")   # Content-Type: text/html; charset=gbk
resp.encoding                               # 'gbk'
resp.text()                                 # decoded as GBK

resp.text(encoding="latin-1")               # override a missing or wrong charset
```

A charset from the header is resolved the way a browser resolves it, against
the WHATWG Encoding Standard. An `encoding=` argument goes to Python's codec
registry instead, so Python spellings the web standard does not list
(`latin-1`, `utf-8-sig`, `cp936`) work as written.

A leading BOM is stripped, and a BOM that contradicts the declared charset is
believed over it — again the browser rule. So a `charset=gbk` response whose
body opens with a UTF-8 BOM decodes as UTF-8, and `text()` never hands back the
invisible U+FEFF that breaks `json.loads` and `startswith`.

A streaming response's `text()` decodes the same way and takes the same
`encoding=` argument (`await stream.text(encoding="gbk")` on the async client).

### Logging

```python
lkrequest.set_log_level("info")                          # global level
lkrequest.set_log_level("lkrequest=debug,lktls=trace")   # module filter
lkrequest.set_log_level("info", format="compact")        # log format
lkrequest.set_log_level("off")                           # disable
lkrequest.set_log_level("debug", format="logging")       # to Python's logging
```

Only the first call in a process takes effect; later ones return `False`. `"compact"`, `"full"` and `"json"` write to stderr. `"logging"` hands every event that passes the level to Python's `logging`, on the logger `lkrequest.` followed by the event's Rust target (`lkrequest.lkrequest.session`, `lkrequest.lktls.handshake`), so configuring `logging.getLogger("lkrequest")` covers them all. The level given here decides what is passed on at all, so keep it as narrow as you need: the loggers' own levels and handlers only apply after that. The events are queued and passed on from a thread of their own, so a request never waits for the GIL to log; a queue that fills up drops events.

### Error handling

```python
try:
    resp = session.get(url, timeout=10.0)
    resp.error_for_status()
except lkrequest.LkTimeoutError:
    print("timed out")
except lkrequest.LkConnectionError:
    print("connection failed")
except lkrequest.TlsError:
    print("TLS error")
except lkrequest.HttpStatusError as e:
    print(f"HTTP error: {e}")
except lkrequest.TooManyRedirectsError:
    print("too many redirects")
except lkrequest.RequestError as e:
    print(f"request error: {e}")
```

Every `RequestError` also says what the Rust library knows about the failure:

```python
except lkrequest.RequestError as e:
    e.phase             # "tcp_connect", "proxy_tunnel", "tls_handshake", ... or None
    e.retryable         # whether trying again could succeed
    e.safe_to_replay    # whether the server cannot have processed it, so even a POST can be resent
    e.status_code       # HttpStatusError: the status
    e.proxy_error_kind  # ProxyError: "authentication_required", "tunnel_refused", ...
    e.tls_alert         # TlsError: the alert the handshake ended in, e.g. "handshake_failure"
    e.diagnostics       # the timings and transport so far, as Response.diagnostics gives them
```

An attribute that does not apply is `None` (`False` for the two flags), on an error built by hand as well. `diagnostics` comes with a failed request of the HTTP methods or `request()`, and with `error_for_status()`; not with a streamed request, a WebSocket or `preconnect()`.

## Available Browser Fingerprints

| Method | TLS | HTTP/2 | TCP |
|------|-----|--------|-----|
| `Client.chrome_131()` | Chrome 131 | Chrome 131 | Chrome |
| `Client.chrome_144()` | Chrome 144 | Chrome 144 | Chrome |
| `Client.chrome_145()` | Chrome 145 | Chrome 145 | Chrome |
| `Client.chrome_146()` | Chrome 146 | Chrome 146 | Chrome |
| `Client.chrome_147()` | Chrome 147 | Chrome 147 | Chrome |
| `Client.chrome_148()` | Chrome 148 | Chrome 148 | Chrome |
| `Client.chrome_149()` | Chrome 149 | Chrome 149 | Chrome |
| `Client.chrome_150()` | Chrome 150 | Chrome 150 | Chrome |
| `Client.chrome_151()` | Chrome 151 | Chrome 151 | Chrome |
| `Client.chrome_152()` | Chrome 152 | Chrome 152 | Chrome |
| `Client.chrome_153()` | Chrome 153 | Chrome 153 | Chrome |
| `Client.chrome_154()` | Chrome 154 | Chrome 154 | Chrome |
| `Client.chrome_155()` | Chrome 155 | Chrome 155 | Chrome |
| `Client.chrome_156()` | Chrome 156 | Chrome 156 | Chrome |
| `Client.chrome_157()` | Chrome 157 | Chrome 157 | Chrome |
| `Client.firefox_133()` | Firefox 133 | Firefox 133 | Firefox |
| `Client.firefox_147()` | Firefox 147 | Firefox 147 | Firefox |
| `Client.firefox_156()` | Firefox 156 | Firefox 156 | Firefox |
| `Client.safari_18()` | Safari 18 | Safari 18 | Safari |
| `Client.safari_26()` | Safari 26 | Safari 26 | Safari |

A client built without `tls_profile=` / `h2_profile=` (plain `Client()`) uses the Chrome 155 TLS and HTTP/2 fingerprints, without a TCP fingerprint or QUIC / HTTP3 profile. Pin a version explicitly if the default changing between releases would matter to you.

TCP fingerprints are OS-specific: `chrome_win` / `chrome_linux` / `chrome_macos` / `firefox_win` / `firefox_linux` / `firefox_macos` / `safari`

Firefox 156 opens its first HTTP/2 request on stream 3 and sends navigation HEADERS with weight 41; every other preset starts on stream 1.

Only the Chrome presets carry a QUIC / HTTP3 fingerprint (with the `quic-h3` feature). The Firefox and Safari presets turn HTTP/3 off, and building with `quic-h3` does not change that.

A preset sets the header **order**, not header values: a request from `Client.chrome_155()` carries no `User-Agent`, `Accept` or other browser headers unless you set them, through `default_headers=` or per request.

## API Reference

### Client

| Parameter | Description |
|------|------|
| `tls_profile` | TLS fingerprint (string name or `TlsProfile` object) |
| `h2_profile` | HTTP/2 fingerprint (string name or `H2Profile` object) |
| `tcp_fingerprint` | TCP fingerprint (string name or `TcpFingerprint` object) |
| `default_headers` | Default request headers, as a `dict` or a list of `(name, value)` pairs. They go on the wire in the order given wherever `header_order` does not place them. A redirect that leaves the origin does not carry along a default `Authorization`, `Cookie` or `Host`, and one from https to http drops a default `Referer` |
| `header_order` | Header send order |
| `cookie_order` | Cookie send order |
| `http1_title_case_headers` | Spelling of HTTP/1.1 header names: `True` (the default) sends `Content-Type`, `False` sends `content-type` but keeps `Host` capitalized, including generated headers. The spelling a header was given in is not kept; HTTP/2 and HTTP/3 always send lowercase names |
| `dns_timeout` / `tcp_connect_timeout` / `tls_handshake_timeout` / `ttfb_timeout` / `total_timeout` / `quic_connect_timeout` | Timeout control |
| `max_response_body_size` / `max_connections_per_session` / `max_header_count` / `max_header_size` / `max_headers_total_size` / `min_transfer_rate`(+ `min_transfer_rate_window`) | Resource limits / DoS protection |
| `max_pending_h2_requests` | Cap HTTP/2 requests queued for a remote stream slot (default: unbounded) |
| `h2_fallback_h1` / `proxy_fallback_direct` / `retry_on_connection_close` | Fault-tolerance options |
| `h2_dispatch_batch_size` | Ready HTTP/2 requests coalesced into one driver write turn (default: 1) |
| `h2_data_frame_policy` | How request bodies are split into HTTP/2 DATA frames (`H2DataFramePolicy`) |
| `require_close_notify` | Reject a body truncated without a TLS close_notify alert (default: `False`) |
| `tls_session_resumption_policy` / `tls_session_cache_partition_policy` | Whether TLS tickets are stored, and how the ticket cache is keyed |
| `middleware` | Middleware list |
| `ca_cert` / `ca_cert_pem` / `ca_cert_der` / `verify` / `use_native_certs` | Certificate configuration |
| `trust_anchor_advertisement` / `trust_anchor_recovery` / `trust_anchor_bindings` | [Trust Anchor Identifiers](#trust-anchor-identifiers): which IDs to send, one more try with an ID the server names, IDs for roots of your own |
| `ech_config` | ECH configuration |
| `dns` | Where names are looked up: `"system"` (default), `"google"`, `"cloudflare"`, `"quad9"`, their `"*_https"` DoH variants, a DNS server as `"ip"` / `"ip:port"`, or Python code; see [DNS](#dns) |
| `ip_family` | Restrict connections to one address family: `"any"` (default), `"ipv4"`, `"ipv6"` |
| `connect_to` | Dial a fixed address for an origin, `{"host:port": "ip:port"}`; TLS, `Host` and cookies keep the original name |
| `system_dns_cache_ttl` / `system_dns_cache_max_entries` | Cache successful OS-resolver lookups for `ttl` seconds (TTL `0` disables caching but keeps in-flight coalescing; cannot be combined with `dns`) |
| `keylog` | TLS secrets in the NSS key log format Wireshark reads: a file path to append them to, or a function called with each line on the thread doing the handshake |
| `masque` | `MasqueConfig` for the hop to a `masque://` proxy (requires the `masque` feature) |

| Method | Description |
|------|------|
| `session(...)` | Create a session (`network_partition_context=...` partitions the TLS ticket cache per site; `h3_retry_mode=...` selects HTTP/3 retries, see Features) |
| `fingerprint_info()` | Return a fingerprint info dict |
| `randomize_fingerprint(shuffle_extensions=True)` | Return a copy of the Client whose TLS profile shuffles its extensions per connection; every other option carries over |
| `get(url, **kwargs)` / `post` / `put` / `delete` / `head` / `patch` / `options` | `session().get(url, **kwargs)` and so on: the request from a session made for the call and dropped after it, so no connection or cookie is kept from one call to the next. For more than one request, make a session |
| `check_proxy(proxy, target_host="www.google.com", target_port=443, timeout=5.0)` | Set a tunnel up through a proxy and return the seconds it took; see [Proxy](#proxy) |
| `tls_profile` / `h2_profile` / `tcp_fingerprint` / `default_headers` / `header_order` / `h3_header_order` / `cookie_order` / `timeouts` / `resource_limits` / `protocol_policy` / `verify` / `ip_family` / `h2_fallback_h1` / `proxy_fallback_direct` / `max_pending_h2_requests` / `ech_config` | Read-only: what the client was built with, a preset applied and the defaults included, mostly under the name of the argument that sets each. `timeouts` and `resource_limits` are dicts keyed by those names |

### Session

All HTTP methods (get/post/put/delete/head/patch/options) support:

| Parameter | Description |
|------|------|
| `headers` | Request headers |
| `params` | URL query params |
| `json` / `data` / `body` / `multipart` | Request body |
| `cookies` / `cookie_override` | Cookies for this request, as a `dict` or a list of `(name, value)` pairs. They follow the session's own cookies in the order given, overrides last; `cookie_override` drops the session's cookies of the same name, and a name given twice in `cookies` is sent twice |
| `timeout` | Request timeout (seconds) |
| `bearer_auth` / `basic_auth` | Authentication |
| `proxy` | Request-level proxy override |
| `no_decompress` / `accept_encoding` | Encoding control |
| `priority` / `h2_priority_weight` | RFC 9218 request priority / the weight (0–255) in an HTTP/2 HEADERS frame's legacy priority field |

| Method | Description |
|------|------|
| `send_streaming(method, url, ...)` | Streaming request, with the same parameters as the HTTP methods |
| `ws_connect(url, *, headers, protocols)` | WebSocket connection |
| `preconnect(url)` / `preconnect_many(urls)` / `prefetch(urls)` | Connection prewarming |
| `pool_stats()` / `pool_clear()` | Connection pool stats (`PoolStats`) / close all pooled connections, keeping the session usable |
| `close()` / `closed` | Close the session and release what it holds; also `with session` (blocking) and `async with session`. See [Session lifecycle and memory](#session-lifecycle-and-memory) |
| `on_request(callback)` / `on_response(callback)` | Register event hooks |
| `set_cookie()` / `set_cookie_with_attrs()` / `set_cookie_raw()` | Set cookies |
| `get_cookie()` / `get_cookies()` / `get_cookie_values()` / `cookie_header()` | Read cookie names and values |
| `get_cookies_with_attrs()` / `get_all_cookies()` | Read cookies as `Cookie` objects, with attributes |
| `remove_cookie()` / `clear_cookies()` | Remove cookies |

### Response

| Attribute/Method | Description |
|-----------|------|
| `status_code` | HTTP status code |
| `ok` | status code < 400 |
| `url` | Final URL |
| `version` | HTTP version (`HttpVersion.H2` / `HttpVersion.HTTP11`) |
| `headers` | Response headers (`HeaderMap`, case-insensitive) |
| `headers_list` | Response headers list (`list[tuple[str, str]]`) |
| `content` | Raw bytes |
| `content_length` | Content-Length |
| `text(encoding=None)` | Decoded text, using the declared charset (cached) |
| `json()` | Parse JSON (cached); raises `JsonDecodeError` |
| `cookies` | Response cookies |
| `encoding` | Charset declared in `Content-Type` |
| `elapsed` | Request duration (seconds) |
| `diagnostics` | Per-phase timing dict: `dns_ms`/`tcp_ms`/`tls_ms`/`ttfb_ms`/`total_ms` + `remote_addr`/`protocol`/`cipher_suite` (None for phases not measured) + `trust_anchor`, the trust-anchor negotiation of a connection the request opened |
| `was_redirected` | Whether it went through a redirect |
| `history` | Redirect chain (`list[RedirectRecord]`) |
| `error_for_status()` | Raise `HttpStatusError` on 4xx/5xx |
| `memoryview(resp)` | Zero-copy access to body |
| `len(resp)` / `bool(resp)` | Length / success |

### HeaderMap

| Method | Description |
|------|------|
| `headers["name"]` | Get header (KeyError if missing) |
| `headers.get("name", default)` | Get header (returns default if missing) |
| `headers.get_all("name")` | Get all headers with that name |
| `"name" in headers` | Check existence |
| `len(headers)` | Header count |
| `headers.keys()` / `values()` / `items()` | Iterate |
| `headers.to_dict()` | Convert to a dict |

### Fingerprint configuration

| Class | Description |
|----|------|
| `TlsProfile` | TLS fingerprint config; presets / custom / JSON serialization |
| `H2Profile` | HTTP/2 fingerprint config (SETTINGS, window update, pseudo-header order, priority, `initial_stream_id`) |
| `TcpFingerprint` | TCP fingerprint config; supports JA4T format |
| `ExtType` | TLS extension type constants |
| `ExtensionSpec` | TLS extension spec |
| `GreaseConfig` | GREASE injection config |
| `PaddingStrategy` | Padding strategy (`block_align` / `fixed_target` / `no_padding`) |
| `RandomizationConfig` | Fingerprint randomization config |
| `H2Setting` | HTTP/2 setting (string name or integer ID) |
| `HeadersPriority` | Headers priority |
| `PriorityFrame` | Priority frame |
| `ClientPool` | Client pool, multi-fingerprint rotation |

### Module functions

| Function | Description |
|------|------|
| `set_log_level(level, *, format="compact")` | Set the log level |
| `enable_metrics()` | Enable Prometheus metrics, returns a `MetricsCollector` |
| `metrics_snapshot()` | Pull a process-level runtime counter dict (real values require the `telemetry` feature) |
| `validate_fingerprint_consistency(...)` | Validate fingerprint-combination consistency |
| `features()` | Which optional features this build has, as `{"quic-h3": True, ...}` by Cargo name; the PyPI wheels have them all |
| `list_presets()` | The browser presets, each `{"name": "chrome_155", "browser": "chrome", "http3": True}`; a name is what `Client.<name>()`, `tls_profile=` and `h2_profile=` take |
| `trust_anchor_identity(der)` | The identity of a DER root certificate, to bind a trust anchor ID to with `Client(trust_anchor_bindings=...)` |

### Exceptions

| Exception | Description |
|------|------|
| `RequestError` | Base class |
| `TlsError` | TLS handshake failure |
| `ProxyError` | Proxy connection failure |
| `HttpStatusError` | HTTP status error (4xx/5xx) |
| `LkConnectionError` | Connection failure |
| `LkTimeoutError` | Timeout |
| `TooManyRedirectsError` | Too many redirects |
| `ResourceLimitError` | Resource limit exceeded |
| `JsonDecodeError` | `json()` got a body that is not JSON (also a `json.JSONDecodeError`) |

All of them carry `phase`, `retryable`, `safe_to_replay`, `status_code`, `proxy_error_kind`, `tls_alert` and `diagnostics`; see [Error handling](#error-handling).

## Examples

The `examples/` directory contains complete examples for every feature:

| Example | Description |
|------|------|
| `basic_requests.py` | Basic sync/async GET/POST usage, concurrent requests |
| `http_methods.py` | GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS |
| `authentication.py` | Bearer Token / Basic Auth |
| `response_inspection.py` | All Response attributes, HeaderMap, memoryview, redirect history |
| `cookie_management.py` | Cookie CRUD, set_cookie_with_attrs, cookie_override |
| `multipart_upload.py` | Multipart text + file upload, fine-grained Part control |
| `websocket.py` | Sync/async WebSocket, WsMessage types |
| `middleware.py` | Request/response interception, header injection, multi-layer onion model |
| `retry_strategies.py` | ExponentialBackoff / FixedInterval / callable / lambda |
| `event_hooks.py` | on_request/on_response callbacks |
| `proxy_pool.py` | Single proxies, multi-hop chains, BadProxyConfig, HealthCheckConfig, ProxyPool, proxies from a function |
| `session_pool.py` | SessionPool / BlockingSessionPool |
| `client_pool.py` | ClientPool multi-fingerprint rotation |
| `browser_fingerprints.py` | 6 preset fingerprints, string specification, fingerprint randomization |
| `custom_fingerprint.py` | Fully custom TlsProfile / H2Profile / TcpFingerprint |
| `fingerprint_validation.py` | validate_fingerprint_consistency |
| `streaming_response.py` | StreamingResponse chunked / full reads |
| `streaming_upload.py` | body_stream file-like / generator / async iterable, content_length |
| `connection_prewarming.py` | preconnect / preconnect_many / prefetch |
| `metrics.py` | enable_metrics / snapshot / prometheus_text |
| `timeout_config.py` | Client- and request-level timeouts, resource limits |
| `accept_encoding.py` | AcceptEncoding control, no_decompress |
| `certificate_config.py` | CA cert PEM/DER/file, verify, ECH |
| `ip_family.py` | `ip_family=` address-family selection, offline and against a live dual-stack host |
| `logging_config.py` | set_log_level, filter directives |
| `error_handling.py` | All exception types, general error-handling patterns |
| `pool_stats.py` | PoolStats connection pool statistics |
| `redirect_history.py` | Redirect chain, RedirectRecord |

Run an example:

```bash
maturin develop
python examples/basic_requests.py
```

## Testing

Using venv and pip:

```bash
# After completing the development setup above, run all tests
just test

# Or manually
python -m pip install -e ".[test]"
python -m pytest tests/ -v

# Run only the unit tests that don't need network
python -m pytest tests/ -v -k "not httpbin and not echo"
```

Using uv:

```bash
uv sync --extra test --extra lint
just test
# Or:
uv run pytest tests/ -v
```

## Benchmark

```bash
maturin develop --release
python benchmarks/bench_latency.py     # single-request latency
python benchmarks/bench_throughput.py   # concurrent throughput
python benchmarks/bench_memory.py      # memory usage
python benchmarks/verify_fingerprint.py # TLS fingerprint verification
```
