# lkrequest

A Python HTTP client with TLS/HTTP2/TCP fingerprint control. Powered by Rust for high performance.

[English](https://github.com/EZ-XLabs/lkrequest-py/blob/main/README.md) | [简体中文](https://github.com/EZ-XLabs/lkrequest-py/blob/main/README-zh.md)

## Features

- **Browser fingerprint emulation** — TLS/HTTP2/TCP fingerprint presets for Chrome, Firefox, and Safari
- **Custom fingerprints** — Fully programmable `TlsProfile` / `H2Profile` / `TcpFingerprint`, with JSON serialization
- **Fingerprint randomization** — `Client(randomize=Randomize.extension_order())` permutes TLS extension order per connection (drifts JA3, keeps JA4 stable, still a real browser); `client.randomize_fingerprint()` generates a unique variant to reduce correlation risk
- **Client pool** — `ClientPool` automatically rotates across multiple fingerprints
- **Async & sync APIs** — Both `asyncio` async and traditional synchronous calls
- **WebSocket** — wss:// connections with consistent fingerprinting
- **Streaming responses** — `send_streaming()` receives large files chunk by chunk
- **Cookie management** — Automatic cookie jar, with manual management, attribute setting, and overrides
- **Proxy support** — HTTP CONNECT / SOCKS5 proxies, authentication, and ordered multi-hop chains; QUIC/H3 works over all-SOCKS5 chains
- **Proxy pool & session pool** — Built-in proxy rotation, bad-proxy marking, and session management
- **Multipart** — File upload support
- **Retry strategies** — Exponential backoff / fixed interval / custom callable retries
- **Middleware** — Request/response interception and modification (onion model)
- **Event hooks** — Lightweight request/response callbacks
- **Connection prewarming** — `preconnect()` / `prefetch()` to batch-establish connections
- **Prometheus metrics** — Built-in request counters, latency histograms, exposition-format export
- **Request diagnostics** — `response.diagnostics` exposes per-request phase timings (DNS/TCP/TLS/TTFB/total) plus remote_addr/protocol/cipher_suite
- **Runtime metrics snapshot** — `metrics_snapshot()` pulls process-level wire bytes / connection / request counters (for host-side collection; real values require the `telemetry` feature)
- **Zero-copy Response** — `bytes::Bytes` + PyBuffer protocol + text/json caching
- **Automatic decompression** — Brotli / gzip / deflate / zstd, with controllable `AcceptEncoding`
- **Certificate management** — Custom CA / disable verification / system certificates
- **ECH** — Encrypted Client Hello support, including TLS/QUIC HelloRetryRequest handling
- **Request priority** — `RequestPriority` (RFC 9218 urgency/incremental), `session.get(url, priority=...)`
- **Protocol policy** — `ProtocolPolicy` / `HttpIntent` control H2/H3 selection, acquisition, and fallback (client / session / request level)
- **Session resumption control** — `SessionResumptionConfig` controls TLS1.3 PSK / TLS1.2 ticket resumption (fingerprint shape); `Client(tls_session_resumption_policy=..., tls_session_cache_partition_policy=...)` controls whether tickets are *stored* and how the cache is keyed, and `session(network_partition_context=NetworkPartitionContext(top_level_site, frame_site))` reproduces the browser's per-site partitioning
- **H2 DATA framing** — `Client(h2_data_frame_policy=H2DataFramePolicy.BROWSER_DEFAULT / PEER_MAX_FRAME_SIZE / fixed_payload(n) / socket_write_aligned(n))` chooses how request bodies are split into DATA frames
- **TLS close_notify** — `Client(require_close_notify=True)` rejects a response whose body was truncated without a TLS close_notify alert
- **Request-level protocol override** — `preferred_http_version` / `idempotency` (0-RTT replay-safety declaration)
- **QUIC / HTTP3** — Optional feature (`maturin develop --features quic-h3`): `session(http3_only=True / http3_with_fallback=True / broken_quic_policy=BrokenQuicPolicy.Resilient)`; `Client(quic_fingerprint=..., quic_profile="chrome_150", disable_http3=True)`; dedicated Chrome 146/150/151/152 `QuicProfile` presets (available only when the feature is enabled). The QUIC-specific ClientHello is a separate TLS profile — pass `quic_fingerprint=TlsProfile.chrome_151_quic()` when building a client manually, otherwise HTTP/3 reuses the main TLS profile
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
git clone https://github.com/EZ-XLabs/lkrequest-py
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
git clone https://github.com/EZ-XLabs/lkrequest-py
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

# Remove and clear
session.remove_cookie("https://example.com", "token")
session.clear_cookies()

# Request-level cookie override
resp = session.get(url, cookie_override={"token": "override_value"})
```

### Multipart file upload

```python
mp = lkrequest.Multipart()
mp.text("title", "File upload")
mp.file("document", "report.pdf", "application/pdf", pdf_bytes)
resp = session.post("https://example.com/upload", multipart=mp)
```

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
proxy = await pool.acquire()
```

TCP-based HTTP supports mixed HTTP CONNECT and SOCKS5 hops. QUIC/HTTP3 requires
every hop in the chain to be SOCKS5; a chain containing an HTTP hop falls back
to H2 when `http3_with_fallback=True`.

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
)

# Custom TCP Fingerprint
tcp = lkrequest.TcpFingerprint(window_size=65535, mss=1460, window_scale=8, ttl=128)

# Combine them
client = lkrequest.Client(tls_profile=tls, h2_profile=h2, tcp_fingerprint=tcp)

# Serialize / deserialize
json_str = tls.to_json()
restored = lkrequest.TlsProfile.from_json(json_str)

# Fingerprint randomization
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

# TimeoutConfig object
tc = lkrequest.TimeoutConfig(total=30.0, tcp_connect=10.0)

# ResourceLimits
rl = lkrequest.ResourceLimits(max_response_body_size=10*1024*1024, max_connections_per_session=16)
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
# Dynamically learn HSTS hosts within the session from response Strict-Transport-Security headers (like a long-running browser)
session = client.session(hsts=lkrequest.Hsts.dynamic())

# Seed known HSTS hosts (e.g. replay state learned in a previous session)
session = client.session(hsts=lkrequest.Hsts.dynamic(seed=["example.com"]))

# Fixed allowlist; preloaded_tlds=True also upgrades Chrome's fully-preloaded gTLDs (.dev/.app/…)
session = client.session(hsts=lkrequest.Hsts.static_(["example.com"], preloaded_tlds=True))
```

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

### Zero-copy Response

```python
resp = session.get("https://example.com")

mv = memoryview(resp)       # zero-copy access to body
text = resp.text()          # cached after first decode
data = resp.json()          # cached after first parse
```

### Logging

```python
lkrequest.set_log_level("info")                          # global level
lkrequest.set_log_level("lkrequest=debug,lktls=trace")   # module filter
lkrequest.set_log_level("info", format="compact")        # log format
lkrequest.set_log_level("off")                           # disable
```

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
| `Client.firefox_133()` | Firefox 133 | Firefox 133 | Firefox |
| `Client.firefox_147()` | Firefox 147 | Firefox 147 | Firefox |
| `Client.safari_18()` | Safari 18 | Safari 18 | Safari |
| `Client.safari_26()` | Safari 26 | Safari 26 | Safari |

TCP fingerprints are OS-specific: `chrome_win` / `chrome_linux` / `chrome_macos` / `firefox_win` / `firefox_linux` / `firefox_macos` / `safari`

## API Reference

### Client

| Parameter | Description |
|------|------|
| `tls_profile` | TLS fingerprint (string name or `TlsProfile` object) |
| `h2_profile` | HTTP/2 fingerprint (string name or `H2Profile` object) |
| `tcp_fingerprint` | TCP fingerprint (string name or `TcpFingerprint` object) |
| `default_headers` | Default request headers |
| `header_order` | Header send order |
| `cookie_order` | Cookie send order |
| `dns_timeout` / `tcp_connect_timeout` / `tls_handshake_timeout` / `ttfb_timeout` / `total_timeout` / `quic_connect_timeout` | Timeout control |
| `max_response_body_size` / `max_connections_per_session` / `max_header_count` / `max_header_size` / `max_headers_total_size` / `min_transfer_rate`(+ `min_transfer_rate_window`) | Resource limits / DoS protection |
| `max_pending_h2_requests` | Cap HTTP/2 requests queued for a remote stream slot (default: unbounded) |
| `h2_fallback_h1` / `proxy_fallback_direct` / `retry_on_connection_close` | Fault-tolerance options |
| `h2_data_frame_policy` | How request bodies are split into HTTP/2 DATA frames (`H2DataFramePolicy`) |
| `require_close_notify` | Reject a body truncated without a TLS close_notify alert (default: `False`) |
| `tls_session_resumption_policy` / `tls_session_cache_partition_policy` | Whether TLS tickets are stored, and how the ticket cache is keyed |
| `middleware` | Middleware list |
| `ca_cert` / `ca_cert_pem` / `ca_cert_der` / `verify` / `use_native_certs` | Certificate configuration |
| `ech_config` | ECH configuration |
| `dns` | Custom DNS |
| `system_dns_cache_ttl` / `system_dns_cache_max_entries` | Cache successful OS-resolver lookups for `ttl` seconds (TTL `0` disables caching but keeps in-flight coalescing; cannot be combined with `dns`) |
| `keylog` | TLS key log file path |

| Method | Description |
|------|------|
| `session(...)` | Create a session (`network_partition_context=...` partitions the TLS ticket cache per site) |
| `fingerprint_info()` | Return a fingerprint info dict |
| `randomize_fingerprint(shuffle_extensions=True)` | Return a new Client with a randomized fingerprint |

### Session

All HTTP methods (get/post/put/delete/head/patch/options) support:

| Parameter | Description |
|------|------|
| `headers` | Request headers |
| `params` | URL query params |
| `json` / `data` / `body` / `multipart` | Request body |
| `cookies` / `cookie_override` | Cookie control |
| `timeout` | Request timeout (seconds) |
| `bearer_auth` / `basic_auth` | Authentication |
| `proxy` | Request-level proxy override |
| `no_decompress` / `accept_encoding` | Encoding control |

| Method | Description |
|------|------|
| `send_streaming(method, url, ...)` | Streaming request |
| `ws_connect(url, *, headers, protocols)` | WebSocket connection |
| `preconnect(url)` / `preconnect_many(urls)` / `prefetch(urls)` | Connection prewarming |
| `pool_stats()` | Connection pool stats (`PoolStats`) |
| `on_request(callback)` / `on_response(callback)` | Register event hooks |
| `set_cookie()` / `set_cookie_with_attrs()` / `set_cookie_raw()` | Set cookies |
| `get_cookie()` / `get_cookies()` / `get_cookie_values()` / `cookie_header()` | Read cookies |
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
| `text()` | UTF-8 text (cached) |
| `json()` | Parse JSON (cached) |
| `cookies` | Response cookies |
| `encoding` | Character encoding |
| `elapsed` | Request duration (seconds) |
| `diagnostics` | Per-phase timing dict: `dns_ms`/`tcp_ms`/`tls_ms`/`ttfb_ms`/`total_ms` + `remote_addr`/`protocol`/`cipher_suite` (None for phases not measured) |
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
| `H2Profile` | HTTP/2 fingerprint config |
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
| `proxy_pool.py` | Single proxies, multi-hop chains, BadProxyConfig, HealthCheckConfig, ProxyPool |
| `session_pool.py` | SessionPool / BlockingSessionPool |
| `client_pool.py` | ClientPool multi-fingerprint rotation |
| `browser_fingerprints.py` | 6 preset fingerprints, string specification, fingerprint randomization |
| `custom_fingerprint.py` | Fully custom TlsProfile / H2Profile / TcpFingerprint |
| `fingerprint_validation.py` | validate_fingerprint_consistency |
| `streaming_response.py` | StreamingResponse chunked / full reads |
| `connection_prewarming.py` | preconnect / preconnect_many / prefetch |
| `metrics.py` | enable_metrics / snapshot / prometheus_text |
| `timeout_config.py` | Timeout configuration, ResourceLimits |
| `accept_encoding.py` | AcceptEncoding control, no_decompress |
| `certificate_config.py` | CA cert PEM/DER/file, verify, ECH |
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
