# Changelog

All important changes to this project will be documented in this file.

## lkrequest-py 0.2.0

### 🚀 Features
- **System DNS Positive Cache** — Added `system_dns_cache_ttl` and `system_dns_cache_max_entries` to `Client` and `BlockingClient`. The OS resolver already coalesces concurrent identical lookups process-wide; these cache successful, non-empty results for `ttl` seconds (default capacity 1024 entries). A `0` TTL keeps the coalescing while disabling the cache. It selects the system resolver, so it cannot be combined with `dns`; errors and empty results are never cached.
- **Shutdown Draining** — Added `drain_pending(timeout=None)`, its blocking counterpart `blocking_drain_pending(...)`, and `pending_requests()`. Waiting for in-flight work before tearing down an event loop means results are still delivered rather than dropped on arrival. Counts are process-wide and cover every async call, not only requests.
- **HTTP/2 Pending-Request Bound** — Added `max_pending_h2_requests` to `Client` and `BlockingClient`. HTTP/2 requests that exceed the peer's concurrent-stream limit now wait for a stream slot instead of failing, and this option caps how many may queue. Omit it (the default) for an unbounded queue; `0` is rejected with `ValueError`.
- **Synthetic Fingerprint Negotiability (`synthetic-fp`)** — Added `NegotiabilityFloor.UNIVERSAL`, `NegotiabilityFloor.PRESET_FAMILY`, `NegotiabilityFloor.custom(...)`, and `Randomize.negotiability(...)` so synthesized ClientHello profiles retain a configurable signature-algorithm compatibility floor.
- **Multi-hop Proxy Chains** — Added `ProxyConfig.parse_chain(...)` and `.through(...)`, with chain metadata via `hop_count()` and `identity()`. Client sessions, proxy pools, and session pools now accept either proxy URLs or `ProxyConfig` objects.
- **Mixed Proxy Transports** — HTTP/1.1 and HTTP/2 can traverse ordered combinations of HTTP CONNECT, SOCKS5, and SOCKS5H hops. QUIC/HTTP3 supports all-SOCKS5 chains when the optional `quic-h3` feature is enabled.
- **QUIC-TLS Profile Presets** — Added `TlsProfile.chrome_146_quic()`, `TlsProfile.chrome_150_quic()`, and `TlsProfile.chrome_151_quic()`, exposing the ClientHello Chrome sends inside QUIC (previously reachable only through the bundled `Client.chrome_1xx()` presets). Pass one to `Client(quic_fingerprint=...)` when building a client manually; HTTP/3 otherwise reuses the main TLS profile.
- **Chrome 151 Preset** — Added `Client.chrome_151()`, `BlockingClient.chrome_151()`, `TlsProfile.chrome_151()`, `H2Profile.chrome_151()`, `QuicProfile.chrome_151()`, and the `"chrome_151"` TLS/H2/QUIC profile names. Captured from Chrome 151.0.7922.72: TCP TLS and HTTP/2 keep Chrome 150's stable fields, while the QUIC-TLS capture omits the three ML-DSA signature algorithms; QUIC transport parameters and HTTP/3 SETTINGS stay aligned with Chrome 150.
- **Chrome 150 QUIC/H3 (`quic-h3`)** — `Client.chrome_150()` now uses dedicated Chrome 150 QUIC TLS and HTTP/3 profiles instead of reusing Chrome 146. The preset covers captured signature algorithms, QUIC transport parameters, QPACK limits, navigation `PRIORITY_UPDATE`, connection-ID lengths, and Initial datagram sizing. Added `QuicProfile.chrome_150()` and the `"chrome_150"` QUIC profile name.

### 🐞 Fixes
- **No More Crashes From Late-Completing Requests** — A request that finished after its event loop had closed used to print a `RuntimeError: Event loop is closed` traceback from whichever worker thread it landed on. Enough of them at once turned into `Fatal Python error: _enter_buffered_busy` and killed the process with SIGABRT — uncatchable, and it took the whole batch down. Results arriving after the loop closes are now dropped silently, since nothing is left to receive them.
- **Multi-Address Connect Fallback** — Connecting now tries every address a hostname resolves to, racing them Happy Eyeballs style (RFC 8305) with interleaved address families, rather than giving up when the first candidate is unreachable. Applies to direct TCP and to SOCKS5 proxies.
- **HTTP/2 Stream-Limit Backpressure** — Requests beyond the peer's advertised `MAX_CONCURRENT_STREAMS` now wait asynchronously for a stream slot instead of failing with a local capacity error.
- **Redirects Over Reused HTTP/1.1 Connections** — Following a redirect no longer fails when the pooled HTTP/1.1 connection was torn down in the meantime. The reuse attempt surfaces as hyper's `operation was canceled`, which is now recognised as a closed connection, so the request is retried on a fresh connection instead of erroring out. Affects any server that hangs up after answering a `3xx` — a common pattern after `POST`.
- **HTTP/2 `1xx` Interim Responses** — The HTTP/2 driver now consumes `1xx` informational responses — such as the `103 Early Hints` Cloudflare sends ahead of its `200` — and returns the final response that follows, instead of reporting the interim status as the final one. A plain `GET https://www.cloudflare.com/` previously came back as `103`.
- **Connection Limit Enforcement** — `max_connections` now bounds *physical* connections, counting those still being dialled and those checked out by an in-flight request rather than only what sits idle in the pool. Exceeding the limit raises instead of quietly opening another connection, and an idle HTTP/1.1 connection is evicted first so one origin's idle connections cannot starve another. `PoolStats.total` correspondingly reports physical connections in use rather than pooled entries.
- **Optional Client Certificate Requests** — A server that asks for a client certificate no longer breaks the handshake. TLS 1.2 and TLS 1.3 now answer a `CertificateRequest` with an empty client `Certificate` message — echoing the request context on TLS 1.3, as RFC 8446 §4.4.2 requires — so endpoints with optional mutual TLS complete the handshake instead of failing.
- **TLS Handshake Reassembly** — TLS 1.2 and TLS 1.3 handshake messages fragmented across multiple records are now buffered and reassembled correctly, preventing failures such as `truncated handshake message in record` without changing ClientHello or fingerprint output.
- **SOCKS5 UDP Relay Compatibility** — QUIC-over-SOCKS5 accepts relay replies from the advertised source IP even when the relay uses a different egress port, preventing affected HTTP/3 requests from hanging.
- **Package Version Reporting** — `lkrequest.__version__` is now read from installed distribution metadata instead of being maintained as a separate hard-coded value.
- **TLS 1.3 ECH + HelloRetryRequest** — Real ECH CH2 now reuses the ECH configuration, HPKE sender context, Inner random, GREASE values, extension permutation, and fake ECH bytes. HRR confirmation, selected groups, cookie-only retries, invalid extensions, dummy CCS, and local fatal alerts now follow the browser/RFC flow.
- **ECH + PSK + HRR Binders** — `pre_shared_key` remains exclusively in `ClientHelloInner`; CH1 and CH2 binders now use the correct truncated Inner transcripts, including `message_hash(ClientHelloInner1) + HRR` for CH2.
- **QUIC/H3 HRR State Transitions** — QUIC revokes 0-RTT stream and packet state after HRR and maps local TLS alerts to QUIC `CRYPTO_ERROR` codes.

## lkrequest-py 0.1.1

### 🐞 Fixes
- **Project URLs** — `Homepage`, `Repository`, and `Issues` in the package metadata pointed at a repository path that does not exist, so every link on the PyPI project page returned 404. They now point at `github.com/EZ-XLabs/lkrequest-py`.
- **README Links on PyPI** — the language switcher at the top of both READMEs used relative paths (`README.md` / `README-zh.md`), which PyPI cannot resolve when it renders the long description. Both now use absolute URLs, so switching between English and 简体中文 works from the project page.

### 📝 Documentation
- **Development Setup** — the setup section now walks through the full local workflow on Linux/macOS and Windows: creating and activating a virtualenv, installing maturin, `pip install -e ".[test,lint]"`, and running the suite via `just test`. An equivalent `uv sync --extra test --extra lint` path is documented alongside it.

## lkrequest-py 0.1.0

### 🚀 Features
- **TLS Fingerprint Control** — Byte-level ClientHello generation that matches real browsers (Chrome, Firefox, Safari)
- **HTTP/2 Fingerprint Control** — SETTINGS frame order, pseudo-header order, WINDOW_UPDATE, PRIORITY frames, and per-request priority weights
- **HTTP/3 + QUIC** — Optional `quic-h3` feature for full HTTP/3 over QUIC with fingerprint-aware Transport Parameters, Alt-Svc auto-discovery, and H2→H3 seamless upgrade
- **Built-in Browser Presets** — Chrome 131/144/145/146/147/148/149/150, Firefox 133/147, Safari 18/26 (TLS + H2, plus QUIC when `quic-h3` is enabled)
- **Session Management** — Cookie jars, connection pooling, HTTP/2 multiplexing, and optional QUIC 0-RTT session resumption
- **Connection Prewarming** — `session.preconnect()` pre-establishes DNS + TCP + TLS + H2 (or, with `quic-h3`, QUIC + H3) connections
- **Custom DNS Resolver** — Pluggable DNS with DoH support, auto ECH config and H3 hints via HTTPS/SVCB records
- **Alt-Svc Discovery** — Automatic HTTP/2 → HTTP/3 protocol upgrade via Alt-Svc headers with broken-QUIC fallback
- **SessionPool** — High-concurrency pool with proxy rotation (round-robin / random)
- **Proxy Support** — SOCKS5 and HTTP CONNECT with authentication
- **WebSocket** — HTTP/1.1 Upgrade (RFC 6455) and H2 Extended CONNECT (RFC 8441)
- **Middleware** — Interceptor chain for request/response modification
- **Retry Policies** — Exponential backoff, fixed interval, custom strategies; idempotency-aware (non-idempotent methods are not silently replayed after a possibly-already-sent failure unless marked `Idempotency::Idempotent`)
- **Redirect Control** — `RedirectPolicy::Follow(n)` or `RedirectPolicy::None` for manual handling
- **Auto-Decompression** — Brotli, gzip, deflate, zstd
- **Blocking API** — Synchronous wrapper for non-async contexts
- **Multipart/Form-Data** — File uploads with streaming support
- **TCP Fingerprint** — JA4T-style TCP SYN fingerprinting
