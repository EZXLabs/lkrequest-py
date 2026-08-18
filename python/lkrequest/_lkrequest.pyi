"""Type stubs for the lkrequest native extension module."""

from typing import Any, AsyncIterator, Callable, Iterable, Iterator, Optional

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class RequestError(Exception):
    """Base class for all lkrequest errors."""

class TlsError(RequestError):
    """Raised when the TLS handshake fails."""

class ProxyError(RequestError):
    """Raised when connecting through a proxy fails."""

class HttpStatusError(RequestError):
    """Raised by ``Response.error_for_status()`` for 4xx/5xx responses."""

class ConnectionError(RequestError):  # noqa: A001
    """Raised when the underlying connection fails."""

class TimeoutError(RequestError):  # noqa: A001
    """Raised when a request exceeds its configured timeout."""

class TooManyRedirectsError(RequestError):
    """Raised when a request exceeds the maximum number of redirects."""

class ResourceLimitError(RequestError):
    """Raised when a configured resource limit (e.g. body size) is exceeded."""

# ---------------------------------------------------------------------------
# Configuration types
# ---------------------------------------------------------------------------

class HttpVersion:
    """HTTP protocol version constants reported by ``Response.version``."""

    HTTP10: int
    HTTP11: int
    H2: int
    Unknown: int
    H3: int

class TimeoutConfig:
    """Per-phase timeout settings (DNS, TCP connect, TLS handshake, TTFB, total) in seconds."""

    def __init__(
        self,
        *,
        dns: Optional[float] = None,
        tcp_connect: Optional[float] = None,
        tls_handshake: Optional[float] = None,
        ttfb: Optional[float] = None,
        total: Optional[float] = None,
    ) -> None: ...

class ResourceLimits:
    """Resource caps such as max response body size, connections per session, and transfer rate."""

    def __init__(
        self,
        *,
        max_response_body_size: Optional[int] = None,
        max_connections_per_session: Optional[int] = None,
        min_transfer_rate: Optional[int] = None,
        transfer_rate_window: Optional[float] = None,
    ) -> None: ...

class SessionResumptionConfig:
    """Controls TLS session resumption: TLS 1.3 PSK and TLS 1.2 session tickets."""

    def __init__(
        self,
        *,
        tls13_psk: bool = True,
        tls12_session_ticket: bool = True,
        store_tickets: bool = True,
        max_tickets_per_host: Optional[int] = None,
    ) -> None: ...
    @staticmethod
    def disabled() -> SessionResumptionConfig:
        """Disable all session resumption."""
    @staticmethod
    def chrome() -> SessionResumptionConfig:
        """Resumption settings matching Chrome's behavior."""
    @staticmethod
    def firefox() -> SessionResumptionConfig:
        """Resumption settings matching Firefox's behavior."""
    @property
    def tls13_psk(self) -> bool: ...
    @property
    def tls12_session_ticket(self) -> bool: ...
    @property
    def store_tickets(self) -> bool: ...
    @property
    def max_tickets_per_host(self) -> Optional[int]: ...

class AcceptEncoding:
    """Content encodings to advertise; combine with ``|`` (e.g. ``AcceptEncoding.GZIP | AcceptEncoding.BR``)."""

    GZIP: AcceptEncoding
    BR: AcceptEncoding
    DEFLATE: AcceptEncoding
    ZSTD: AcceptEncoding
    ALL: AcceptEncoding
    def __or__(self, other: AcceptEncoding) -> AcceptEncoding: ...

class PoolStats:
    """Connection pool statistics returned by ``Session.pool_stats()``."""

    h2_connections: int
    h1_connections: int
    total: int
    max_total: int
    at_capacity: bool

class SessionPoolStats:
    """Session pool statistics returned by ``SessionPool.stats()``."""

    idle_sessions: int
    max_sessions: int

# ---------------------------------------------------------------------------
# Multipart
# ---------------------------------------------------------------------------

class Multipart:
    """Builder for ``multipart/form-data`` request bodies (text and file parts)."""

    def __init__(self) -> None: ...
    def text(self, name: str, value: str) -> None:
        """Add a text field."""
    def file(self, name: str, filename: str, content_type: str, data: bytes) -> None:
        """Add a file part with the given filename, content type, and bytes."""

class Part:
    """A single multipart part with fine-grained filename/content-type control."""

    def __init__(self, name: str, body: bytes) -> None: ...
    def filename(self, filename: str) -> None:
        """Set the part's filename."""
    def content_type(self, ct: str) -> None:
        """Set the part's content type."""

# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------

class ExponentialBackoff:
    """Retry policy with exponentially growing delay and optional jitter."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        jitter: bool = True,
    ) -> None: ...

class FixedInterval:
    """Retry policy that waits a fixed interval between attempts."""

    def __init__(self, max_retries: int = 3, interval: float = 1.0) -> None: ...

# ---------------------------------------------------------------------------
# Request priority (RFC 9218)
# ---------------------------------------------------------------------------

class RequestPriority:
    """RFC 9218 request priority (urgency 0-7, incremental flag); pass via ``priority=``."""

    def __init__(self, urgency: int, incremental: bool = False) -> None: ...
    @staticmethod
    def navigation() -> RequestPriority:
        """Priority preset for top-level navigation requests."""
    @staticmethod
    def fetch() -> RequestPriority:
        """Priority preset for fetch/XHR requests."""
    @staticmethod
    def image() -> RequestPriority:
        """Priority preset for image resources."""
    @staticmethod
    def background() -> RequestPriority:
        """Priority preset for low-urgency background requests."""
    @property
    def urgency(self) -> int: ...
    @property
    def incremental(self) -> bool: ...
    def to_header_value(self) -> str:
        """Render this priority as a ``Priority`` header value."""

# ---------------------------------------------------------------------------
# Protocol policy
# ---------------------------------------------------------------------------

class HttpIntent:
    """Intent constants steering H2/H3 selection, acquisition, and fallback."""

    H2Only: HttpIntent
    H3Only: HttpIntent
    AcquireH3WhenViable: HttpIntent
    ReuseExistingProtocol: HttpIntent

class ProtocolPolicy:
    """Policy controlling HTTP/2 vs HTTP/3 selection, acquisition, and fallback."""

    @staticmethod
    def chrome_standard() -> ProtocolPolicy:
        """Chrome-like default H2/H3 policy."""
    @staticmethod
    def chrome_conservative() -> ProtocolPolicy:
        """More cautious Chrome-like policy."""
    @staticmethod
    def crawler_throughput() -> ProtocolPolicy:
        """Throughput-oriented policy for crawlers."""
    @staticmethod
    def h3_strict() -> ProtocolPolicy:
        """Policy requiring HTTP/3."""
    def with_intent(self, intent: HttpIntent) -> ProtocolPolicy:
        """Return a copy of this policy with the given protocol intent."""
    @property
    def intent(self) -> HttpIntent: ...

class PreferredHttpVersion:
    """Per-request HTTP version preference passed via ``preferred_http_version=``."""

    Auto: PreferredHttpVersion
    Http1Only: PreferredHttpVersion
    Http2Only: PreferredHttpVersion
    Http3Only: PreferredHttpVersion
    Http3WithFallback: PreferredHttpVersion

class Idempotency:
    """Per-request idempotency declaration affecting 0-RTT replay safety and retries."""

    Default: Idempotency
    Idempotent: Idempotency
    NotIdempotent: Idempotency

class BrokenQuicPolicy:
    """Policy for handling broken QUIC/HTTP3 connections (strict, resilient, or disabled)."""

    Strict: BrokenQuicPolicy
    Resilient: BrokenQuicPolicy
    Disabled: BrokenQuicPolicy

class Hsts:
    """HTTP→HTTPS scheme-upgrade (HSTS) policy for a session, passed via
    ``Client.session(hsts=...)``.

    A fresh session is a stateless first visit, so omitting ``hsts`` performs no
    upgrades (equivalent to :meth:`none`). Plug a policy in to mirror Chrome's
    preloaded gTLDs, replay a session that already learned HSTS, or enforce your
    own rules. Host matching is suffix-aware (HSTS ``includeSubDomains``).
    """

    @staticmethod
    def none() -> Hsts:
        """Never upgrade ``http://`` to ``https://`` (the default)."""
    @staticmethod
    def static_(hosts: list[str], preloaded_tlds: bool = False) -> Hsts:
        """Upgrade a fixed set of hosts. Set ``preloaded_tlds=True`` to also
        upgrade every host under a gTLD Chrome preloads in full (``.dev``,
        ``.app``, …)."""
    @staticmethod
    def dynamic(seed: list[str] | None = None) -> Hsts:
        """Learn HSTS hosts from ``Strict-Transport-Security`` response headers
        during the session, optionally pre-seeded with known HSTS hosts."""

# ---------------------------------------------------------------------------
# Fingerprint randomization
# ---------------------------------------------------------------------------

class Randomize:
    """Fingerprint randomization policy passed via ``Client(randomize=...)``.

    Tiers 0/1 (``off`` / ``extension_order``) are always available. The
    synthetic tiers 3a/3b (``recombine`` / ``full``, with the ``Layers`` mask)
    require building the extension with the ``synthetic-fp`` feature and produce
    fingerprints that match no real browser (negative-model targets only).
    """

    @staticmethod
    def off() -> Randomize:
        """Tier 0 — no added randomization (the default)."""
    @staticmethod
    def extension_order() -> Randomize:
        """Tier 1 — force per-connection TLS extension-order permutation (drifts JA3, stays a real browser)."""
    @staticmethod
    def recombine() -> Randomize:
        """Tier 3a — a synthetic identity per session across all layers (requires the ``synthetic-fp`` feature)."""
    @staticmethod
    def recombine_layers(layers: Layers) -> Randomize:
        """Tier 3a restricted to a ``Layers`` subset (requires the ``synthetic-fp`` feature)."""
    @staticmethod
    def full() -> Randomize:
        """Tier 3b — like ``recombine`` but with out-of-corpus H2/QUIC values (requires the ``synthetic-fp`` feature)."""
    @staticmethod
    def full_layers(layers: Layers) -> Randomize:
        """Tier 3b restricted to a ``Layers`` subset (requires the ``synthetic-fp`` feature)."""
    def negotiability(self, floor: NegotiabilityFloor) -> Randomize:
        """Set the sig-alg negotiability floor for this synthetic policy; returns a new policy (requires the ``synthetic-fp`` feature)."""

class Layers:
    """Layer mask for synthetic ``Randomize`` policies; compose with ``|`` (only available with the ``synthetic-fp`` feature)."""

    TLS: Layers
    H2: Layers
    QUIC: Layers
    @staticmethod
    def all() -> Layers:
        """All fingerprint layers (the safe "no layer left constant" default)."""
    def __or__(self, other: Layers) -> Layers: ...

class NegotiabilityFloor:
    """Sig-alg negotiability floor for synthetic ``Randomize`` policies (only available with the ``synthetic-fp`` feature)."""

    UNIVERSAL: NegotiabilityFloor
    PRESET_FAMILY: NegotiabilityFloor
    @staticmethod
    def custom(sig_algs: list[int]) -> NegotiabilityFloor:
        """Guarantee a caller-supplied set of sig-alg code points (advanced; caller owns negotiability)."""

# ---------------------------------------------------------------------------
# QUIC / HTTP3 (only available when built with the `quic-h3` feature)
# ---------------------------------------------------------------------------

class QuicProfile:
    """QUIC/HTTP3 transport fingerprint (only available with the ``quic-h3`` feature)."""

    @staticmethod
    def chrome() -> QuicProfile:
        """Chrome QUIC fingerprint preset."""
    @staticmethod
    def chrome_146() -> QuicProfile:
        """Chrome 146 QUIC fingerprint preset."""
    @staticmethod
    def chrome_150() -> QuicProfile:
        """Chrome 150 QUIC fingerprint preset."""
    @staticmethod
    def chrome_151() -> QuicProfile:
        """Chrome 151 QUIC fingerprint preset (no ML-DSA signature algorithms)."""
    @staticmethod
    def from_json(json_str: str) -> QuicProfile:
        """Build a QuicProfile from a JSON string."""
    def to_json(self) -> str:
        """Serialize this profile to a JSON string."""
    def validate(self) -> None:
        """Validate the profile, raising on inconsistent settings."""
    @property
    def connection_id_length(self) -> int: ...

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class Middleware:
    """Request/response interceptor (onion model) that can observe or modify requests and responses."""

    def __init__(
        self,
        name: str,
        *,
        on_request: Optional[
            Callable[[dict[str, Any]], Optional[dict[str, Any]]]
        ] = None,
        on_response: Optional[
            Callable[[dict[str, Any]], Optional[dict[str, Any]]]
        ] = None,
    ) -> None: ...

# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------

class ProxyConfig:
    """Immutable single-proxy or ordered multi-hop proxy-chain configuration."""

    def __init__(self, url: str) -> None:
        """Parse a single HTTP CONNECT, SOCKS5, or SOCKS5H proxy URL."""
    @staticmethod
    def parse(url: str) -> ProxyConfig:
        """Parse a single proxy URL."""
    @staticmethod
    def parse_chain(urls: Iterable[str]) -> ProxyConfig:
        """Build an ordered proxy chain from client-facing hop to final hop."""
    def through(self, hops: Iterable[str | ProxyConfig]) -> ProxyConfig:
        """Return a new config with the supplied upstream hops prepended."""
    def hop_count(self) -> int:
        """Return the total number of proxy hops."""
    def identity(self) -> str:
        """Return the stable identity used for pooling and failure tracking."""
    def __str__(self) -> str: ...

class BadProxyConfig:
    """Configures how a ProxyPool detects and cools down failing proxies."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        window: float = 60.0,
        cooldown_duration: float = 300.0,
        max_cooldowns: int = 5,
    ) -> None: ...

class HealthCheckConfig:
    """Configures periodic proxy health checks against a target host/port."""

    def __init__(
        self,
        *,
        interval: float = 60.0,
        timeout: float = 5.0,
        target_host: str = "www.google.com",
        target_port: int = 443,
    ) -> None: ...

class ProxyPool:
    """Pool of proxies with rotation, bad-proxy cooldown, and optional health checks."""

    def __init__(
        self,
        proxies: Iterable[str | ProxyConfig],
        *,
        max_proxies: Optional[int] = None,
        rotation: Optional[str] = None,
        bad_proxy_config: Optional[BadProxyConfig] = None,
        health_check: Optional[HealthCheckConfig] = None,
    ) -> None: ...
    async def acquire(self) -> str:
        """Acquire the next available proxy URL according to the rotation policy."""
    def mark_bad(self, identity: str) -> None:
        """Mark a proxy as failing so it is cooled down."""

# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class HeaderMap:
    """Case-insensitive, multi-value view of HTTP response headers."""

    def __getitem__(self, name: str) -> str:
        """Return the header value, raising ``KeyError`` if absent."""
    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Return the header value, or ``default`` if absent."""
    def get_all(self, name: str) -> list[str]:
        """Return all values for a repeated header."""
    def __contains__(self, name: str) -> bool: ...
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[str]: ...
    def keys(self) -> list[str]:
        """Return all header names."""
    def values(self) -> list[str]:
        """Return all header values."""
    def items(self) -> list[tuple[str, str]]:
        """Return all (name, value) pairs."""
    def to_dict(self) -> dict[str, str]:
        """Return the headers as a plain dict."""

class RedirectRecord:
    """One hop in a redirect chain (see ``Response.history``)."""

    url: str
    status_code: int
    redirect_to: str
    @property
    def headers(self) -> HeaderMap: ...

class Response:
    """A completed HTTP response with status, headers, body, cookies, and diagnostics."""

    @property
    def status_code(self) -> int:
        """The HTTP status code."""
    @property
    def url(self) -> str:
        """The final URL after any redirects."""
    @property
    def version(self) -> HttpVersion:
        """The HTTP protocol version used for the response."""
    @property
    def content_length(self) -> Optional[int]:
        """The ``Content-Length`` value, if present."""
    @property
    def headers(self) -> HeaderMap:
        """The response headers as a case-insensitive ``HeaderMap``."""
    @property
    def headers_list(self) -> list[tuple[str, str]]:
        """The response headers as an ordered list of (name, value) pairs."""
    @property
    def cookies(self) -> dict[str, str]:
        """Cookies set by this response."""
    @property
    def encoding(self) -> Optional[str]:
        """The detected character encoding, if any."""
    @property
    def elapsed(self) -> float:
        """Total request duration in seconds."""
    @property
    def history(self) -> list[RedirectRecord]:
        """The chain of redirects that led to this response."""
    @property
    def diagnostics(self) -> dict[str, Any]:
        """Per-phase timings (dns/tcp/tls/ttfb/total ms) plus remote_addr/protocol/cipher_suite."""
    @property
    def content(self) -> bytes:
        """The raw response body bytes."""
    @property
    def ok(self) -> bool:
        """True if the status code is below 400."""
    @property
    def was_redirected(self) -> bool:
        """True if the request went through one or more redirects."""
    def text(self) -> str:
        """Decode and return the body as text (cached after first call)."""
    def json(self) -> Any:
        """Parse and return the body as JSON (cached after first call)."""
    def error_for_status(self) -> None:
        """Raise ``HttpStatusError`` if the status code is 4xx or 5xx."""
    def __len__(self) -> int: ...
    def __bool__(self) -> bool: ...

class StreamingResponse:
    """An async streaming response read chunk by chunk via iteration or ``chunk()``."""

    @property
    def status_code(self) -> int:
        """The HTTP status code."""
    @property
    def headers(self) -> HeaderMap:
        """The response headers."""
    async def chunk(self) -> Optional[bytes]:
        """Read the next raw body chunk, or ``None`` at end of stream."""
    async def chunk_decoded(self) -> Optional[bytes]:
        """Read the next decompressed body chunk, or ``None`` at end of stream."""
    async def bytes(self) -> bytes:
        """Read the entire remaining body into bytes."""
    async def text(self) -> str:
        """Read the entire remaining body and decode it as text."""
    def __aiter__(self) -> AsyncIterator[bytes]: ...
    async def __anext__(self) -> bytes: ...

class BlockingStreamingResponse:
    """A synchronous streaming response read chunk by chunk via iteration or ``chunk()``."""

    @property
    def status_code(self) -> int:
        """The HTTP status code."""
    @property
    def headers(self) -> HeaderMap:
        """The response headers."""
    def chunk(self) -> Optional[bytes]:
        """Read the next raw body chunk, or ``None`` at end of stream."""
    def chunk_decoded(self) -> Optional[bytes]:
        """Read the next decompressed body chunk, or ``None`` at end of stream."""
    def bytes(self) -> bytes:
        """Read the entire remaining body into bytes."""
    def text(self) -> str:
        """Read the entire remaining body and decode it as text."""
    def __iter__(self) -> Iterator[bytes]: ...
    def __next__(self) -> bytes: ...

# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

class WsMessage:
    """A WebSocket message; variants are exposed as the nested Text/Binary/Ping/Pong/Close subclasses."""

    # Complex-enum variants are exposed as nested subclasses of WsMessage.
    class Text(WsMessage):
        """A text WebSocket message."""

        data: str

    class Binary(WsMessage):
        """A binary WebSocket message."""

        data: bytes

    class Ping(WsMessage):
        """A WebSocket ping control frame."""

        data: bytes

    class Pong(WsMessage):
        """A WebSocket pong control frame."""

        data: bytes

    class Close(WsMessage):
        """A WebSocket close frame with an optional code and reason."""

        code: Optional[int]
        reason: str

    @staticmethod
    def text(data: str) -> WsMessage:
        """Construct a text message."""
    @staticmethod
    def binary(data: bytes) -> WsMessage:
        """Construct a binary message."""
    def is_text(self) -> bool:
        """True if this is a text message."""
    def is_binary(self) -> bool:
        """True if this is a binary message."""
    def is_close(self) -> bool:
        """True if this is a close frame."""

class WsConnection:
    """An open async WebSocket connection; iterate it to receive messages."""

    async def send_text(self, text: str) -> None:
        """Send a text message."""
    async def send_binary(self, data: bytes) -> None:
        """Send a binary message."""
    async def recv(self) -> WsMessage:
        """Receive the next message."""
    async def close(self, code: Optional[int] = None, reason: str = "") -> None:
        """Close the connection with an optional code and reason."""
    def __aiter__(self) -> AsyncIterator[WsMessage]: ...
    async def __anext__(self) -> WsMessage: ...

class BlockingWsConnection:
    """An open synchronous WebSocket connection; iterate it to receive messages."""

    def send_text(self, text: str) -> None:
        """Send a text message."""
    def send_binary(self, data: bytes) -> None:
        """Send a binary message."""
    def recv(self) -> WsMessage:
        """Receive the next message."""
    def close(self, code: Optional[int] = None, reason: str = "") -> None:
        """Close the connection with an optional code and reason."""
    def __iter__(self) -> Iterator[WsMessage]: ...
    def __next__(self) -> Optional[WsMessage]: ...

# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session:
    """An async HTTP session sharing connections, cookies, and configuration across requests."""

    async def get(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a GET request."""
    async def post(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a POST request with optional json/data/body/multipart payload."""
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a request with an explicit HTTP method (e.g. ``"GET"``, ``"POST"``)."""
    async def put(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a PUT request with optional json/data/body/multipart payload."""
    async def delete(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a DELETE request."""
    async def head(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a HEAD request."""
    async def patch(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a PATCH request with optional json/data/body/multipart payload."""
    async def options(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send an OPTIONS request."""
    def pool_stats(self) -> PoolStats:
        """Return current connection pool statistics."""
    def pool_clear(self) -> None:
        """Close all pooled connections and abort their driver tasks."""
    async def ws_connect(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        protocols: Optional[list[str]] = None,
    ) -> WsConnection:
        """Open a WebSocket connection (preserving the session's fingerprint)."""
    def set_cookie(self, url: str, name: str, value: str) -> None:
        """Set a cookie for the given URL in the session's cookie jar."""
    def set_cookie_with_attrs(
        self,
        url: str,
        name: str,
        value: str,
        *,
        path: Optional[str] = None,
        domain: Optional[str] = None,
        secure: bool = False,
        http_only: bool = False,
    ) -> None:
        """Set a cookie with explicit path/domain/secure/http_only attributes."""
    def set_cookie_raw(self, url: str, set_cookie_header: str) -> None:
        """Set a cookie by parsing a raw ``Set-Cookie`` header value."""
    def get_cookie(self, url: str, name: str) -> Optional[str]:
        """Return the value of a cookie for the URL, or ``None`` if absent."""
    def get_cookies(self, url: str) -> list[tuple[str, str]]:
        """Return all (name, value) cookies applicable to the URL."""
    def get_cookie_values(self, url: str, name: str) -> list[str]:
        """Return all values for a cookie name applicable to the URL."""
    def cookie_header(self, url: str) -> Optional[str]:
        """Return the ``Cookie`` header that would be sent for the URL."""
    def remove_cookie(self, url: str, name: str) -> None:
        """Remove a cookie from the jar."""
    def clear_cookies(self) -> None:
        """Remove all cookies from the jar."""
    async def preconnect(self, url: str) -> None:
        """Establish a connection to the URL ahead of time to reduce first-request latency."""
    async def preconnect_many(self, urls: list[str]) -> list[dict[str, Any]]:
        """Preconnect to multiple URLs, returning a per-URL result dict for each."""
    async def prefetch(self, urls: list[str]) -> list[dict[str, Any]]:
        """Warm connections to multiple URLs, returning a per-URL result dict for each."""
    async def send_streaming(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        accept_encoding: Optional[AcceptEncoding] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> StreamingResponse:
        """Send a request and return a streaming response read chunk by chunk."""
    def on_request(self, callback: Callable[..., Any]) -> None:
        """Register an event hook called before each request."""
    def on_response(self, callback: Callable[..., Any]) -> None:
        """Register an event hook called after each response."""

class BlockingSession:
    """A synchronous HTTP session sharing connections, cookies, and configuration across requests."""

    def get(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a GET request."""
    def post(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a POST request with optional json/data/body/multipart payload."""
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a request with an explicit HTTP method (e.g. ``"GET"``, ``"POST"``)."""
    def put(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a PUT request with optional json/data/body/multipart payload."""
    def delete(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a DELETE request."""
    def head(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a HEAD request."""
    def patch(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        no_decompress: bool = False,
        accept_encoding: Optional[AcceptEncoding] = None,
        priority: Optional[RequestPriority] = None,
        preferred_http_version: Optional[PreferredHttpVersion] = None,
        idempotency: Optional[Idempotency] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send a PATCH request with optional json/data/body/multipart payload."""
    def options(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> Response:
        """Send an OPTIONS request."""
    def pool_stats(self) -> PoolStats:
        """Return current connection pool statistics."""
    def pool_clear(self) -> None:
        """Close all pooled connections and abort their driver tasks."""
    def ws_connect(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        protocols: Optional[list[str]] = None,
    ) -> BlockingWsConnection:
        """Open a WebSocket connection (preserving the session's fingerprint)."""
    def set_cookie(self, url: str, name: str, value: str) -> None:
        """Set a cookie for the given URL in the session's cookie jar."""
    def set_cookie_with_attrs(
        self,
        url: str,
        name: str,
        value: str,
        *,
        path: Optional[str] = None,
        domain: Optional[str] = None,
        secure: bool = False,
        http_only: bool = False,
    ) -> None:
        """Set a cookie with explicit path/domain/secure/http_only attributes."""
    def get_cookie(self, url: str, name: str) -> Optional[str]:
        """Return the value of a cookie for the URL, or ``None`` if absent."""
    def get_cookies(self, url: str) -> list[tuple[str, str]]:
        """Return all (name, value) cookies applicable to the URL."""
    def get_cookie_values(self, url: str, name: str) -> list[str]:
        """Return all values for a cookie name applicable to the URL."""
    def cookie_header(self, url: str) -> Optional[str]:
        """Return the ``Cookie`` header that would be sent for the URL."""
    def remove_cookie(self, url: str, name: str) -> None:
        """Remove a cookie from the jar."""
    def clear_cookies(self) -> None:
        """Remove all cookies from the jar."""
    def preconnect(self, url: str) -> None:
        """Establish a connection to the URL ahead of time to reduce first-request latency."""
    def preconnect_many(self, urls: list[str]) -> list[dict[str, Any]]:
        """Preconnect to multiple URLs, returning a per-URL result dict for each."""
    def prefetch(self, urls: list[str]) -> list[dict[str, Any]]:
        """Warm connections to multiple URLs, returning a per-URL result dict for each."""
    def send_streaming(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        params: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        json: Optional[Any] = None,
        data: Optional[dict[str, str] | list[tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        multipart: Optional[Multipart] = None,
        cookies: Optional[dict[str, str]] = None,
        cookie_override: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        bearer_auth: Optional[str] = None,
        basic_auth: Optional[tuple[str, Optional[str]]] = None,
        proxy: Optional[str] = None,
        accept_encoding: Optional[AcceptEncoding] = None,
        header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
    ) -> BlockingStreamingResponse:
        """Send a request and return a streaming response read chunk by chunk."""
    def on_request(self, callback: Callable[..., Any]) -> None:
        """Register an event hook called before each request."""
    def on_response(self, callback: Callable[..., Any]) -> None:
        """Register an event hook called after each response."""

# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class Client:
    """Async HTTP client holding shared TLS/HTTP2/TCP fingerprint and connection configuration; create sessions via ``session()``."""

    def __init__(
        self,
        *,
        tls_profile: Optional[str | TlsProfile] = None,
        h2_profile: Optional[str | H2Profile] = None,
        tcp_fingerprint: Optional[str | TcpFingerprint] = None,
        default_headers: Optional[dict[str, str]] = None,
        header_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        dns_timeout: Optional[float] = None,
        tcp_connect_timeout: Optional[float] = None,
        tls_handshake_timeout: Optional[float] = None,
        ttfb_timeout: Optional[float] = None,
        total_timeout: Optional[float] = None,
        max_response_body_size: Optional[int] = None,
        max_connections_per_session: Optional[int] = None,
        max_pending_h2_requests: Optional[int] = None,
        quic_connect_timeout: Optional[float] = None,
        max_header_count: Optional[int] = None,
        max_header_size: Optional[int] = None,
        max_headers_total_size: Optional[int] = None,
        min_transfer_rate: Optional[int] = None,
        min_transfer_rate_window: Optional[float] = None,
        h2_fallback_h1: Optional[bool] = None,
        proxy_fallback_direct: Optional[bool] = None,
        retry_on_connection_close: Optional[bool] = None,
        middleware: Optional[list[Middleware]] = None,
        ca_cert: Optional[str] = None,
        ca_cert_pem: Optional[bytes] = None,
        ca_cert_der: Optional[bytes] = None,
        verify: Optional[bool] = None,
        use_native_certs: bool = False,
        ech_config: Optional[bytes] = None,
        dns: Optional[str] = None,
        system_dns_cache_ttl: Optional[float] = None,
        system_dns_cache_max_entries: Optional[int] = None,
        keylog: Optional[str] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        session_resumption: Optional[SessionResumptionConfig] = None,
        disable_http3: bool = False,
        quic_fingerprint: Optional[str | TlsProfile] = None,
        quic_profile: Optional[str | QuicProfile] = None,
        randomize: Optional[Randomize] = None,
    ) -> None:
        """Build a client with explicit fingerprints, headers, timeouts, certificates, and protocol options."""
    @staticmethod
    def chrome_131() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_144() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_145() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_146() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_147() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_148() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_149() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_150() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_151() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def firefox_133() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def firefox_147() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def safari_18() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def safari_26() -> Client:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    def session(
        self,
        *,
        proxy: Optional[str | ProxyConfig] = None,
        max_redirects: Optional[int] = None,
        allow_redirects: bool = True,
        http1_only: bool = False,
        http2_only: bool = False,
        http3_only: bool = False,
        http3_with_fallback: bool = False,
        retry: Optional[
            ExponentialBackoff | FixedInterval | Callable[..., Optional[float]]
        ] = None,
        middleware: Optional[list[Middleware]] = None,
        accept_encoding: Optional[AcceptEncoding] = None,
        ech_config: Optional[bytes] = None,
        max_connections: Optional[int] = None,
        idle_timeout: Optional[float] = None,
        on_request: Optional[Callable[..., Any]] = None,
        on_response: Optional[Callable[..., Any]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
        broken_quic_policy: Optional[BrokenQuicPolicy] = None,
        header_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        https_only: bool = False,
        hsts: Optional[Hsts] = None,
        base_url: Optional[str] = None,
    ) -> Session:
        """Create a new session, optionally overriding proxy, retry, protocol, and hook settings.

        Set ``allow_redirects=False`` to stop following 3xx redirects and return
        the redirect response as-is; it takes precedence over ``max_redirects``.
        (Note: ``max_redirects=0`` instead raises ``TooManyRedirectsError`` on the
        first redirect, so use ``allow_redirects=False`` to inspect a 3xx response.)
        """
    def fingerprint_info(self) -> dict[str, Any]:
        """Return a dict describing the client's active TLS/HTTP2/TCP fingerprint."""
    def randomize_fingerprint(
        self,
        *,
        shuffle_extensions: bool = True,
    ) -> Client:
        """Return a new client with a randomized fingerprint variant to reduce correlation."""

class BlockingClient:
    """Synchronous HTTP client holding shared TLS/HTTP2/TCP fingerprint and connection configuration; create sessions via ``session()``."""

    def __init__(
        self,
        *,
        tls_profile: Optional[str | TlsProfile] = None,
        h2_profile: Optional[str | H2Profile] = None,
        tcp_fingerprint: Optional[str | TcpFingerprint] = None,
        default_headers: Optional[dict[str, str]] = None,
        header_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        dns_timeout: Optional[float] = None,
        tcp_connect_timeout: Optional[float] = None,
        tls_handshake_timeout: Optional[float] = None,
        ttfb_timeout: Optional[float] = None,
        total_timeout: Optional[float] = None,
        max_response_body_size: Optional[int] = None,
        max_connections_per_session: Optional[int] = None,
        max_pending_h2_requests: Optional[int] = None,
        quic_connect_timeout: Optional[float] = None,
        max_header_count: Optional[int] = None,
        max_header_size: Optional[int] = None,
        max_headers_total_size: Optional[int] = None,
        min_transfer_rate: Optional[int] = None,
        min_transfer_rate_window: Optional[float] = None,
        h2_fallback_h1: Optional[bool] = None,
        proxy_fallback_direct: Optional[bool] = None,
        retry_on_connection_close: Optional[bool] = None,
        middleware: Optional[list[Middleware]] = None,
        ca_cert: Optional[str] = None,
        ca_cert_pem: Optional[bytes] = None,
        ca_cert_der: Optional[bytes] = None,
        verify: Optional[bool] = None,
        use_native_certs: bool = False,
        ech_config: Optional[bytes] = None,
        dns: Optional[str] = None,
        system_dns_cache_ttl: Optional[float] = None,
        system_dns_cache_max_entries: Optional[int] = None,
        keylog: Optional[str] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        session_resumption: Optional[SessionResumptionConfig] = None,
        disable_http3: bool = False,
        quic_fingerprint: Optional[str | TlsProfile] = None,
        quic_profile: Optional[str | QuicProfile] = None,
        randomize: Optional[Randomize] = None,
    ) -> None:
        """Build a client with explicit fingerprints, headers, timeouts, certificates, and protocol options."""
    @staticmethod
    def chrome_131() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_144() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_145() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_146() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_147() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_148() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_149() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_150() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def chrome_151() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def firefox_133() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def firefox_147() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def safari_18() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    @staticmethod
    def safari_26() -> BlockingClient:
        """Create a client preconfigured with this browser's TLS/HTTP2/TCP fingerprint."""
    def session(
        self,
        *,
        proxy: Optional[str | ProxyConfig] = None,
        max_redirects: Optional[int] = None,
        allow_redirects: bool = True,
        http1_only: bool = False,
        http2_only: bool = False,
        http3_only: bool = False,
        http3_with_fallback: bool = False,
        retry: Optional[
            ExponentialBackoff | FixedInterval | Callable[..., Optional[float]]
        ] = None,
        middleware: Optional[list[Middleware]] = None,
        accept_encoding: Optional[AcceptEncoding] = None,
        ech_config: Optional[bytes] = None,
        max_connections: Optional[int] = None,
        idle_timeout: Optional[float] = None,
        on_request: Optional[Callable[..., Any]] = None,
        on_response: Optional[Callable[..., Any]] = None,
        protocol_policy: Optional[ProtocolPolicy] = None,
        http_intent: Optional[HttpIntent] = None,
        broken_quic_policy: Optional[BrokenQuicPolicy] = None,
        header_order: Optional[list[str]] = None,
        h3_header_order: Optional[list[str]] = None,
        cookie_order: Optional[list[str]] = None,
        https_only: bool = False,
        hsts: Optional[Hsts] = None,
        base_url: Optional[str] = None,
    ) -> BlockingSession:
        """Create a new session, optionally overriding proxy, retry, protocol, and hook settings.

        Set ``allow_redirects=False`` to stop following 3xx redirects and return
        the redirect response as-is; it takes precedence over ``max_redirects``.
        (Note: ``max_redirects=0`` instead raises ``TooManyRedirectsError`` on the
        first redirect, so use ``allow_redirects=False`` to inspect a 3xx response.)
        """
    def fingerprint_info(self) -> dict[str, Any]:
        """Return a dict describing the client's active TLS/HTTP2/TCP fingerprint."""
    def randomize_fingerprint(
        self,
        *,
        shuffle_extensions: bool = True,
    ) -> BlockingClient:
        """Return a new client with a randomized fingerprint variant to reduce correlation."""

# ---------------------------------------------------------------------------
# Session Pool
# ---------------------------------------------------------------------------

class SessionPool:
    """Async pool of sessions over a set of proxies, with rotation and bad-session handling."""

    def __init__(
        self,
        client: Client,
        proxies: Iterable[str | ProxyConfig],
        *,
        max_sessions: Optional[int] = None,
        idle_timeout: Optional[float] = None,
        rotation: Optional[str] = None,
    ) -> None: ...
    async def acquire(self) -> SessionGuard:
        """Acquire a session guard for use as an async context manager."""
    async def acquire_fresh(self, bad_guard: SessionGuard) -> SessionGuard:
        """Replace a bad session with a fresh one and return its guard."""
    async def mark_bad(self, session_guard: SessionGuard) -> None:
        """Mark the guarded session as bad so it is not reused."""
    async def stats(self) -> SessionPoolStats:
        """Return current session pool statistics."""

class SessionGuard:
    """Async context manager yielding a pooled ``Session`` and returning it on exit."""

    @property
    def session(self) -> Session: ...  # type: ignore[override]
    async def __aenter__(self) -> Session: ...
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool: ...

class BlockingSessionPool:
    """Synchronous pool of sessions over a set of proxies, with rotation and bad-session handling."""

    def __init__(
        self,
        client: BlockingClient,
        proxies: Iterable[str | ProxyConfig],
        *,
        max_sessions: Optional[int] = None,
        idle_timeout: Optional[float] = None,
        rotation: Optional[str] = None,
    ) -> None: ...
    def acquire(self) -> BlockingSessionGuard:
        """Acquire a session guard for use as a context manager."""
    def acquire_fresh(self, bad_guard: BlockingSessionGuard) -> BlockingSessionGuard:
        """Replace a bad session with a fresh one and return its guard."""
    def mark_bad(self, session_guard: BlockingSessionGuard) -> None:
        """Mark the guarded session as bad so it is not reused."""
    def stats(self) -> SessionPoolStats:
        """Return current session pool statistics."""

class BlockingSessionGuard:
    """Context manager yielding a pooled ``BlockingSession`` and returning it on exit."""

    @property
    def session(self) -> BlockingSession: ...
    def __enter__(self) -> BlockingSession: ...
    def __exit__(
        self,
        exc_type: Optional[type] = None,
        exc_val: Optional[BaseException] = None,
        exc_tb: Optional[Any] = None,
    ) -> bool: ...

# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class MetricsCollector:
    """Collects Prometheus-style request metrics; returned by ``enable_metrics()``."""

    def snapshot(self) -> dict[str, Any]:
        """Return a dict snapshot of the collected metrics."""
    def prometheus_text(self) -> str:
        """Render the collected metrics in Prometheus exposition format."""
    def reset(self) -> None:
        """Reset all collected metrics to zero."""

# ---------------------------------------------------------------------------
# Fingerprint configuration
# ---------------------------------------------------------------------------

class ExtType:
    """Numeric constants for TLS extension types used when building an ``ExtensionSpec``."""

    SNI: int
    EC_POINT_FORMATS: int
    SUPPORTED_GROUPS: int
    SESSION_TICKET: int
    ENCRYPT_THEN_MAC: int
    EXTENDED_MASTER_SECRET: int
    SIGNATURE_ALGORITHMS: int
    SUPPORTED_VERSIONS: int
    PSK_KEY_EXCHANGE_MODES: int
    KEY_SHARE: int
    ALPN: int
    STATUS_REQUEST: int
    SIGNED_CERTIFICATE_TIMESTAMP: int
    COMPRESS_CERTIFICATE: int
    APPLICATION_SETTINGS: int
    APPLICATION_SETTINGS_NEW: int
    RENEGOTIATION_INFO: int
    DELEGATED_CREDENTIALS: int
    RECORD_SIZE_LIMIT: int
    PADDING: int
    COOKIE: int
    PRE_SHARED_KEY: int
    ENCRYPTED_CLIENT_HELLO: int

class ExtensionSpec:
    """Specification of a single TLS extension within a ``TlsProfile``."""

    def __init__(
        self,
        extension_type: int,
        *,
        source: str = "auto",
        raw_data: Optional[str] = None,
    ) -> None: ...
    @property
    def extension_type(self) -> int: ...
    @property
    def source(self) -> str: ...

class GreaseConfig:
    """Controls which TLS ClientHello fields receive GREASE values."""

    def __init__(
        self,
        *,
        cipher_suite: bool = False,
        extensions: bool = False,
        supported_groups: bool = False,
        supported_versions: bool = False,
        signature_algorithms: bool = False,
        key_share: bool = False,
    ) -> None: ...

class PaddingStrategy:
    """TLS ClientHello padding strategy (block alignment, fixed target, or none)."""

    @staticmethod
    def block_align(min_length: int, block_size: int) -> PaddingStrategy:
        """Pad to a multiple of ``block_size`` (at least ``min_length``)."""
    @staticmethod
    def fixed_target(target_length: int) -> PaddingStrategy:
        """Pad up to a fixed target length."""
    @staticmethod
    def no_padding() -> PaddingStrategy:
        """Disable padding."""

class RandomizationConfig:
    """Configures fingerprint randomization, such as shuffling TLS extensions."""

    def __init__(
        self,
        *,
        shuffle_extensions: bool = False,
    ) -> None: ...

class TlsProfile:
    """Fully programmable TLS fingerprint (cipher suites, extensions, groups, etc.); supports presets and JSON serialization."""

    def __init__(
        self,
        name: str,
        *,
        cipher_suites: Optional[list[int]] = None,
        extensions: Optional[list[ExtensionSpec]] = None,
        supported_groups: Optional[list[int]] = None,
        signature_algorithms: Optional[list[int]] = None,
        key_share_curves: Optional[list[int]] = None,
        alpn_protocols: Optional[list[str]] = None,
        tls_min_version: Optional[str] = None,
        tls_max_version: Optional[str] = None,
        ec_point_formats: Optional[list[int]] = None,
        compression_methods: Optional[list[int]] = None,
        grease: Optional[GreaseConfig] = None,
        padding: Optional[PaddingStrategy] = None,
        alps_protocols: Optional[list[str]] = None,
        compress_cert_algorithms: Optional[list[int]] = None,
        record_size_limit: Optional[int] = None,
        delegated_credentials_sig_algs: Optional[list[int]] = None,
        session_id_length: int = 32,
        randomization: Optional[RandomizationConfig] = None,
    ) -> None: ...
    @staticmethod
    def chrome_131() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_144() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_145() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_146() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_147() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_148() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_149() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_150() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_151() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def chrome_146_quic() -> TlsProfile:
        """Chrome 146 QUIC-TLS preset (the ClientHello sent inside QUIC), for ``Client(quic_fingerprint=...)``."""
    @staticmethod
    def chrome_150_quic() -> TlsProfile:
        """Chrome 150 QUIC-TLS preset, for ``Client(quic_fingerprint=...)``."""
    @staticmethod
    def chrome_151_quic() -> TlsProfile:
        """Chrome 151 QUIC-TLS preset: Chrome 150's QUIC ClientHello without the three ML-DSA signature algorithms."""
    @staticmethod
    def firefox_133() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def firefox_147() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def safari_18() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def safari_26() -> TlsProfile:
        """TLS fingerprint preset for this browser version."""
    @staticmethod
    def from_json(json_str: str) -> TlsProfile:
        """Build a TlsProfile from a JSON string."""
    @staticmethod
    def from_json_file(path: str) -> TlsProfile:
        """Build a TlsProfile from a JSON file path."""
    @staticmethod
    def from_client_hello(data: bytes, *, name: str = "captured") -> TlsProfile:
        """Build a TlsProfile by parsing raw captured ClientHello bytes."""
    def to_json(self) -> str:
        """Serialize this profile to a JSON string."""
    def to_dict(self) -> dict[str, Any]:
        """Serialize this profile to a dict."""
    @property
    def name(self) -> str: ...
    @property
    def cipher_suites(self) -> list[int]: ...
    @property
    def supported_groups(self) -> list[int]: ...
    @property
    def signature_algorithms(self) -> list[int]: ...
    @property
    def alpn_protocols(self) -> list[str]: ...

class H2Setting:
    """A single HTTP/2 SETTINGS entry, keyed by string name or numeric id."""

    def __init__(self, id: str | int, value: int) -> None: ...
    @property
    def value(self) -> int: ...

class HeadersPriority:
    """HTTP/2 priority info (stream dependency, weight, exclusive flag) for the HEADERS frame."""

    def __init__(
        self, stream_dependency: int, weight: int, exclusive: bool
    ) -> None: ...

class PriorityFrame:
    """An HTTP/2 PRIORITY frame definition for a given stream."""

    def __init__(
        self, stream_id: int, dependency: int, weight: int, exclusive: bool
    ) -> None: ...

class PriorityConfig:
    """HTTP/2 priority strategy (urgency weights, stream dependency policy, defaults)."""

    def __init__(
        self,
        *,
        urgency_weights: Optional[list[int]] = None,
        exclusive: bool = False,
        stream_dep_policy: str = "flat",
        auto_priority_header: bool = False,
        default_urgency: int = 3,
        default_incremental: bool = False,
    ) -> None: ...
    @staticmethod
    def default_config() -> PriorityConfig:
        """Return the library's default priority configuration."""
    @staticmethod
    def chrome() -> PriorityConfig:
        """Priority configuration matching Chrome."""
    @staticmethod
    def firefox() -> PriorityConfig:
        """Priority configuration matching Firefox."""
    @staticmethod
    def safari18() -> PriorityConfig:
        """Priority configuration matching Safari 18."""
    @staticmethod
    def safari26() -> PriorityConfig:
        """Priority configuration matching Safari 26."""
    @property
    def urgency_weights(self) -> Optional[list[int]]: ...
    @property
    def exclusive(self) -> bool: ...
    @property
    def stream_dep_policy(self) -> str: ...
    @property
    def auto_priority_header(self) -> bool: ...
    @property
    def default_urgency(self) -> int: ...
    @property
    def default_incremental(self) -> bool: ...

class H2Profile:
    """Programmable HTTP/2 fingerprint (SETTINGS, window update, pseudo-header order, priority); supports presets and JSON."""

    def __init__(
        self,
        settings: list[H2Setting],
        window_update: int,
        pseudo_header_order: list[str],
        *,
        headers_priority: Optional[HeadersPriority] = None,
        priority_frames: Optional[list[PriorityFrame]] = None,
        priority_config: Optional[PriorityConfig] = None,
    ) -> None: ...
    @property
    def priority_config(self) -> PriorityConfig: ...
    @staticmethod
    def chrome_131() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_144() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_145() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_146() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_147() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_148() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_149() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_150() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def chrome_151() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def firefox_133() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def firefox_147() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def safari_18() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def safari_26() -> H2Profile:
        """HTTP/2 fingerprint preset for this browser version."""
    @staticmethod
    def from_json(json_str: str) -> H2Profile:
        """Build an H2Profile from a JSON string."""
    @staticmethod
    def from_json_file(path: str) -> H2Profile:
        """Build an H2Profile from a JSON file path."""
    @staticmethod
    def from_h2_frames(data: bytes) -> H2Profile:
        """Build an H2Profile by parsing captured HTTP/2 frame bytes."""
    def to_json(self) -> str:
        """Serialize this profile to a JSON string."""
    def to_dict(self) -> dict[str, Any]:
        """Serialize this profile to a dict."""

class TcpFingerprint:
    """TCP-layer fingerprint (window size, MSS, scale, TTL, buffers); supports OS presets and JA4T."""

    def __init__(
        self,
        *,
        window_size: Optional[int] = None,
        mss: Optional[int] = None,
        window_scale: Optional[int] = None,
        ttl: Optional[int] = None,
        tcp_nodelay: Optional[bool] = None,
        recv_buf_size: Optional[int] = None,
        send_buf_size: Optional[int] = None,
    ) -> None: ...
    @staticmethod
    def from_ja4t(ja4t: str) -> TcpFingerprint:
        """Build a TcpFingerprint from a JA4T fingerprint string."""
    def to_ja4t(self) -> Optional[str]:
        """Render this fingerprint as a JA4T string, if possible."""
    @staticmethod
    def chrome() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def chrome_win() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def chrome_linux() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def chrome_macos() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def firefox() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def firefox_win() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def firefox_linux() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def firefox_macos() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""
    @staticmethod
    def safari() -> TcpFingerprint:
        """TCP fingerprint preset for this browser/OS."""

# ---------------------------------------------------------------------------
# Client Pool
# ---------------------------------------------------------------------------

class ClientPool:
    """Pool of clients that rotates across multiple fingerprints to reduce correlation."""

    def __init__(
        self,
        clients: list[Client],
        *,
        rotation: str = "round_robin",
    ) -> None: ...
    def acquire(self) -> Client:
        """Return the next client according to the rotation policy."""
    def add(self, client: Client) -> None:
        """Add a client to the pool."""
    def __len__(self) -> int: ...

# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------

def pending_requests() -> int:
    """Number of async operations handed to Python that have not finished yet (process-wide)."""

async def drain_pending(timeout: Optional[float] = None) -> bool:
    """Wait until nothing is in flight; ``timeout`` in seconds, ``None`` waits forever. True if it drained."""

def blocking_drain_pending(timeout: Optional[float] = None) -> bool:
    """Blocking counterpart of :func:`drain_pending`."""

def set_log_level(level: str, *, format: str = "compact") -> bool:
    """Set the global log level (e.g. ``"info"`` or a filter like ``"lkrequest=debug"``); ``format`` selects the output style."""

def enable_metrics() -> MetricsCollector:
    """Enable Prometheus metrics collection and return the ``MetricsCollector``."""

def validate_fingerprint_consistency(
    *,
    tls_profile: Optional[str] = None,
    h2_profile: Optional[str] = None,
    tcp_fingerprint: Optional[str] = None,
) -> dict[str, Any]:
    """Validate that a TLS/HTTP2/TCP fingerprint combination is consistent; returns a dict with ``valid`` and ``warnings``."""

def metrics_snapshot() -> dict[str, Any]:
    """Return a process-level counters dict (bytes in/out, requests, connections); requires the ``telemetry`` feature for real values."""
