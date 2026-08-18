"""
lkrequest - Python HTTP client with TLS/HTTP2/TCP fingerprint control.

Powered by Rust for high performance and accurate browser fingerprinting.
"""

from importlib.metadata import version as _distribution_version

from lkrequest._lkrequest import (
    # Async API
    Client,
    Session,
    Response,
    StreamingResponse,
    HeaderMap,
    RedirectRecord,
    # Blocking API
    BlockingStreamingResponse,
    BlockingClient,
    BlockingSession,
    # Configuration
    TimeoutConfig,
    ResourceLimits,
    HttpVersion,
    AcceptEncoding,
    PoolStats,
    SessionPoolStats,
    SessionResumptionConfig,
    # Multipart
    Multipart,
    Part,
    # Proxy
    ProxyConfig,
    ProxyPool,
    BadProxyConfig,
    HealthCheckConfig,
    # Session Pool
    SessionPool,
    SessionGuard,
    BlockingSessionPool,
    BlockingSessionGuard,
    # Retry
    ExponentialBackoff,
    FixedInterval,
    # Request priority (RFC 9218)
    RequestPriority,
    # Protocol policy
    ProtocolPolicy,
    HttpIntent,
    PreferredHttpVersion,
    Idempotency,
    BrokenQuicPolicy,
    # HSTS / scheme-upgrade policy
    Hsts,
    # Fingerprint randomization
    Randomize,
    # Middleware
    Middleware,
    # WebSocket
    WsMessage,
    WsConnection,
    BlockingWsConnection,
    # Metrics
    MetricsCollector,
    # Fingerprint configuration (v0.6.0)
    ExtType,
    ExtensionSpec,
    GreaseConfig,
    PaddingStrategy,
    RandomizationConfig,
    TlsProfile,
    H2Setting,
    HeadersPriority,
    PriorityFrame,
    PriorityConfig,
    H2Profile,
    TcpFingerprint,
    # Client Pool (v0.6.0)
    ClientPool,
    # Exceptions
    RequestError,
    TlsError,
    ProxyError,
    HttpStatusError,
    ConnectionError as LkConnectionError,
    TimeoutError as LkTimeoutError,
    TooManyRedirectsError,
    ResourceLimitError,
    # Functions
    set_log_level,
    enable_metrics,
    metrics_snapshot,
    validate_fingerprint_consistency,
    pending_requests,
    drain_pending,
    blocking_drain_pending,
)

# QuicProfile is only present when built with the `quic-h3` feature
# (maturin develop --features quic-h3). The `as` redundant alias marks it as an
# intentional re-export (added to __all__ below), suppressing the unused-import
# warning for this conditional import.
try:
    from lkrequest._lkrequest import QuicProfile as QuicProfile
except ImportError:
    pass

# Layers (the synthetic-fingerprint layer mask) and NegotiabilityFloor (the
# sig-alg negotiability floor for synthetic policies) are only present when built
# with the `synthetic-fp` feature (maturin develop --features synthetic-fp). The
# `Randomize` policy type itself is always available (Tiers 0/1).
try:
    from lkrequest._lkrequest import Layers as Layers
except ImportError:
    pass

try:
    from lkrequest._lkrequest import NegotiabilityFloor as NegotiabilityFloor
except ImportError:
    pass

__version__ = _distribution_version("lkrequest")

__all__ = [
    # Async API
    "Client",
    "Session",
    "Response",
    "StreamingResponse",
    "HeaderMap",
    "RedirectRecord",
    # Blocking API
    "BlockingClient",
    "BlockingSession",
    "BlockingStreamingResponse",
    # Configuration
    "TimeoutConfig",
    "ResourceLimits",
    "HttpVersion",
    "AcceptEncoding",
    "PoolStats",
    "SessionPoolStats",
    "SessionResumptionConfig",
    # Multipart
    "Multipart",
    "Part",
    # Proxy
    "ProxyConfig",
    "ProxyPool",
    "BadProxyConfig",
    "HealthCheckConfig",
    # Session Pool
    "SessionPool",
    "SessionGuard",
    "BlockingSessionPool",
    "BlockingSessionGuard",
    # Retry
    "ExponentialBackoff",
    "FixedInterval",
    # Request priority (RFC 9218)
    "RequestPriority",
    # Protocol policy
    "ProtocolPolicy",
    "HttpIntent",
    "PreferredHttpVersion",
    "Idempotency",
    "BrokenQuicPolicy",
    # HSTS / scheme-upgrade policy
    "Hsts",
    # Fingerprint randomization
    "Randomize",
    # Middleware
    "Middleware",
    # WebSocket
    "WsMessage",
    "WsConnection",
    "BlockingWsConnection",
    # Metrics
    "MetricsCollector",
    # Fingerprint configuration (v0.6.0)
    "ExtType",
    "ExtensionSpec",
    "GreaseConfig",
    "PaddingStrategy",
    "RandomizationConfig",
    "TlsProfile",
    "H2Setting",
    "HeadersPriority",
    "PriorityFrame",
    "PriorityConfig",
    "H2Profile",
    "TcpFingerprint",
    # Client Pool (v0.6.0)
    "ClientPool",
    # Exceptions
    "RequestError",
    "TlsError",
    "ProxyError",
    "HttpStatusError",
    "LkConnectionError",
    "LkTimeoutError",
    "TooManyRedirectsError",
    "ResourceLimitError",
    # Functions
    "set_log_level",
    "enable_metrics",
    "metrics_snapshot",
    "validate_fingerprint_consistency",
    "pending_requests",
    "drain_pending",
    "blocking_drain_pending",
]

# Feature-gated symbols: only export the ones that were actually importable so
# that `from lkrequest import *` does not fail on a build without the feature.
# - QuicProfile requires the `quic-h3` build feature
# - Layers / NegotiabilityFloor require the `synthetic-fp` build feature
for _optional_name in ("QuicProfile", "Layers", "NegotiabilityFloor"):
    if _optional_name in globals():
        __all__.append(_optional_name)
del _optional_name
