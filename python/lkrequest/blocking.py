"""
lkrequest.blocking - Synchronous HTTP client API.

Usage:
    from lkrequest.blocking import Client

    client = Client.chrome_131()
    session = client.session()
    response = session.get("https://example.com")
    print(response.text())
"""

from lkrequest._lkrequest import (
    BlockingClient as Client,
    BlockingSession as Session,
    BlockingSessionPool as SessionPool,
    BlockingSessionGuard as SessionGuard,
    BlockingWsConnection as WsConnection,
    BlockingStreamingResponse as StreamingResponse,
    Response,
    HeaderMap,
    TimeoutConfig,
    ResourceLimits,
    Multipart,
    Part,
    ProxyConfig,
    BadProxyConfig,
    HealthCheckConfig,
    ExponentialBackoff,
    FixedInterval,
    Middleware,
    WsMessage,
    TlsProfile,
    H2Profile,
    PriorityConfig,
    TcpFingerprint,
    ClientPool,
    RequestPriority,
    ProtocolPolicy,
    HttpIntent,
    PreferredHttpVersion,
    Idempotency,
    BrokenQuicPolicy,
    SessionResumptionConfig,
    H2DataFramePolicy,
    TlsSessionResumptionPolicy,
    TlsSessionCachePartitionPolicy,
    NetworkPartitionContext,
)

__all__ = [
    "Client",
    "Session",
    "SessionPool",
    "SessionGuard",
    "WsConnection",
    "StreamingResponse",
    "Response",
    "HeaderMap",
    "TimeoutConfig",
    "ResourceLimits",
    "Multipart",
    "Part",
    "ProxyConfig",
    "BadProxyConfig",
    "HealthCheckConfig",
    "ExponentialBackoff",
    "FixedInterval",
    "Middleware",
    "WsMessage",
    "TlsProfile",
    "H2Profile",
    "PriorityConfig",
    "TcpFingerprint",
    "ClientPool",
    "RequestPriority",
    "ProtocolPolicy",
    "HttpIntent",
    "PreferredHttpVersion",
    "Idempotency",
    "BrokenQuicPolicy",
    "SessionResumptionConfig",
    "H2DataFramePolicy",
    "TlsSessionResumptionPolicy",
    "TlsSessionCachePartitionPolicy",
    "NetworkPartitionContext",
]
