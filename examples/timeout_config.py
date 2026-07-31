"""
超时配置示例

演示多层超时控制：客户端级别、会话级别、请求级别。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    # === TimeoutConfig 对象 ===
    print("=== TimeoutConfig ===")
    tc = lkrequest.TimeoutConfig(
        dns=5.0,            # DNS 解析超时
        tcp_connect=10.0,   # TCP 连接超时
        tls_handshake=10.0, # TLS 握手超时
        ttfb=15.0,          # 首字节超时
        total=30.0,         # 总超时
    )
    print(f"TimeoutConfig: {repr(tc)}")

    # 部分配置
    tc_partial = lkrequest.TimeoutConfig(total=60.0)
    print(f"仅 total: {repr(tc_partial)}")

    # === 客户端级超时 ===
    print(f"\n=== 客户端级超时 ===")
    client = Client(
        dns_timeout=5.0,
        tcp_connect_timeout=10.0,
        tls_handshake_timeout=10.0,
        ttfb_timeout=15.0,
        total_timeout=30.0,
    )
    session = client.session()
    resp = session.get("https://httpbin.org/get")
    print(f"状态码: {resp.status_code}, 耗时: {resp.elapsed:.3f}s")

    # === 请求级超时（覆盖客户端配置） ===
    print(f"\n=== 请求级超时 ===")
    resp = session.get("https://httpbin.org/get", timeout=5.0)
    print(f"5s 超时请求: {resp.status_code}, 耗时: {resp.elapsed:.3f}s")

    # === 超时触发示例 ===
    print(f"\n=== 超时触发 ===")
    try:
        fast_client = Client(total_timeout=0.001)
        fast_session = fast_client.session()
        fast_session.get("https://httpbin.org/delay/5")
    except lkrequest.LkTimeoutError as e:
        print(f"超时异常: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"其他异常: {type(e).__name__}: {e}")

    # === ResourceLimits ===
    print(f"\n=== ResourceLimits ===")
    rl = lkrequest.ResourceLimits(
        max_response_body_size=1024 * 1024,  # 1MB
        max_connections_per_session=16,
    )
    print(f"ResourceLimits: {repr(rl)}")

    client_limited = Client(
        max_response_body_size=10 * 1024 * 1024,
        max_connections_per_session=8,
    )
    print(f"受限客户端: {repr(client_limited)}")


if __name__ == "__main__":
    main()
