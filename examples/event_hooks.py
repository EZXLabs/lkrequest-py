"""
Event Hook 示例

演示轻量级的请求/响应回调机制。
与中间件不同，Event Hook 不能修改请求/响应，只用于观察。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def sync_hooks():
    """同步 Event Hook 示例"""
    print("=== 同步 Event Hook ===")

    # --- 在创建会话时绑定 ---
    def on_request(method, url, headers):
        print(f"  → {method} {url}")

    def on_response(status_code, url, elapsed):
        print(f"  ← {status_code} {url} ({elapsed:.3f}s)")

    client = BlockingClient.chrome_144()
    session = client.session(
        on_request=on_request,
        on_response=on_response,
    )

    print("发送 GET 请求:")
    resp = session.get("https://httpbin.org/get")

    print("\n发送 POST 请求:")
    resp = session.post("https://httpbin.org/post", json={"test": True})

    # --- 动态添加 Hook ---
    print(f"\n=== 动态添加 Hook ===")
    client2 = BlockingClient.chrome_144()
    session2 = client2.session()

    request_count = [0]

    def counter_hook(method, url, headers):
        request_count[0] += 1
        print(f"  请求 #{request_count[0]}: {method} {url}")

    session2.on_request(counter_hook)

    session2.get("https://httpbin.org/get")
    session2.get("https://httpbin.org/get")
    session2.get("https://httpbin.org/get")
    print(f"  总请求数: {request_count[0]}")


async def async_hooks():
    """异步 Event Hook 示例"""
    print("\n=== 异步 Event Hook ===")

    latencies = []

    def track_latency(status_code, url, elapsed):
        latencies.append(elapsed)

    client = lkrequest.Client.chrome_144()
    session = client.session(
        on_request=lambda m, u, h: print(f"  → {m} {u}"),
        on_response=track_latency,
    )

    urls = [f"https://httpbin.org/get?id={i}" for i in range(3)]
    tasks = [session.get(url) for url in urls]
    responses = await asyncio.gather(*tasks)

    print(f"\n  延迟统计 ({len(latencies)} 请求):")
    if latencies:
        print(f"    平均: {sum(latencies) / len(latencies):.3f}s")
        print(f"    最大: {max(latencies):.3f}s")
        print(f"    最小: {min(latencies):.3f}s")


if __name__ == "__main__":
    sync_hooks()
    asyncio.run(async_hooks())
