"""
连接预热示例

演示 preconnect / preconnect_many / prefetch 的用法。
提前建立 TLS 连接以减少首次请求延迟。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def blocking_prewarming():
    """同步连接预热"""
    print("=== 同步连接预热 ===\n")

    client = BlockingClient.chrome_144()
    session = client.session()

    # --- preconnect: 预建单个连接 ---
    print("--- preconnect ---")
    session.preconnect("https://httpbin.org")
    print("已预连接 httpbin.org")

    # 后续请求复用已有连接，延迟更低
    resp = session.get("https://httpbin.org/get")
    print(f"请求耗时: {resp.elapsed:.3f}s (应该更快)")

    # --- preconnect_many: 批量预建连接 ---
    print(f"\n--- preconnect_many ---")
    results = session.preconnect_many([
        "https://httpbin.org",
        "https://www.example.com",
    ])
    for r in results:
        status = "成功" if r.get("success") else f"失败: {r.get('error')}"
        print(f"  {r.get('url', 'N/A')}: {status}")

    # --- prefetch: 批量预热（建立完整连接） ---
    print(f"\n--- prefetch ---")
    results = session.prefetch([
        "https://httpbin.org",
        "https://www.example.com",
    ])
    for r in results:
        status = "成功" if r.get("success") else f"失败: {r.get('error')}"
        duration = r.get("duration_ms", 0)
        print(f"  {r.get('url', 'N/A')}: {status} ({duration:.0f}ms)")


async def async_prewarming():
    """异步连接预热"""
    print(f"\n=== 异步连接预热 ===\n")

    client = lkrequest.Client.chrome_144()
    session = client.session()

    # --- 异步 preconnect ---
    print("--- async preconnect ---")
    await session.preconnect("https://httpbin.org")
    print("已异步预连接")

    # --- 异步 preconnect_many ---
    print(f"\n--- async preconnect_many ---")
    results = await session.preconnect_many([
        "https://httpbin.org",
        "https://www.example.com",
    ])
    for r in results:
        print(f"  {r.get('url', 'N/A')}: {'成功' if r.get('success') else '失败'}")

    # --- 异步 prefetch ---
    print(f"\n--- async prefetch ---")
    results = await session.prefetch([
        "https://httpbin.org",
        "https://www.example.com",
    ])
    for r in results:
        status = "成功" if r.get("success") else f"失败: {r.get('error')}"
        duration = r.get("duration_ms", 0)
        print(f"  {r.get('url', 'N/A')}: {status} ({duration:.0f}ms)")

    # --- prefetch 后请求 ---
    print(f"\n--- prefetch 后请求 ---")
    resp = await session.get("https://httpbin.org/get")
    print(f"请求耗时: {resp.elapsed:.3f}s")


if __name__ == "__main__":
    blocking_prewarming()
    asyncio.run(async_prewarming())
