"""
连接池统计示例

演示 PoolStats 的使用，监控连接池状态。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def blocking_pool_stats():
    """同步连接池统计"""
    print("=== 同步连接池统计 ===\n")

    client = BlockingClient.chrome_144()
    session = client.session()

    # 请求前的连接池状态
    stats = session.pool_stats()
    print(f"请求前:")
    print(f"  h2_connections: {stats.h2_connections}")
    print(f"  h1_connections: {stats.h1_connections}")
    print(f"  total: {stats.total}")
    print(f"  max_total: {stats.max_total}")
    print(f"  at_capacity: {stats.at_capacity}")
    print(f"  repr: {repr(stats)}")

    # 发送请求后
    session.get("https://httpbin.org/get")
    stats = session.pool_stats()
    print(f"\n请求后:")
    print(f"  h2: {stats.h2_connections}, h1: {stats.h1_connections}, total: {stats.total}")

    # 多次请求后
    session.get("https://httpbin.org/post", json={"a": 1})
    session.get("https://httpbin.org/get")
    stats = session.pool_stats()
    print(f"\n3 次请求后:")
    print(f"  h2: {stats.h2_connections}, h1: {stats.h1_connections}, total: {stats.total}")


async def async_pool_stats():
    """异步连接池统计"""
    print(f"\n=== 异步连接池统计 ===\n")

    client = lkrequest.Client.chrome_144()
    session = client.session()

    stats = session.pool_stats()
    print(f"初始: total={stats.total}, at_capacity={stats.at_capacity}")

    await session.get("https://httpbin.org/get")
    stats = session.pool_stats()
    print(f"请求后: total={stats.total}")


if __name__ == "__main__":
    blocking_pool_stats()
    asyncio.run(async_pool_stats())
