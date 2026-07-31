"""
会话池示例

演示异步 SessionPool 和同步 BlockingSessionPool 的用法。

注意：实际使用需要可用的代理。示例中仅展示 API 用法。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def blocking_session_pool():
    """同步会话池示例"""
    print("=== 同步会话池 (BlockingSessionPool) ===")

    client = BlockingClient.chrome_144()

    pool = lkrequest.BlockingSessionPool(
        client,
        proxies=["http://127.0.0.1:8080"],
        max_sessions=10,
        idle_timeout=120.0,
    )

    # 查看池状态
    stats = pool.stats()
    print(f"池状态: idle={stats.idle_sessions}, max={stats.max_sessions}")

    # 使用 context manager 获取会话
    # guard = pool.acquire()
    # with guard as session:
    #     resp = session.get("https://httpbin.org/get")
    #     print(f"状态码: {resp.status_code}")

    # 替换坏会话
    # fresh_guard = pool.acquire_fresh(bad_guard)
    # pool.mark_bad(bad_guard)


async def async_session_pool():
    """异步会话池示例"""
    print(f"\n=== 异步会话池 (SessionPool) ===")

    client = lkrequest.Client.chrome_144()

    pool = lkrequest.SessionPool(
        client,
        proxies=["http://127.0.0.1:8080"],
        max_sessions=10,
        idle_timeout=120.0,
    )

    # 查看池状态
    stats = await pool.stats()
    print(f"池状态: idle={stats.idle_sessions}, max={stats.max_sessions}")

    # 使用 async with 获取会话
    # guard = await pool.acquire()
    # async with guard as session:
    #     resp = await session.get("https://httpbin.org/get")
    #     print(f"状态码: {resp.status_code}")

    # 高并发使用模式
    # async def worker(pool):
    #     guard = await pool.acquire()
    #     async with guard as session:
    #         try:
    #             resp = await session.get("https://example.com")
    #             return resp.status_code
    #         except Exception:
    #             await pool.mark_bad(guard)
    #             fresh = await pool.acquire_fresh(guard)
    #             async with fresh as new_session:
    #                 return (await new_session.get("https://example.com")).status_code
    #
    # results = await asyncio.gather(*[worker(pool) for _ in range(20)])

    print("  支持方法: acquire(), acquire_fresh(), mark_bad(), stats()")


def session_pool_stats():
    """SessionPoolStats 示例"""
    print(f"\n=== SessionPoolStats ===")

    stats = lkrequest.SessionPoolStats
    print(f"  属性: idle_sessions, max_sessions")


if __name__ == "__main__":
    blocking_session_pool()
    asyncio.run(async_session_pool())
    session_pool_stats()
