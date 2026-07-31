"""
代理和代理池示例

演示单代理、多跳代理链、代理池、坏代理配置和健康检查。

注意：运行此示例需要可用的代理服务器。
      示例中使用的代理地址需要替换为你自己的。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def proxy_basics():
    """代理基础用法"""
    print("=== 代理基础用法 ===")

    client = BlockingClient.chrome_144()

    # 会话级代理
    session = client.session(proxy="http://127.0.0.1:8080")
    print(f"会话级代理: {repr(session)}")

    # 请求级代理覆盖（临时使用不同代理）
    # resp = session.get("https://httpbin.org/ip", proxy="http://other-proxy:8080")

    print("  支持的代理格式:")
    print("    HTTP:   http://host:port")
    print("    HTTPS:  https://host:port")
    print("    SOCKS5: socks5://host:port")
    print("    带认证:  socks5://YOUR_PROXY_USER:YOUR_PROXY_PASS@proxy.example.com:1080:port")

    # 多跳代理链（按 client -> target 顺序）
    chain = lkrequest.ProxyConfig.parse_chain(
        [
            "socks5://hop1.example:1080",
            "socks5h://hop2.example:1080",
        ]
    )
    chain_session = client.session(proxy=chain, http3_with_fallback=True)
    print(f"多跳代理链: {chain}")
    print(f"代理跳数: {chain.hop_count()}")
    print(f"链式会话: {repr(chain_session)}")
    print("  QUIC/H3 要求每一跳都是 SOCKS5；含 HTTP 跳时可回退 H2")


def proxy_pool_config():
    """代理池配置示例"""
    print("\n=== 代理池配置 ===")

    # --- BadProxyConfig: 坏代理标记策略 ---
    bad_config = lkrequest.BadProxyConfig(
        failure_threshold=5,  # 连续失败 5 次标记为坏代理
        window=120.0,  # 在 120 秒窗口内计算失败次数
        cooldown_duration=600.0,  # 冷却 10 分钟后重新启用
        max_cooldowns=5,  # 最多冷却 5 次后永久禁用
    )
    print(f"BadProxyConfig: {repr(bad_config)}")

    # --- HealthCheckConfig: 健康检查配置 ---
    health_config = lkrequest.HealthCheckConfig(
        interval=30.0,  # 每 30 秒检查一次
        timeout=3.0,  # 检查超时 3 秒
        target_host="www.google.com",
        target_port=443,
    )
    print(f"HealthCheckConfig: {repr(health_config)}")

    # --- ProxyPool: 代理池 ---
    proxies = [
        "http://proxy1:8080",
        "http://proxy2:8080",
        "socks5://proxy3:1080",
    ]

    # Round-robin 轮换
    pool_rr = lkrequest.ProxyPool(
        proxies,
        rotation="round_robin",
        bad_proxy_config=bad_config,
        health_check=health_config,
    )
    print(f"\n代理池 (round_robin): {repr(pool_rr)}")

    # 随机轮换
    pool_random = lkrequest.ProxyPool(
        proxies,
        rotation="random",
    )
    print(f"代理池 (random): {repr(pool_random)}")

    # 带最大代理数限制
    pool_limited = lkrequest.ProxyPool(
        proxies,
        max_proxies=10,
        rotation="round_robin",
    )
    print(f"代理池 (max=10): {repr(pool_limited)}")


async def proxy_pool_usage():
    """代理池使用示例"""
    print("\n=== 代理池使用 ===")

    pool = lkrequest.ProxyPool(
        ["http://127.0.0.1:8080", "http://127.0.0.1:8081"],
        rotation="round_robin",
        bad_proxy_config=lkrequest.BadProxyConfig(failure_threshold=3),
    )

    # 获取一个代理
    proxy = await pool.acquire()
    print(f"获取代理: {proxy}")

    # 标记代理为坏
    # pool.mark_bad(proxy)
    print("可用方法: acquire(), mark_bad(identity)")


if __name__ == "__main__":
    proxy_basics()
    proxy_pool_config()
    asyncio.run(proxy_pool_usage())
