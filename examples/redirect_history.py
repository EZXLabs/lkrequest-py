"""
重定向历史示例

演示重定向链跟踪和 RedirectRecord 的使用。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def blocking_redirect():
    """同步重定向历史"""
    print("=== 重定向历史 ===\n")

    client = BlockingClient.chrome_144()
    session = client.session()

    # --- 无重定向 ---
    resp = session.get("https://httpbin.org/get")
    print(f"无重定向:")
    print(f"  was_redirected: {resp.was_redirected}")
    print(f"  history: {resp.history}")

    # --- 单次重定向 ---
    print(f"\n单次重定向:")
    resp = session.get("https://httpbin.org/redirect/1")
    print(f"  was_redirected: {resp.was_redirected}")
    print(f"  最终 URL: {resp.url}")
    print(f"  history ({len(resp.history)} 跳):")
    for hop in resp.history:
        print(f"    {hop.status_code} {hop.url} → {hop.redirect_to}")
        print(f"    repr: {repr(hop)}")

    # --- 多次重定向 ---
    print(f"\n多次重定向:")
    resp = session.get("https://httpbin.org/redirect/3")
    print(f"  最终状态码: {resp.status_code}")
    print(f"  最终 URL: {resp.url}")
    print(f"  总跳数: {len(resp.history)}")
    for i, hop in enumerate(resp.history):
        print(f"    [{i}] {hop.status_code} {hop.url}")
        print(f"         → {hop.redirect_to}")
        headers_dict = hop.headers.to_dict()
        location = headers_dict.get("location", "N/A")
        print(f"         Location: {location}")

    # --- 限制重定向次数 ---
    print(f"\n限制重定向次数:")
    limited = client.session(max_redirects=2)
    try:
        limited.get("https://httpbin.org/redirect/5")
    except lkrequest.TooManyRedirectsError as e:
        print(f"  重定向超限: {e}")


async def async_redirect():
    """异步重定向历史"""
    print(f"\n=== 异步重定向历史 ===\n")

    client = lkrequest.Client.chrome_144()
    session = client.session()

    resp = await session.get("https://httpbin.org/redirect/2")
    print(f"最终: {resp.status_code} {resp.url}")
    for hop in resp.history:
        print(f"  {hop.status_code} {hop.url} → {hop.redirect_to}")


if __name__ == "__main__":
    blocking_redirect()
    asyncio.run(async_redirect())
