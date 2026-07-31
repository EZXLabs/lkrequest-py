"""
基础 HTTP 请求示例

演示同步和异步 API 的 GET/POST 基本用法。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def sync_examples():
    """同步 API 示例"""
    print("=" * 60)
    print("同步 API 示例")
    print("=" * 60)

    client = BlockingClient.chrome_144()
    session = client.session()

    # --- GET 请求 ---
    resp = session.get("https://httpbin.org/get")
    print(f"\n[GET] 状态码: {resp.status_code}")
    print(f"[GET] URL: {resp.url}")
    print(f"[GET] 耗时: {resp.elapsed:.3f}s")

    # --- GET 带查询参数 ---
    resp = session.get(
        "https://httpbin.org/get",
        params={"name": "lkrequest", "version": "0.6.0"},
    )
    data = resp.json()
    print(f"\n[GET+params] args: {data['args']}")

    # --- POST JSON ---
    resp = session.post(
        "https://httpbin.org/post",
        json={"message": "Hello from lkrequest!", "numbers": [1, 2, 3]},
    )
    data = resp.json()
    print(f"\n[POST JSON] 收到: {data['json']}")

    # --- POST 表单 ---
    resp = session.post(
        "https://httpbin.org/post",
        data={"username": "admin", "password": "secret"},
    )
    data = resp.json()
    print(f"[POST form] 表单: {data['form']}")

    # --- POST 原始二进制 ---
    resp = session.post(
        "https://httpbin.org/post",
        body=b"raw binary payload",
        headers={"Content-Type": "application/octet-stream"},
    )
    print(f"[POST body] 状态: {resp.status_code}")

    # --- 自定义 Headers ---
    resp = session.get(
        "https://httpbin.org/headers",
        headers={
            "X-Custom-Header": "my-value",
            "Accept-Language": "zh-CN,zh;q=0.9",
        },
    )
    print(f"\n[Headers] X-Custom-Header: {resp.json()['headers'].get('X-Custom-Header')}")


async def async_examples():
    """异步 API 示例"""
    print("\n" + "=" * 60)
    print("异步 API 示例")
    print("=" * 60)

    client = lkrequest.Client.chrome_144()
    session = client.session()

    # --- 异步 GET ---
    resp = await session.get("https://httpbin.org/get")
    print(f"\n[async GET] 状态码: {resp.status_code}")

    # --- 异步 POST ---
    resp = await session.post(
        "https://httpbin.org/post",
        json={"async": True, "framework": "lkrequest"},
    )
    print(f"[async POST] 返回: {resp.json()['json']}")

    # --- 并发请求 ---
    urls = [f"https://httpbin.org/get?id={i}" for i in range(5)]
    tasks = [session.get(url) for url in urls]
    responses = await asyncio.gather(*tasks)
    print(f"\n[并发] 发送 {len(urls)} 个请求，全部成功: {all(r.ok for r in responses)}")
    for r in responses:
        print(f"  id={r.json()['args']['id']}, 耗时={r.elapsed:.3f}s")


if __name__ == "__main__":
    sync_examples()
    asyncio.run(async_examples())
