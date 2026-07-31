"""
流式响应示例

演示 StreamingResponse 的用法 —— 逐块接收大文件/长响应。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def blocking_streaming():
    """同步流式响应"""
    print("=== 同步流式响应 ===")

    client = BlockingClient.chrome_144()
    session = client.session()

    stream = session.send_streaming("GET", "https://httpbin.org/get")
    print(f"状态码: {stream.status_code}")
    print(f"Headers: {stream.headers.get('content-type')}")

    # 读取完整 body
    body = stream.bytes()
    print(f"Body 长度: {len(body)} bytes")

    # 也可以读取为文本
    stream2 = session.send_streaming("GET", "https://httpbin.org/html")
    text = stream2.text()
    print(f"Text 长度: {len(text)} chars")


async def async_streaming():
    """异步流式响应"""
    print(f"\n=== 异步流式响应 ===")

    client = lkrequest.Client.chrome_144()
    session = client.session()

    # --- 完整读取 ---
    stream = await session.send_streaming("GET", "https://httpbin.org/get")
    print(f"状态码: {stream.status_code}")
    body = await stream.bytes()
    print(f"bytes() 长度: {len(body)}")

    # --- 文本读取 ---
    stream2 = await session.send_streaming("GET", "https://httpbin.org/html")
    text = await stream2.text()
    print(f"text() 长度: {len(text)}")

    # --- 逐块读取 (async for) ---
    print(f"\n--- 逐块读取 ---")
    stream3 = await session.send_streaming("GET", "https://httpbin.org/get")
    total = 0
    chunk_count = 0
    async for chunk in stream3:
        total += len(chunk)
        chunk_count += 1
    print(f"收到 {chunk_count} 个 chunk, 总计 {total} bytes")

    # --- 使用 chunk() 方法手动读取 ---
    print(f"\n--- chunk() 手动读取 ---")
    stream4 = await session.send_streaming("GET", "https://httpbin.org/get")
    chunks = []
    while True:
        chunk = await stream4.chunk()
        if chunk is None:
            break
        chunks.append(chunk)
    print(f"手动读取 {len(chunks)} 个 chunk")

    # --- 带参数的流式请求 ---
    print(f"\n--- 带参数的流式请求 ---")
    stream5 = await session.send_streaming(
        "GET",
        "https://httpbin.org/get",
        headers={"Accept": "application/json"},
        params={"key": "value"},
        timeout=30.0,
    )
    data = await stream5.text()
    print(f"带参数结果: {len(data)} chars")


if __name__ == "__main__":
    blocking_streaming()
    asyncio.run(async_streaming())
