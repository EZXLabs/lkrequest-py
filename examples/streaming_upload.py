"""
流式上传示例

演示 body_stream= / content_length= —— 上传时不把整个请求体留在内存里。

body_stream 接受三种源:
  1. file-like 对象(有 read(n) 方法)
  2. 任意 bytes 可迭代对象(生成器、列表、迭代器)
  3. 异步可迭代对象(仅异步客户端)

省略 content_length 即未知长度:HTTP/1.1 走 chunked,HTTP/2 / HTTP/3 走 DATA 帧。
"""

import asyncio
import io
import os
import tempfile

import lkrequest
from lkrequest.blocking import Client as BlockingClient

UPLOAD_URL = "https://httpbin.org/post"


def blocking_upload():
    """同步流式上传"""
    print("=== 同步流式上传 ===")

    client = BlockingClient.chrome_152()
    session = client.session()

    # --- 磁盘文件,已知精确长度 ---
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(b"payload from a real file\n" * 100)
        path = tmp.name
    try:
        with open(path, "rb") as handle:
            resp = session.post(
                UPLOAD_URL,
                body_stream=handle,
                content_length=os.path.getsize(path),
            )
        print(f"文件上传: {resp.status_code}")
    finally:
        os.unlink(path)

    # --- 内存中的 file-like 对象 ---
    resp = session.post(
        UPLOAD_URL, body_stream=io.BytesIO(b"from BytesIO"), content_length=12
    )
    print(f"BytesIO: {resp.status_code}")

    # --- 生成器,未知长度 ---
    def chunks():
        for i in range(5):
            yield f"chunk-{i};".encode()

    resp = session.post(UPLOAD_URL, body_stream=chunks())
    print(f"生成器(未知长度): {resp.status_code}")

    # --- content_length 是精确值,源提前结束会失败 ---
    try:
        session.post(UPLOAD_URL, body_stream=io.BytesIO(b"short"), content_length=999)
    except lkrequest.RequestError as e:
        print(f"长度不匹配被拒: {type(e).__name__}")

    # --- 异步源在同步客户端不可用(没有事件循环驱动 __anext__) ---
    async def async_chunks():
        yield b"nope"

    try:
        session.post(UPLOAD_URL, body_stream=async_chunks())
    except TypeError as e:
        print(f"异步源被拒: {e}")


async def async_upload():
    """异步流式上传"""
    print("\n=== 异步流式上传 ===")

    client = lkrequest.Client.chrome_152()
    session = client.session()

    # --- 同步源在异步客户端同样可用 ---
    resp = await session.post(
        UPLOAD_URL, body_stream=io.BytesIO(b"async + BytesIO"), content_length=15
    )
    print(f"BytesIO: {resp.status_code}")

    # --- 异步生成器 ---
    async def produce():
        for i in range(5):
            await asyncio.sleep(0)  # 让出控制权,模拟真实的异步生产者
            yield f"async-chunk-{i};".encode()

    resp = await session.post(UPLOAD_URL, body_stream=produce())
    print(f"异步生成器: {resp.status_code}")

    # --- 转发另一个响应,两端都不缓冲 ---
    async def relay(url):
        stream = await session.send_streaming("GET", url)
        async for chunk in stream:
            yield chunk

    resp = await session.post(
        UPLOAD_URL, body_stream=relay("https://httpbin.org/bytes/4096")
    )
    print(f"响应转发: {resp.status_code}")

    # --- 源是单次使用的:重试要自己重建源 ---
    # 一旦 transport 认领了源,自动重试、协议回落,以及必须保留请求体的重定向
    # 都无法重放它。需要重试就重新打开文件 / 重新创建生成器。
    for attempt in range(3):
        try:
            resp = await session.post(
                UPLOAD_URL,
                body_stream=io.BytesIO(b"retryable"),  # 每次都是新的源
                content_length=9,
            )
            print(f"第 {attempt + 1} 次尝试成功: {resp.status_code}")
            break
        except lkrequest.RequestError as e:
            print(f"第 {attempt + 1} 次失败,重建源后重试: {e}")


if __name__ == "__main__":
    blocking_upload()
    asyncio.run(async_upload())
