"""
WebSocket 示例

演示同步和异步 WebSocket 连接。
"""

import asyncio
import lkrequest
from lkrequest.blocking import Client as BlockingClient


def sync_websocket():
    """同步 WebSocket 示例"""
    print("=== 同步 WebSocket ===")

    client = BlockingClient.chrome_144()
    session = client.session()

    ws = session.ws_connect(
        "wss://echo.websocket.org",
        headers={"Origin": "https://echo.websocket.org"},
    )
    print(f"已连接: {repr(ws)}")

    # 接收服务器的欢迎消息
    greeting = ws.recv()
    print(f"服务器欢迎: text={greeting.is_text()}")

    # 发送文本消息
    ws.send_text("Hello from lkrequest (sync)!")
    echo = ws.recv()
    print(f"Echo 回复: text={echo.is_text()}")

    # 发送二进制消息
    ws.send_binary(b"\x01\x02\x03\x04")
    binary_echo = ws.recv()
    print(f"Binary echo: binary={binary_echo.is_binary()}")

    ws.close()
    print("连接已关闭\n")


async def async_websocket():
    """异步 WebSocket 示例"""
    print("=== 异步 WebSocket ===")

    client = lkrequest.Client.chrome_144()
    session = client.session()

    ws = await session.ws_connect(
        "wss://echo.websocket.org",
        headers={"Origin": "https://echo.websocket.org"},
    )
    print(f"已连接: {repr(ws)}")

    # 接收欢迎消息
    greeting = await ws.recv()
    print(f"服务器欢迎: text={greeting.is_text()}")

    # 发送并接收
    await ws.send_text("Hello from lkrequest (async)!")
    echo = await ws.recv()
    print(f"Echo 回复: text={echo.is_text()}")

    await ws.close()
    print("连接已关闭\n")


def ws_message_types():
    """WsMessage 类型示例"""
    print("=== WsMessage 类型 ===")

    text_msg = lkrequest.WsMessage.text("hello")
    print(f"Text: is_text={text_msg.is_text()}, is_binary={text_msg.is_binary()}, is_close={text_msg.is_close()}")
    print(f"repr: {repr(text_msg)}")

    binary_msg = lkrequest.WsMessage.binary(b"\x00\x01\x02")
    print(f"Binary: is_text={binary_msg.is_text()}, is_binary={binary_msg.is_binary()}")


if __name__ == "__main__":
    sync_websocket()
    asyncio.run(async_websocket())
    ws_message_types()
    print()
