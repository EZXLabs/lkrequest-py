"""
日志配置示例

演示 set_log_level 的用法。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    # === 日志级别 ===
    print("=== 日志级别 ===")
    print("可用级别: trace, debug, info, warn, error, off")

    # 设置为 info 级别
    lkrequest.set_log_level("info")
    print("已设置: info")

    # 设置为 debug（更详细）
    lkrequest.set_log_level("debug")
    print("已设置: debug")

    # 关闭日志
    lkrequest.set_log_level("off")
    print("已设置: off")

    # === 过滤指令 ===
    print(f"\n=== 过滤指令 ===")
    print("支持 tracing 过滤语法，可以为不同模块设置不同级别")

    lkrequest.set_log_level("lkrequest=debug,lktls=trace")
    print("已设置: lkrequest=debug,lktls=trace")

    lkrequest.set_log_level("lkrequest=info")
    print("已设置: lkrequest=info")

    # === 日志格式 ===
    print(f"\n=== 日志格式 ===")
    lkrequest.set_log_level("info", format="compact")
    print("已设置: info (compact 格式)")

    # === 实际使用场景 ===
    print(f"\n=== 实际使用 ===")
    lkrequest.set_log_level("off")

    client = Client.chrome_144()
    session = client.session()
    resp = session.get("https://httpbin.org/get")
    print(f"请求完成: {resp.status_code}")

    # 调试时开启详细日志
    # lkrequest.set_log_level("debug")
    # resp = session.get("https://httpbin.org/get")


if __name__ == "__main__":
    main()
