"""
日志配置示例

演示 set_log_level 的用法。一个进程里只有第一次调用生效：它返回 True，
之后的调用都返回 False，也不改变任何设置。所以要在程序启动时调用一次，
把级别、过滤指令和格式一次定好。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    # === 级别与过滤指令 ===
    # 可用级别: trace, debug, info, warn, error, off
    # 也支持 tracing 的过滤语法，为不同模块设置不同级别，例如
    # "lkrequest=debug,lktls=trace"，或 "warn,lkrequest=info"。
    #
    # === 格式 ===
    # format 可选 compact（默认）、full、json，都写到 stderr；
    # 也可以是 logging，交给 Python 的 logging。logger 名为 "lkrequest."
    # 加上 Rust target，配置 logging.getLogger("lkrequest") 即可：
    #     import logging
    #     logging.basicConfig(level=logging.INFO)
    #     lkrequest.set_log_level("info", format="logging")
    installed = lkrequest.set_log_level("warn,lkrequest=info", format="compact")
    print(f"日志已设置: {installed}")  # True

    # 再调用一次不会生效，仍是上面的设置
    print(f"再设置为 debug: {lkrequest.set_log_level('debug')}")  # False

    # === 实际使用 ===
    client = Client.chrome_144()
    session = client.session()
    resp = session.get("https://httpbin.org/get")
    print(f"请求完成: {resp.status_code}")


if __name__ == "__main__":
    main()
