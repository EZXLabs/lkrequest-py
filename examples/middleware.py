"""
中间件示例

演示请求/响应中间件的创建和使用（洋葱模型）。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    # === 基础中间件 ===
    print("=== 基础中间件 ===")
    mw = lkrequest.Middleware("my_middleware")
    print(f"中间件: {repr(mw)}")

    # === 请求拦截中间件 ===
    print(f"\n=== 请求拦截中间件 ===")

    def log_request(req_dict):
        """记录每个请求"""
        print(f"  [中间件] → {req_dict['method']} {req_dict['url']}")
        return req_dict

    def log_response(resp_dict):
        """记录每个响应"""
        print(f"  [中间件] ← {resp_dict['status']}")
        return resp_dict

    logger_mw = lkrequest.Middleware(
        "logger",
        on_request=log_request,
        on_response=log_response,
    )

    # 客户端级中间件：所有会话的请求都会经过
    client = Client(middleware=[logger_mw])
    session = client.session()
    resp = session.get("https://httpbin.org/get")
    print(f"  最终状态码: {resp.status_code}")

    # === 请求修改中间件（注入 Header） ===
    print(f"\n=== Header 注入中间件 ===")

    def inject_headers(req_dict):
        """为每个请求注入自定义 Header"""
        if req_dict.get("headers") is None:
            req_dict["headers"] = {}
        req_dict["headers"]["X-Injected-By"] = "middleware"
        req_dict["headers"]["X-Request-Id"] = "req-12345"
        return req_dict

    header_mw = lkrequest.Middleware("header_injector", on_request=inject_headers)

    client2 = Client.chrome_144()
    session2 = client2.session(middleware=[header_mw])
    resp = session2.get("https://httpbin.org/headers")
    received = resp.json()["headers"]
    print(f"  X-Injected-By: {received.get('X-Injected-By')}")
    print(f"  X-Request-Id: {received.get('X-Request-Id')}")

    # === 多层中间件（洋葱模型） ===
    print(f"\n=== 多层中间件 ===")

    def timing_request(req_dict):
        print(f"  [timing] 请求开始: {req_dict['method']} {req_dict['url']}")
        return req_dict

    def timing_response(resp_dict):
        print(f"  [timing] 响应完成: {resp_dict['status']}")
        return resp_dict

    def auth_request(req_dict):
        print(f"  [auth] 注入认证 Header")
        return req_dict

    timing_mw = lkrequest.Middleware(
        "timing",
        on_request=timing_request,
        on_response=timing_response,
    )
    auth_mw = lkrequest.Middleware(
        "auth",
        on_request=auth_request,
    )

    # Client-level middleware must go through the constructor; the chrome_144()
    # preset factory takes no arguments. Pass the fingerprint as a preset name.
    client3 = Client(tls_profile="chrome_144", h2_profile="chrome_144", middleware=[timing_mw])
    session3 = client3.session(middleware=[auth_mw])
    resp = session3.get("https://httpbin.org/get")
    print(f"  结果: {resp.status_code}")

    # === 仅响应中间件 ===
    print(f"\n=== 仅响应中间件 ===")

    def response_only(resp_dict):
        print(f"  [resp_only] 状态: {resp_dict['status']}, URL: {resp_dict.get('url', 'N/A')}")
        return resp_dict

    resp_mw = lkrequest.Middleware("response_logger", on_response=response_only)
    client4 = Client.chrome_144()
    session4 = client4.session(middleware=[resp_mw])
    session4.get("https://httpbin.org/get")


if __name__ == "__main__":
    main()
