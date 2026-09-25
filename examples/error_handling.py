"""
错误处理示例

演示所有异常类型及其使用场景。
"""

import json

import lkrequest
from lkrequest.blocking import Client


def main():
    client = Client.chrome_144()
    session = client.session()

    # === 异常层级 ===
    print("=== 异常层级 ===")
    print(f"RequestError (基类)")
    print(f"  ├── TlsError          - TLS 握手失败")
    print(f"  ├── ProxyError        - 代理连接失败")
    print(f"  ├── HttpStatusError   - HTTP 状态错误")
    print(f"  ├── LkConnectionError - 连接失败")
    print(f"  ├── LkTimeoutError    - 超时")
    print(f"  ├── TooManyRedirectsError - 重定向过多")
    print(f"  ├── ResourceLimitError    - 资源限制超出")
    print("  └── JsonDecodeError       - body 不是合法 JSON")
    print("     （JsonDecodeError 同时也是 json.JSONDecodeError）")

    # === HttpStatusError ===
    print(f"\n=== HttpStatusError ===")
    resp_404 = session.get("https://httpbin.org/status/404")
    print(f"404 响应 ok={resp_404.ok}")
    try:
        resp_404.error_for_status()
    except lkrequest.HttpStatusError as e:
        print(f"捕获: {type(e).__name__}: {e}")

    resp_500 = session.get("https://httpbin.org/status/500")
    try:
        resp_500.error_for_status()
    except lkrequest.HttpStatusError as e:
        print(f"捕获: {type(e).__name__}: {e}")

    # === TooManyRedirectsError ===
    print(f"\n=== TooManyRedirectsError ===")
    limited_session = client.session(max_redirects=2)
    try:
        limited_session.get("https://httpbin.org/redirect/10")
    except lkrequest.TooManyRedirectsError as e:
        print(f"捕获: {type(e).__name__}: {e}")

    # === JsonDecodeError ===
    # 两个基类都能接住：库自己的 RequestError，以及标准库的 json.JSONDecodeError。
    print("\n=== JsonDecodeError ===")
    html = session.get("https://httpbin.org/html")
    try:
        html.json()
    except lkrequest.RequestError as e:
        print(f"按 RequestError 捕获: {type(e).__name__}: {e}")
        print(f"  同时也是 json.JSONDecodeError: {isinstance(e, json.JSONDecodeError)}")
        print(f"  失败位置: pos={e.pos} line={e.lineno} col={e.colno}")

    # === 通用错误处理模式 ===
    print(f"\n=== 通用错误处理模式 ===")

    def safe_request(session, url):
        try:
            resp = session.get(url, timeout=10.0)
            resp.error_for_status()
            return resp
        except lkrequest.LkTimeoutError:
            print(f"  超时: {url}")
        except lkrequest.LkConnectionError:
            print(f"  连接失败: {url}")
        except lkrequest.TlsError:
            print(f"  TLS 错误: {url}")
        except lkrequest.ProxyError:
            print(f"  代理错误: {url}")
        except lkrequest.HttpStatusError as e:
            print(f"  HTTP 错误: {url} → {e}")
        except lkrequest.TooManyRedirectsError:
            print(f"  重定向过多: {url}")
        except lkrequest.ResourceLimitError:
            print(f"  资源限制: {url}")
        except lkrequest.RequestError as e:
            print(f"  请求错误: {url} → {e}")
        return None

    result = safe_request(session, "https://httpbin.org/get")
    if result:
        print(f"  成功: {result.status_code}")

    safe_request(session, "https://httpbin.org/status/503")

    # === 异常继承检查 ===
    print(f"\n=== 异常继承关系 ===")
    errors = [
        lkrequest.TlsError,
        lkrequest.ProxyError,
        lkrequest.HttpStatusError,
        lkrequest.LkConnectionError,
        lkrequest.LkTimeoutError,
        lkrequest.TooManyRedirectsError,
        lkrequest.ResourceLimitError,
        lkrequest.JsonDecodeError,
    ]
    for err_cls in errors:
        is_request_error = issubclass(err_cls, lkrequest.RequestError)
        print(f"  {err_cls.__name__} → RequestError: {is_request_error}")


if __name__ == "__main__":
    main()
