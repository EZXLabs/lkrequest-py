"""
Cookie 管理示例

演示 Cookie 的设置、获取、删除和高级用法。
"""

from lkrequest.blocking import Client


def main():
    client = Client.chrome_144()
    session = client.session()

    url = "https://httpbin.org"

    # --- 设置 Cookie ---
    print("=== 设置 Cookie ===")
    session.set_cookie(url, "session_id", "abc123")
    session.set_cookie(url, "user", "alice")
    session.set_cookie(url, "lang", "zh-CN")
    print("已设置 3 个 Cookie")

    # --- 获取单个 Cookie ---
    print(f"\n=== 获取单个 Cookie ===")
    val = session.get_cookie(url, "session_id")
    print(f"session_id = {val}")

    # --- 获取所有 Cookie ---
    print(f"\n=== 获取所有 Cookie ===")
    cookies = session.get_cookies(url)
    for name, value in cookies:
        print(f"  {name} = {value}")

    # --- Cookie Header 字符串 ---
    header = session.cookie_header(url)
    print(f"\nCookie Header: {header}")

    # --- 带属性设置 Cookie ---
    print(f"\n=== set_cookie_with_attrs ===")
    session.set_cookie_with_attrs(
        url,
        "secure_token",
        "xyz789",
        path="/api",
        domain="httpbin.org",
        secure=True,
        http_only=True,
    )
    val = session.get_cookie(url + "/api", "secure_token")
    print(f"secure_token (path=/api) = {val}")

    # --- 验证 Cookie 发送 ---
    print(f"\n=== 验证 Cookie 请求 ===")
    resp = session.get("https://httpbin.org/cookies")
    print(f"服务器收到的 Cookies: {resp.json()['cookies']}")

    # --- 删除 Cookie ---
    print(f"\n=== 删除 Cookie ===")
    session.remove_cookie(url, "lang")
    val = session.get_cookie(url, "lang")
    print(f"删除后 lang = {val}")

    # --- Cookie Override ---
    print(f"\n=== Cookie Override ===")
    session.set_cookie(url, "token", "original_value")
    resp = session.get(
        "https://httpbin.org/cookies",
        cookie_override={"token": "overridden_value"},
    )
    print(f"Override 后服务器看到: {resp.json()['cookies']}")

    # --- 清除所有 Cookie ---
    print(f"\n=== 清除所有 Cookie ===")
    session.clear_cookies()
    cookies = session.get_cookies(url)
    print(f"清除后 Cookie 数量: {len(cookies)}")


if __name__ == "__main__":
    main()
