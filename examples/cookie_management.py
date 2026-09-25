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

    # --- 读回完整属性 ---
    # get_cookies() 只给 (name, value)，区分不了同名但 path 不同的两条。
    print("\n=== get_cookies_with_attrs ===")
    session.set_cookie_raw(url, "token=ROOT; Path=/")
    session.set_cookie_raw(url + "/api", "token=API; Path=/api")
    for c in session.get_cookies_with_attrs(url + "/api/orders"):
        print(
            f"  {c.name}={c.value} path={c.path} domain={c.domain} "
            f"secure={c.secure} http_only={c.http_only} same_site={c.same_site} "
            f"expires={c.expires} host_only={c.host_only}"
        )

    # 整个 jar（跨域）—— 持久化登录态、或同步给浏览器时用这个
    print("\n=== get_all_cookies ===")
    for c in session.get_all_cookies():
        kind = "持久" if c.is_persistent else "会话"
        print(f"  [{kind}] {c.domain}{c.path} {c.name}")

    # Cookie 可哈希，两个 jar 可以直接做集合差
    before = set(session.get_all_cookies())
    session.set_cookie(url, "brand_new", "1")
    added = set(session.get_all_cookies()) - before
    print(f"新增的 Cookie: {[c.name for c in added]}")

    # --- Cookie 头的顺序（线上可见，按 Chrome 的规则） ---
    # path 长的在前，同 path 下先设的在前。get_all_cookies() 按创建顺序从旧到新
    # 返回，所以把它写回一个新 session，发出的 Cookie 头能逐字还原。
    print("\n=== Cookie 顺序 ===")
    ordered = Client.chrome_144().session()
    for set_cookie in ["b=1; Path=/", "a=2; Path=/", "api=3; Path=/api"]:
        ordered.set_cookie_raw(url, set_cookie)
    print(f"  创建顺序: {[c.name for c in ordered.get_all_cookies()]}")
    print(f"  发送顺序: {ordered.cookie_header(url + '/api/orders')}")

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
