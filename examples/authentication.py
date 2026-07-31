"""
认证方式示例

演示 Bearer Token 和 Basic Auth 的用法。
"""

from lkrequest.blocking import Client


def main():
    client = Client.chrome_144()
    session = client.session()

    # --- Bearer Token 认证 ---
    resp = session.get(
        "https://httpbin.org/bearer",
        bearer_auth="my-secret-token-12345",
    )
    print("[Bearer Auth]")
    print(f"  状态码: {resp.status_code}")
    print(f"  authenticated: {resp.json()['authenticated']}")
    print(f"  token: {resp.json()['token']}")

    # --- Basic Auth ---
    resp = session.get(
        "https://httpbin.org/basic-auth/myuser/mypass",
        basic_auth=("myuser", "mypass"),
    )
    print(f"\n[Basic Auth]")
    print(f"  状态码: {resp.status_code}")
    print(f"  authenticated: {resp.json()['authenticated']}")
    print(f"  user: {resp.json()['user']}")

    # --- Basic Auth 失败 ---
    resp = session.get(
        "https://httpbin.org/basic-auth/myuser/mypass",
        basic_auth=("wrong_user", "wrong_pass"),
    )
    print(f"\n[Basic Auth 失败]")
    print(f"  状态码: {resp.status_code}")  # 401


if __name__ == "__main__":
    main()
