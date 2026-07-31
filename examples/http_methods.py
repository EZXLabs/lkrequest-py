"""
所有 HTTP 方法示例

演示 GET / POST / PUT / DELETE / HEAD / PATCH / OPTIONS。
"""

from lkrequest.blocking import Client


def main():
    client = Client.chrome_144()
    session = client.session()

    # --- GET ---
    resp = session.get("https://httpbin.org/get")
    print(f"GET     → {resp.status_code}")

    # --- POST ---
    resp = session.post("https://httpbin.org/post", json={"action": "create"})
    print(f"POST    → {resp.status_code}, json={resp.json()['json']}")

    # --- PUT ---
    resp = session.put("https://httpbin.org/put", json={"action": "update"})
    print(f"PUT     → {resp.status_code}, json={resp.json()['json']}")

    # --- PATCH ---
    resp = session.patch("https://httpbin.org/patch", json={"field": "new_value"})
    print(f"PATCH   → {resp.status_code}, json={resp.json()['json']}")

    # --- DELETE ---
    resp = session.delete("https://httpbin.org/delete")
    print(f"DELETE  → {resp.status_code}")

    # --- HEAD (只返回 Headers，没有 body) ---
    resp = session.head("https://httpbin.org/get")
    print(f"HEAD    → {resp.status_code}, body长度={len(resp.content)}")

    # --- OPTIONS ---
    resp = session.options("https://httpbin.org/get")
    print(f"OPTIONS → {resp.status_code}, Allow={resp.headers.get('Allow', 'N/A')}")


if __name__ == "__main__":
    main()
