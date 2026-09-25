"""
响应对象详解示例

演示 Response 的所有属性和方法。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    client = Client.chrome_144()
    session = client.session()

    resp = session.get("https://httpbin.org/get")

    # --- 基本属性 ---
    print("=== 基本属性 ===")
    print(f"status_code : {resp.status_code}")
    print(f"ok          : {resp.ok}")
    print(f"url         : {resp.url}")
    print(f"elapsed     : {resp.elapsed:.4f}s")
    print(f"encoding    : {resp.encoding}")
    print(f"was_redirected: {resp.was_redirected}")

    # --- HTTP 版本 ---
    version_name = {
        lkrequest.HttpVersion.HTTP11: "HTTP/1.1",
        lkrequest.HttpVersion.H2: "HTTP/2",
    }
    print(f"version     : {version_name.get(resp.version, 'Unknown')}")

    # --- Content ---
    print(f"\ncontent_length: {resp.content_length}")
    print(f"len(content)  : {len(resp.content)} bytes")
    print(f"len(resp)     : {len(resp)} bytes")
    print(f"bool(resp)    : {bool(resp)}")

    # --- text() 和 json() (带缓存) ---
    text1 = resp.text()
    text2 = resp.text()  # 缓存，不重复解码
    print(f"\ntext() 长度: {len(text1)} chars")
    print(f"text() 缓存: {text1 is text2}")

    data = resp.json()
    print(f"json() 结果类型: {type(data).__name__}")

    # --- 字符集解码 ---
    # text() 按 Content-Type 声明的 charset 解码, 未声明时回落 UTF-8。
    print("\n=== 字符集解码 ===")
    gbk = session.get("https://httpbin.org/encoding/utf8")
    print(f"声明的 charset: {gbk.encoding}")
    print(f"text() 前 40 字: {gbk.text()[:40]!r}")

    # 服务器没声明或声明错了, 用 encoding= 覆盖。无法解码的字节转为 U+FFFD,
    # 不会抛异常 —— 需要精确字节时用 content。
    print(f"text(encoding='latin-1') 前 40 字: {gbk.text(encoding='latin-1')[:40]!r}")

    # --- memoryview (零拷贝, 仅 full-API wheel 支持) ---
    try:
        mv = memoryview(resp)
        print(f"\nmemoryview 长度: {len(mv)} bytes (零拷贝)")
    except TypeError:
        # abi3 wheels omit the raw buffer protocol; .content still works.
        print(f"\nmemoryview: abi3 wheel 不支持, 用 resp.content ({len(resp.content)} bytes)")

    # --- Headers (HeaderMap) ---
    print("\n=== Headers (HeaderMap) ===")
    headers = resp.headers
    print(f"类型: {type(headers).__name__}")
    print(f"数量: {len(headers)}")
    print(f"Content-Type: {headers['content-type']}")
    print(f"get('X-None'): {headers.get('X-None')}")
    print(f"get('X-None', 'default'): {headers.get('X-None', 'default')}")
    print(f"'content-type' in headers: {'content-type' in headers}")

    print(f"\nkeys(): {headers.keys()[:3]}...")
    print(f"get_all('content-type'): {headers.get_all('content-type')}")

    d = headers.to_dict()
    print(f"to_dict() 类型: {type(d).__name__}, 键数: {len(d)}")

    print(f"\nitems() 示例:")
    for k, v in headers.items()[:3]:
        print(f"  {k}: {v}")

    # --- headers_list ---
    hl = resp.headers_list
    print(f"\nheaders_list 类型: {type(hl).__name__}, 数量: {len(hl)}")

    # --- Cookies ---
    print(f"\ncookies: {resp.cookies}")

    # --- 重定向历史 ---
    resp2 = session.get("https://httpbin.org/redirect/2")
    print(f"\n=== 重定向历史 ===")
    print(f"最终 URL   : {resp2.url}")
    print(f"was_redirected: {resp2.was_redirected}")
    print(f"history 长度: {len(resp2.history)}")
    for i, hop in enumerate(resp2.history):
        print(f"  [{i}] {hop.status_code} {hop.url} → {hop.redirect_to}")

    # --- error_for_status ---
    print(f"\n=== error_for_status ===")
    resp_ok = session.get("https://httpbin.org/status/200")
    resp_ok.error_for_status()  # 不抛异常
    print("200: OK (no exception)")

    resp_err = session.get("https://httpbin.org/status/404")
    try:
        resp_err.error_for_status()
    except lkrequest.HttpStatusError as e:
        print(f"404: 捕获异常 {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
