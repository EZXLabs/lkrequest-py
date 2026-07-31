"""
AcceptEncoding 控制示例

演示请求和会话级别的 Accept-Encoding 配置。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    # === AcceptEncoding 常量 ===
    print("=== AcceptEncoding 常量 ===")
    ae = lkrequest.AcceptEncoding
    print(f"GZIP:    {repr(ae.GZIP)}")
    print(f"BR:      {repr(ae.BR)}")
    print(f"DEFLATE: {repr(ae.DEFLATE)}")
    print(f"ZSTD:    {repr(ae.ZSTD)}")
    print(f"ALL:     {repr(ae.ALL)}")

    # === 组合编码 ===
    print(f"\n=== 组合编码 (位或) ===")
    gzip_br = ae.GZIP | ae.BR
    print(f"GZIP | BR: {repr(gzip_br)}")

    gzip_br_zstd = ae.GZIP | ae.BR | ae.ZSTD
    print(f"GZIP | BR | ZSTD: {repr(gzip_br_zstd)}")

    # === 会话级 AcceptEncoding ===
    print(f"\n=== 会话级 AcceptEncoding ===")
    client = Client.chrome_144()

    # 只接受 gzip
    session_gzip = client.session(accept_encoding=ae.GZIP)
    print(f"仅 GZIP 会话: {repr(session_gzip)}")

    # gzip + brotli
    session_combo = client.session(accept_encoding=ae.GZIP | ae.BR)
    print(f"GZIP+BR 会话: {repr(session_combo)}")

    # === 请求级 AcceptEncoding ===
    print(f"\n=== 请求级 AcceptEncoding ===")
    session = client.session()

    resp = session.get(
        "https://httpbin.org/get",
        accept_encoding=ae.GZIP,
    )
    print(f"GZIP 请求: {resp.status_code}")

    resp = session.get(
        "https://httpbin.org/get",
        accept_encoding=ae.GZIP | ae.BR | ae.ZSTD,
    )
    print(f"多编码请求: {resp.status_code}")

    # === 禁用解压 (no_decompress) ===
    print(f"\n=== 禁用自动解压 ===")
    resp_raw = session.get(
        "https://httpbin.org/gzip",
        no_decompress=True,
    )
    print(f"no_decompress: status={resp_raw.status_code}, body={len(resp_raw.content)} bytes")

    resp_normal = session.get("https://httpbin.org/gzip")
    print(f"正常(解压后): status={resp_normal.status_code}, body={len(resp_normal.content)} bytes")


if __name__ == "__main__":
    main()
