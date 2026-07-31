"""
证书配置示例

演示 CA 证书管理、禁用验证和系统证书。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    # === 禁用证书验证（仅开发/调试用） ===
    print("=== 禁用证书验证 ===")
    client_no_verify = Client(verify=False)
    print(f"verify=False: {repr(client_no_verify)}")

    # 异步版本
    async_client_no_verify = lkrequest.Client(verify=False)
    print(f"async verify=False: {repr(async_client_no_verify)}")

    # === 使用系统证书 ===
    print(f"\n=== 系统证书 ===")
    client_native = Client(use_native_certs=True)
    print(f"use_native_certs: {repr(client_native)}")

    session = client_native.session()
    resp = session.get("https://httpbin.org/get")
    print(f"使用系统证书请求: {resp.status_code}")

    # === CA 证书 (PEM 格式 - bytes) ===
    print(f"\n=== CA 证书 (PEM) ===")
    pem_data = b"-----BEGIN CERTIFICATE-----\nZHVtbXk=\n-----END CERTIFICATE-----\n"
    client_pem = Client(ca_cert_pem=pem_data)
    print(f"ca_cert_pem: {repr(client_pem)}")

    # === CA 证书 (DER 格式 - bytes) ===
    print(f"\n=== CA 证书 (DER) ===")
    der_data = b"\x30\x82\x01\x00"  # 示例 DER 数据
    client_der = Client(ca_cert_der=der_data)
    print(f"ca_cert_der: {repr(client_der)}")

    # === CA 证书文件路径 ===
    print(f"\n=== CA 证书文件路径 ===")
    try:
        client_file = Client(ca_cert="/path/to/ca-bundle.crt")
    except OSError as e:
        print(f"文件不存在时抛出: {type(e).__name__}: {e}")

    # === ECH (Encrypted Client Hello) ===
    print(f"\n=== ECH 配置 ===")
    client_ech = Client(ech_config=b"\x00\x01\x02\x03")
    print(f"client ECH: {repr(client_ech)}")

    session_ech = client_ech.session(ech_config=b"\x00\x01\x02\x03")
    print(f"session ECH: {repr(session_ech)}")


if __name__ == "__main__":
    main()
