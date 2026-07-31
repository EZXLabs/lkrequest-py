"""
自定义指纹配置示例

演示 TlsProfile / H2Profile / TcpFingerprint 的完全自定义用法。
"""

import lkrequest


def tls_profile_examples():
    """TlsProfile 示例"""
    print("=== TlsProfile ===\n")

    # --- 使用预设 ---
    print("--- 预设 TlsProfile ---")
    profiles = {
        "Chrome 131": lkrequest.TlsProfile.chrome_131(),
        "Chrome 144": lkrequest.TlsProfile.chrome_144(),
        "Firefox 133": lkrequest.TlsProfile.firefox_133(),
        "Firefox 147": lkrequest.TlsProfile.firefox_147(),
        "Safari 18": lkrequest.TlsProfile.safari_18(),
        "Safari 26": lkrequest.TlsProfile.safari_26(),
    }
    for name, p in profiles.items():
        print(f"  {name}: cipher_suites={len(p.cipher_suites)}, "
              f"groups={len(p.supported_groups)}, alpn={p.alpn_protocols}")

    # --- 查看 profile 属性 ---
    print("\n--- Profile 属性 ---")
    chrome = lkrequest.TlsProfile.chrome_144()
    print(f"  name: {chrome.name}")
    print(f"  cipher_suites: {chrome.cipher_suites[:5]}...")
    print(f"  supported_groups: {chrome.supported_groups}")
    print(f"  signature_algorithms: {chrome.signature_algorithms[:5]}...")
    print(f"  alpn_protocols: {chrome.alpn_protocols}")

    # --- 序列化 ---
    print("\n--- JSON 序列化 ---")
    json_str = chrome.to_json()
    print(f"  to_json() 长度: {len(json_str)} chars")

    restored = lkrequest.TlsProfile.from_json(json_str)
    print(f"  from_json() name: {restored.name}")

    d = chrome.to_dict()
    print(f"  to_dict() keys: {list(d.keys())[:5]}...")

    # --- 完全自定义 ---
    print("\n--- 完全自定义 TlsProfile ---")
    extensions = [
        lkrequest.ExtensionSpec(lkrequest.ExtType.SNI),
        lkrequest.ExtensionSpec(lkrequest.ExtType.EC_POINT_FORMATS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_GROUPS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SESSION_TICKET),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SIGNATURE_ALGORITHMS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_VERSIONS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.PSK_KEY_EXCHANGE_MODES),
        lkrequest.ExtensionSpec(lkrequest.ExtType.KEY_SHARE),
        lkrequest.ExtensionSpec(lkrequest.ExtType.ALPN),
        lkrequest.ExtensionSpec(lkrequest.ExtType.STATUS_REQUEST),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SIGNED_CERTIFICATE_TIMESTAMP),
        lkrequest.ExtensionSpec(lkrequest.ExtType.COMPRESS_CERTIFICATE),
        lkrequest.ExtensionSpec(lkrequest.ExtType.RENEGOTIATION_INFO),
        lkrequest.ExtensionSpec(lkrequest.ExtType.PADDING),
    ]

    custom_tls = lkrequest.TlsProfile(
        "my_custom_browser",
        cipher_suites=[
            0x1301,  # TLS_AES_128_GCM_SHA256
            0x1302,  # TLS_AES_256_GCM_SHA384
            0x1303,  # TLS_CHACHA20_POLY1305_SHA256
            0xc02b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ],
        extensions=extensions,
        supported_groups=[0x001d, 0x0017, 0x0018],  # x25519, secp256r1, secp384r1
        signature_algorithms=[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        key_share_curves=[0x001d, 0x0017],
        alpn_protocols=["h2", "http/1.1"],
        tls_min_version="1.2",
        tls_max_version="1.3",
        ec_point_formats=[0],
        compression_methods=[0],
        grease=lkrequest.GreaseConfig(
            cipher_suite=True,
            extensions=True,
            supported_groups=True,
            supported_versions=True,
            key_share=True,
        ),
        padding=lkrequest.PaddingStrategy.block_align(128, 512),
        alps_protocols=["h2"],
        compress_cert_algorithms=[2],  # brotli
        record_size_limit=16385,
        session_id_length=32,
        randomization=lkrequest.RandomizationConfig(shuffle_extensions=True),
    )
    print(f"  name: {custom_tls.name}")
    print(f"  cipher_suites: {custom_tls.cipher_suites}")
    print(f"  alpn: {custom_tls.alpn_protocols}")


def h2_profile_examples():
    """H2Profile 示例"""
    print("\n\n=== H2Profile ===\n")

    # --- 预设 ---
    print("--- 预设 H2Profile ---")
    chrome_h2 = lkrequest.H2Profile.chrome_144()
    firefox_h2 = lkrequest.H2Profile.firefox_147()
    safari_h2 = lkrequest.H2Profile.safari_26()
    print(f"  Chrome 144: {repr(chrome_h2)}")
    print(f"  Firefox 147: {repr(firefox_h2)}")
    print(f"  Safari 26: {repr(safari_h2)}")

    # --- 序列化 ---
    print("\n--- JSON 序列化 ---")
    json_str = chrome_h2.to_json()
    print(f"  to_json() 长度: {len(json_str)} chars")

    d = chrome_h2.to_dict()
    print(f"  to_dict() keys: {list(d.keys())}")

    restored = lkrequest.H2Profile.from_json(json_str)
    print(f"  from_json(): {repr(restored)}")

    # --- 自定义 ---
    print("\n--- 自定义 H2Profile ---")

    # H2 Settings (使用小写 snake_case 名称)
    settings = [
        lkrequest.H2Setting("header_table_size", 65536),
        lkrequest.H2Setting("enable_push", 0),
        lkrequest.H2Setting("max_concurrent_streams", 1000),
        lkrequest.H2Setting("initial_window_size", 6291456),
        lkrequest.H2Setting("max_header_list_size", 262144),
    ]

    # 也可以用整数 ID
    settings_by_id = [
        lkrequest.H2Setting(1, 65536),   # header_table_size
        lkrequest.H2Setting(2, 0),       # enable_push
        lkrequest.H2Setting(3, 1000),    # max_concurrent_streams
        lkrequest.H2Setting(4, 6291456), # initial_window_size
    ]

    # Headers Priority (weight 最大 255)
    headers_priority = lkrequest.HeadersPriority(
        stream_dependency=0,
        weight=255,
        exclusive=True,
    )

    # Priority Frames
    priority_frames = [
        lkrequest.PriorityFrame(stream_id=3, dependency=0, weight=201, exclusive=False),
        lkrequest.PriorityFrame(stream_id=5, dependency=0, weight=101, exclusive=False),
        lkrequest.PriorityFrame(stream_id=7, dependency=0, weight=1, exclusive=False),
        lkrequest.PriorityFrame(stream_id=9, dependency=7, weight=1, exclusive=False),
        lkrequest.PriorityFrame(stream_id=11, dependency=3, weight=1, exclusive=False),
    ]

    custom_h2 = lkrequest.H2Profile(
        settings,
        15663105,  # window_update
        ["method", "authority", "scheme", "path"],  # pseudo header order (不含 : 前缀)
        headers_priority=headers_priority,
        priority_frames=priority_frames,
    )
    print(f"  自定义 H2Profile: {repr(custom_h2)}")


def tcp_fingerprint_examples():
    """TcpFingerprint 示例"""
    print("\n\n=== TcpFingerprint ===\n")

    # --- 预设 ---
    print("--- 预设 TCP 指纹 ---")
    presets = [
        ("Chrome (通用)", lkrequest.TcpFingerprint.chrome),
        ("Chrome Windows", lkrequest.TcpFingerprint.chrome_win),
        ("Chrome Linux", lkrequest.TcpFingerprint.chrome_linux),
        ("Chrome macOS", lkrequest.TcpFingerprint.chrome_macos),
        ("Firefox (通用)", lkrequest.TcpFingerprint.firefox),
        ("Firefox Windows", lkrequest.TcpFingerprint.firefox_win),
        ("Firefox Linux", lkrequest.TcpFingerprint.firefox_linux),
        ("Firefox macOS", lkrequest.TcpFingerprint.firefox_macos),
        ("Safari", lkrequest.TcpFingerprint.safari),
    ]
    for name, factory in presets:
        tcp = factory()
        print(f"  {name}: {repr(tcp)}")

    # --- 自定义 ---
    print("\n--- 自定义 TCP 指纹 ---")
    custom_tcp = lkrequest.TcpFingerprint(
        window_size=65535,
        mss=1460,
        window_scale=8,
        ttl=128,
        tcp_nodelay=True,
        recv_buf_size=65536,
        send_buf_size=65536,
    )
    print(f"  自定义 TCP: {repr(custom_tcp)}")

    # --- JA4T ---
    print("\n--- JA4T 格式 ---")
    tcp_chrome = lkrequest.TcpFingerprint.chrome_win()
    ja4t = tcp_chrome.to_ja4t()
    print(f"  Chrome Win JA4T: {ja4t}")

    if ja4t:
        from_ja4t = lkrequest.TcpFingerprint.from_ja4t(ja4t)
        print(f"  from_ja4t(): {repr(from_ja4t)}")


def ext_type_examples():
    """ExtType 常量示例"""
    print("\n\n=== ExtType 常量 ===\n")

    all_types = [
        ("SNI", lkrequest.ExtType.SNI),
        ("ALPN", lkrequest.ExtType.ALPN),
        ("SUPPORTED_GROUPS", lkrequest.ExtType.SUPPORTED_GROUPS),
        ("SIGNATURE_ALGORITHMS", lkrequest.ExtType.SIGNATURE_ALGORITHMS),
        ("KEY_SHARE", lkrequest.ExtType.KEY_SHARE),
        ("SUPPORTED_VERSIONS", lkrequest.ExtType.SUPPORTED_VERSIONS),
        ("PSK_KEY_EXCHANGE_MODES", lkrequest.ExtType.PSK_KEY_EXCHANGE_MODES),
        ("SESSION_TICKET", lkrequest.ExtType.SESSION_TICKET),
        ("STATUS_REQUEST", lkrequest.ExtType.STATUS_REQUEST),
        ("COMPRESS_CERTIFICATE", lkrequest.ExtType.COMPRESS_CERTIFICATE),
        ("APPLICATION_SETTINGS", lkrequest.ExtType.APPLICATION_SETTINGS),
        ("PADDING", lkrequest.ExtType.PADDING),
        ("ENCRYPTED_CLIENT_HELLO", lkrequest.ExtType.ENCRYPTED_CLIENT_HELLO),
    ]
    for name, val in all_types:
        print(f"  {name}: {val} (0x{val:04x})")


def combined_example():
    """组合使用自定义指纹"""
    print("\n\n=== 组合使用自定义指纹 ===\n")

    tls = lkrequest.TlsProfile.chrome_144()
    h2 = lkrequest.H2Profile.chrome_144()
    tcp = lkrequest.TcpFingerprint.chrome_win()

    client = lkrequest.Client(
        tls_profile=tls,
        h2_profile=h2,
        tcp_fingerprint=tcp,
        total_timeout=30.0,
    )
    print(f"客户端: {repr(client)}")
    info = client.fingerprint_info()
    print(f"指纹信息: {info}")


if __name__ == "__main__":
    tls_profile_examples()
    h2_profile_examples()
    tcp_fingerprint_examples()
    ext_type_examples()
    combined_example()
