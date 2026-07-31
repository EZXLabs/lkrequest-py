"""
浏览器指纹预设示例

演示所有内置浏览器指纹预设和指纹随机化。
"""

import lkrequest
from lkrequest.blocking import Client as BlockingClient


def preset_fingerprints():
    """所有预设指纹"""
    print("=== 浏览器指纹预设 ===\n")

    presets = [
        ("Chrome 131", lkrequest.Client.chrome_131),
        ("Chrome 144", lkrequest.Client.chrome_144),
        ("Firefox 133", lkrequest.Client.firefox_133),
        ("Firefox 147", lkrequest.Client.firefox_147),
        ("Safari 18", lkrequest.Client.safari_18),
        ("Safari 26", lkrequest.Client.safari_26),
    ]

    for name, factory in presets:
        client = factory()
        info = client.fingerprint_info()
        print(f"{name}:")
        print(f"  TLS: {info.get('tls_profile', 'N/A')}")
        print(f"  H2:  settings={info.get('h2_settings_count', 'N/A')}, window_update={info.get('h2_window_update', 'N/A')}")
        print(f"  TCP: {info.get('tcp_ja4t', 'N/A')}")
        print()

    # 同步版本也有相同的预设
    print("--- 同步版本 ---")
    blocking_presets = [
        ("Chrome 144 (blocking)", BlockingClient.chrome_144),
        ("Firefox 147 (blocking)", BlockingClient.firefox_147),
        ("Safari 26 (blocking)", BlockingClient.safari_26),
    ]
    for name, factory in blocking_presets:
        client = factory()
        print(f"{name}: {repr(client)}")


def custom_string_profiles():
    """使用字符串指定预设"""
    print("\n=== 字符串指定预设 ===")

    client = lkrequest.Client(
        tls_profile="chrome_144",
        h2_profile="chrome_144",
        tcp_fingerprint="chrome_win",
    )
    info = client.fingerprint_info()
    print(f"自定义 (字符串): TLS={info.get('tls_profile')}")

    # 无效的配置名会抛出 ValueError
    try:
        lkrequest.Client(tls_profile="nonexistent")
    except ValueError as e:
        print(f"无效 TLS profile: {e}")

    try:
        lkrequest.Client(h2_profile="nonexistent")
    except ValueError as e:
        print(f"无效 H2 profile: {e}")


def fingerprint_randomization():
    """指纹随机化"""
    print("\n=== 指纹随机化 ===")

    base = lkrequest.Client.chrome_144()
    randomized = base.randomize_fingerprint(shuffle_extensions=True)
    print(f"原始:   {repr(base)}")
    print(f"随机化: {repr(randomized)}")

    # Blocking 版本
    base_b = BlockingClient.chrome_144()
    rand_b = base_b.randomize_fingerprint(shuffle_extensions=True)
    print(f"原始(blocking):   {repr(base_b)}")
    print(f"随机化(blocking): {repr(rand_b)}")


if __name__ == "__main__":
    preset_fingerprints()
    custom_string_profiles()
    fingerprint_randomization()
