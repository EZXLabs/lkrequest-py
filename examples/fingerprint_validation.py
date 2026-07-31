"""
指纹一致性验证示例

演示 validate_fingerprint_consistency 的用法。
"""

import lkrequest


def main():
    # === 一致的指纹组合 ===
    print("=== 一致的指纹组合 ===")
    result = lkrequest.validate_fingerprint_consistency(
        tls_profile="chrome_144",
        h2_profile="chrome_144",
        tcp_fingerprint="chrome_win",
    )
    print(f"  valid: {result['valid']}")
    print(f"  warnings: {result.get('warnings', [])}")

    # === 混合指纹组合 ===
    print(f"\n=== 混合指纹组合 ===")
    result = lkrequest.validate_fingerprint_consistency(
        tls_profile="chrome_144",
        h2_profile="firefox_147",
        tcp_fingerprint="safari",
    )
    print(f"  valid: {result['valid']}")
    warnings = result.get("warnings", [])
    if warnings:
        for w in warnings:
            print(f"  ⚠ {w}")

    # === 部分指纹验证 ===
    print(f"\n=== 部分指纹验证 ===")
    result = lkrequest.validate_fingerprint_consistency(
        tls_profile="chrome_144",
    )
    print(f"  仅 TLS - valid: {result['valid']}")

    result = lkrequest.validate_fingerprint_consistency(
        tls_profile="firefox_147",
        h2_profile="firefox_147",
    )
    print(f"  TLS+H2 Firefox - valid: {result['valid']}")

    # === 所有有效组合 ===
    print(f"\n=== 常用组合验证 ===")
    combos = [
        ("chrome_131", "chrome_131", "chrome_win"),
        ("chrome_144", "chrome_144", "chrome_win"),
        ("firefox_133", "firefox_133", "firefox_win"),
        ("firefox_147", "firefox_147", "firefox_win"),
        ("safari_18", "safari_18", "safari"),
        ("safari_26", "safari_26", "safari"),
    ]
    for tls, h2, tcp in combos:
        result = lkrequest.validate_fingerprint_consistency(
            tls_profile=tls,
            h2_profile=h2,
            tcp_fingerprint=tcp,
        )
        status = "✓" if result["valid"] else "✗"
        print(f"  {status} TLS={tls}, H2={h2}, TCP={tcp}")


if __name__ == "__main__":
    main()
