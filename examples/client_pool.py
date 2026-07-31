"""
客户端池示例

演示 ClientPool 的用法 —— 在多个指纹之间轮换。
"""

import lkrequest


def main():
    # === 创建客户端池 ===
    print("=== ClientPool ===")

    # 创建不同指纹的客户端
    clients = [
        lkrequest.Client.chrome_144(),
        lkrequest.Client.firefox_147(),
        lkrequest.Client.safari_26(),
    ]

    # Round-robin 轮换
    pool = lkrequest.ClientPool(clients, rotation="round_robin")
    print(f"初始大小: {len(pool)}")

    # === 从池中获取客户端 ===
    print(f"\n=== Round-Robin 轮换 ===")
    for i in range(6):
        client = pool.acquire()
        info = client.fingerprint_info()
        print(f"  #{i}: {info.get('tls_profile', 'N/A')}")

    # === 动态添加客户端 ===
    print(f"\n=== 动态添加 ===")
    randomized = lkrequest.Client.chrome_144().randomize_fingerprint()
    pool.add(randomized)
    print(f"添加后大小: {len(pool)}")

    # === 随机轮换 ===
    print(f"\n=== 随机轮换 ===")
    random_pool = lkrequest.ClientPool(
        [
            lkrequest.Client.chrome_144(),
            lkrequest.Client.firefox_147(),
            lkrequest.Client.safari_26(),
        ],
        rotation="random",
    )
    for i in range(5):
        client = random_pool.acquire()
        info = client.fingerprint_info()
        print(f"  #{i}: {info.get('tls_profile', 'N/A')}")

    # === 实际使用模式 ===
    print(f"\n=== 实际使用模式 ===")
    pool2 = lkrequest.ClientPool(
        [lkrequest.Client.chrome_144(), lkrequest.Client.firefox_147()],
        rotation="round_robin",
    )

    # 每次请求使用不同的指纹
    urls = [
        "https://httpbin.org/get?page=1",
        "https://httpbin.org/get?page=2",
        "https://httpbin.org/get?page=3",
    ]
    print("  使用不同指纹访问多个 URL:")
    print("  (实际运行需要网络连接)")
    for url in urls:
        client = pool2.acquire()
        session = client.session()
        # resp = session.get(url)  # 需要 await for async
        info = client.fingerprint_info()
        print(f"    {url} → 指纹: {info.get('tls_profile', 'N/A')}")


if __name__ == "__main__":
    main()
