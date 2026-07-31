"""
Prometheus 指标示例

演示 MetricsCollector 的指标收集和导出。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    # === 启用指标收集 ===
    print("=== 启用指标收集 ===")
    collector = lkrequest.enable_metrics()
    print(f"MetricsCollector: {repr(collector)}")

    # === 执行一些请求 ===
    print(f"\n=== 执行请求 ===")
    client = Client.chrome_144()
    session = client.session()

    session.get("https://httpbin.org/get")
    session.post("https://httpbin.org/post", json={"test": True})
    session.get("https://httpbin.org/status/404")
    session.get("https://httpbin.org/get")

    print("已发送 4 个请求")

    # === 快照 ===
    print(f"\n=== 指标快照 ===")
    snap = collector.snapshot()
    for key, value in snap.items():
        print(f"  {key}: {value}")

    # === Prometheus 导出格式 ===
    print(f"\n=== Prometheus exposition format ===")
    prom_text = collector.prometheus_text()
    print(prom_text[:500])
    if len(prom_text) > 500:
        print(f"... (总长度 {len(prom_text)} chars)")

    # === 重置指标 ===
    print(f"\n=== 重置指标 ===")
    collector.reset()
    snap_after = collector.snapshot()
    print(f"重置后快照: {snap_after}")

    # === 再次收集 ===
    session.get("https://httpbin.org/get")
    snap_new = collector.snapshot()
    print(f"新请求后快照: {snap_new}")


if __name__ == "__main__":
    main()
