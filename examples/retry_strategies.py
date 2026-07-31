"""
重试策略示例

演示指数退避、固定间隔和自定义 callable 重试策略。
"""

import lkrequest
from lkrequest.blocking import Client


def main():
    client = Client.chrome_144()

    # === 指数退避重试 ===
    print("=== 指数退避重试 (ExponentialBackoff) ===")
    retry_exp = lkrequest.ExponentialBackoff(
        max_retries=3,      # 最多重试 3 次
        base_delay=0.5,     # 基础延迟 0.5 秒
        max_delay=30.0,     # 最大延迟 30 秒
        jitter=True,        # 添加随机抖动
    )
    print(f"  配置: {repr(retry_exp)}")

    session1 = client.session(retry=retry_exp)
    resp = session1.get("https://httpbin.org/get")
    print(f"  结果: {resp.status_code}")

    # === 固定间隔重试 ===
    print(f"\n=== 固定间隔重试 (FixedInterval) ===")
    retry_fixed = lkrequest.FixedInterval(
        max_retries=5,      # 最多重试 5 次
        interval=1.0,       # 每次间隔 1 秒
    )
    print(f"  配置: {repr(retry_fixed)}")

    session2 = client.session(retry=retry_fixed)
    resp = session2.get("https://httpbin.org/get")
    print(f"  结果: {resp.status_code}")

    # === 自定义重试策略 (callable) ===
    print(f"\n=== 自定义重试策略 (callable) ===")

    def smart_retry(attempt: int, error: str | None, status: int | None) -> float | None:
        """
        智能重试策略：
        - attempt: 当前重试次数 (从 1 开始)
        - error: 错误信息 (连接错误等)
        - status: HTTP 状态码 (请求成功但状态码异常时)
        返回 float 表示等待秒数，None 表示放弃重试
        """
        print(f"  [smart_retry] attempt={attempt}, error={error}, status={status}")

        if status == 429:
            return min(2 ** attempt, 60)

        if status and 500 <= status < 600:
            if attempt <= 3:
                return 1.0 * attempt
            return None

        if error and attempt <= 2:
            return 0.5
        return None

    session3 = client.session(retry=smart_retry)
    resp = session3.get("https://httpbin.org/get")
    print(f"  结果: {resp.status_code}")

    # === Lambda 重试 ===
    print(f"\n=== Lambda 重试 ===")
    session4 = client.session(
        retry=lambda attempt, error, status: 0.5 if attempt < 3 else None
    )
    resp = session4.get("https://httpbin.org/get")
    print(f"  结果: {resp.status_code}")

    # === 记录重试日志的策略 ===
    print(f"\n=== 重试日志记录 ===")
    retry_log = []

    def logging_retry(attempt, error, status):
        retry_log.append({
            "attempt": attempt,
            "error": error,
            "status": status,
        })
        if attempt <= 3:
            return 0.1
        return None

    session5 = client.session(retry=logging_retry)
    resp = session5.get("https://httpbin.org/get")
    print(f"  重试日志: {retry_log}")
    print(f"  (正常请求不会触发重试，日志应该为空)")


if __name__ == "__main__":
    main()
