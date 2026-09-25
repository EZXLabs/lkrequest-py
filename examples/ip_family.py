"""
地址族选择示例 (ip_family=)
ip_family:
  "any"   默认, 即系统顺序
  "ipv4"  仅用 IPv4
  "ipv6"  仅用 IPv6
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import lkrequest
from lkrequest.blocking import Client


class _QuietHandler(BaseHTTPRequestHandler):
    """只回 200 的最小服务器,存在的意义是让我们观察连到了哪个地址。"""

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _try_get(url, **client_kwargs):
    """发一个请求,把结果或错误折成一行可打印的文本。"""
    try:
        resp = Client(verify=False, **client_kwargs).session().get(url, timeout=10.0)
        return f"{resp.status_code}  remote_addr={resp.diagnostics['remote_addr']}"
    except lkrequest.RequestError as e:
        # 只保留最内层原因,外层的 "TCP connect failed: ..." 包装对演示是噪音。
        return f"{type(e).__name__}: {str(e).split(': ')[-1]}"


def offline_demo():
    """离线部分:localhost 是个现成的双栈目标(127.0.0.1 + ::1)。"""
    print("=" * 74)
    print("第一部分:离线 —— 观察实际选中了哪个地址")
    print("=" * 74)

    resolved = sorted({info[4][0] for info in socket.getaddrinfo("localhost", 80)})
    print(f"\nlocalhost 解析为: {resolved}")
    if "::1" not in resolved:
        print("  ⚠️  本机 localhost 不是双栈,下面的对比会退化(仍能看到报错行为)")

    server = HTTPServer(("127.0.0.1", 0), _QuietHandler)  # 只监听 IPv4
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port
    print(f"本地服务器: 127.0.0.1:{port}(只监听 IPv4)")

    try:
        # --- 同一个 URL,四种设置 ---
        print(f"\n--- GET http://localhost:{port}/ ---")
        for label, kwargs in (
            ("不传(默认)", {}),
            ('ip_family="any"', {"ip_family": "any"}),
            ('ip_family="ipv4"', {"ip_family": "ipv4"}),
            ('ip_family="ipv6"', {"ip_family": "ipv6"}),
        ):
            print(f"  {label:20} -> {_try_get(f'http://localhost:{port}/', **kwargs)}")

        print(
            "\n  说明:ipv6 那行连不上,正是因为过滤后只剩 ::1,而服务器只监听\n"
            "        127.0.0.1 —— 这就是「过滤真的改变了选址」的证据。"
        )

        # --- 目标只解析出被排除的那一族:明确报错 ---
        print("\n--- 目标只有 IPv4,却要求 ipv6 ---")
        print(f"  GET http://127.0.0.1:{port}/")
        print(f"  {_try_get(f'http://127.0.0.1:{port}/', ip_family='ipv6')}")
        print("  说明:报错点名了是哪个设置造成的,不会被误读成 DNS 故障。")
    finally:
        server.shutdown()

    # --- 非法取值当场拒绝 ---
    print("\n--- 非法取值 ---")
    try:
        Client(ip_family="v4")
    except ValueError as e:
        print(f"  Client(ip_family='v4') -> ValueError: {e}")

    # --- 与其它 DNS 选项组合 ---
    print("\n--- 与其它 DNS 选项组合(过滤器包在它们外面)---")
    for label, kwargs in (
        ('dns="cloudflare"', {"dns": "cloudflare", "ip_family": "ipv4"}),
        (
            "system_dns_cache_ttl=30",
            {"system_dns_cache_ttl": 30.0, "ip_family": "ipv4"},
        ),
    ):
        Client(**kwargs)  # 构造成功即说明组合有效
        print(f"  {label:26} + ip_family='ipv4'  -> OK")


def network_demo():
    """联网部分:看真实出口 IP。没有外网就跳过。"""
    print("\n" + "=" * 74)
    print("第二部分:联网 —— 真实出口 IP")
    print("=" * 74)

    # api64 同时发布 A 和 AAAA;api / api6 分别只有一种。
    url = "https://api64.ipify.org/?format=json"
    try:
        families = sorted(
            {
                "IPv6" if info[0] == socket.AF_INET6 else "IPv4"
                for info in socket.getaddrinfo("api64.ipify.org", 443)
            }
        )
    except socket.gaierror as e:
        print(f"\n  跳过:解析 api64.ipify.org 失败({e})")
        return

    print(f"\napi64.ipify.org 在本机解析为: {families}")
    if families == ["IPv4"]:
        print("  (本机没有 IPv6 通路,所以只拿到 A 记录 —— ipv6 那行会明确报错)")

    print(f"\n--- GET {url} ---")
    for label, kwargs in (
        ("不传(默认)", {}),
        ('ip_family="ipv4"', {"ip_family": "ipv4"}),
        ('ip_family="ipv6"', {"ip_family": "ipv6"}),
    ):
        try:
            resp = Client(**kwargs).session().get(url, timeout=15.0)
            seen = resp.json().get("ip", "?")
            print(
                f"  {label:20} -> 目标看到的出口 IP = {seen}"
                f"   (remote_addr={resp.diagnostics['remote_addr']})"
            )
        except lkrequest.RequestError as e:
            print(f"  {label:20} -> {type(e).__name__}: {str(e).split(': ')[-1]}")

    print(
        "\n  在双栈环境里,上面 ipv4 / ipv6 两行会给出**不同地址族的出口 IP** ——\n"
        "  这正是 issue 要解决的问题:不加这个参数,同一条链路可能两者混用。"
    )


if __name__ == "__main__":
    offline_demo()
    network_demo()
