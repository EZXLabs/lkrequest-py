# lkrequest

Python HTTP 客户端，支持 TLS/HTTP2/TCP 指纹控制。基于 Rust 高性能实现。

[English](https://github.com/EZ-XLabs/lkrequest-py/blob/main/README.md) | [简体中文](https://github.com/EZ-XLabs/lkrequest-py/blob/main/README-zh.md)

## 特性

- **浏览器指纹模拟** — Chrome、Firefox、Safari 的 TLS/HTTP2/TCP 指纹预设
- **自定义指纹** — 完全可编程的 `TlsProfile` / `H2Profile` / `TcpFingerprint`，支持 JSON 序列化
- **指纹随机化** — `Client(randomize=Randomize.extension_order())` 按连接置换 TLS 扩展顺序（漂移 JA3、JA4 不变，仍是真实浏览器）；`client.randomize_fingerprint()` 生成唯一变体，降低关联风险
- **客户端池** — `ClientPool` 在多个指纹之间自动轮换
- **异步 & 同步 API** — 同时支持 `asyncio` 异步和传统同步调用
- **WebSocket** — 支持 wss:// 连接，保持指纹一致性
- **流式响应** — `send_streaming()` 逐块接收大文件
- **Cookie 管理** — 自动 Cookie Jar，支持手动管理、属性设置、覆盖
- **代理支持** — HTTP CONNECT / SOCKS5 代理、认证和有序多跳代理链；全 SOCKS5 链支持 QUIC/H3
- **代理池 & 会话池** — 内置代理轮换、坏代理标记和会话管理
- **Multipart** — 文件上传支持
- **重试策略** — 指数退避 / 固定间隔 / 自定义 callable 重试
- **中间件** — 请求/响应拦截和修改（洋葱模型）
- **Event Hook** — 轻量级请求/响应回调
- **连接预热** — `preconnect()` / `prefetch()` 批量预建连接
- **Prometheus 指标** — 内置请求计数、延迟直方图、exposition format 导出
- **请求诊断** — `response.diagnostics` 暴露单请求分阶段计时（DNS/TCP/TLS/TTFB/total）+ remote_addr/protocol/cipher_suite
- **运行指标快照** — `metrics_snapshot()` 拉取进程级 wire 字节 / 连接 / 请求计数（供宿主自采，需 `telemetry` feature 才有真实数值）
- **零拷贝 Response** — `bytes::Bytes` + PyBuffer 协议 + text/json 缓存
- **自动解压** — Brotli / gzip / deflate / zstd，可控 `AcceptEncoding`
- **证书管理** — 自定义 CA / 禁用验证 / 系统证书
- **ECH** — Encrypted Client Hello 支持，包括 TLS/QUIC HelloRetryRequest 处理
- **请求优先级** — `RequestPriority`（RFC 9218 urgency/incremental），`session.get(url, priority=...)`
- **协议策略** — `ProtocolPolicy` / `HttpIntent` 控制 H2/H3 选择、获取与回退（client / session / 请求级）
- **会话恢复控制** — `SessionResumptionConfig` 控制 TLS1.3 PSK / TLS1.2 ticket 恢复
- **请求级协议覆盖** — `preferred_http_version` / `idempotency`（0-RTT 重放安全声明）
- **QUIC / HTTP3** — 可选 feature（`maturin develop --features quic-h3`）：`session(http3_only=True / http3_with_fallback=True / broken_quic_policy=BrokenQuicPolicy.Resilient)`；`Client(quic_fingerprint=..., quic_profile="chrome_150", disable_http3=True)`；独立的 Chrome 146/150 `QuicProfile` 预设（仅 feature 开启时可用）
- **合成指纹（高级）** — 可选 feature（`maturin develop --features synthetic-fp`）：`Client(randomize=Randomize.recombine())` 为每个 session 合成一个跨层（TLS+H2+H3）唯一身份；`Randomize.full()` 进一步对 H2/QUIC 取语料外数值；`Layers` 掩码（如 `Randomize.recombine_layers(Layers.TLS | Layers.H2)`）限定合成层。合成指纹不匹配任何真实浏览器，仅用于黑名单（negative-model）目标，对白名单会立即失败

## 安装

使用 pip：

```bash
pip install lkrequest
```

在使用 uv 管理的项目中：

```bash
uv add lkrequest
```

### 开发环境

使用 venv 和 pip：

```bash
git clone https://github.com/EZ-XLabs/lkrequest-py
cd lkrequest-py
python3 -m venv .venv                 # Linux/macOS
# py -m venv .venv                    # Windows
source .venv/bin/activate             # Linux/macOS
# .venv\Scripts\Activate.ps1          # Windows PowerShell
python -m pip install --upgrade pip
python -m pip install maturin
python -m pip install -e ".[test,lint]"
```

使用 uv（自动创建和管理 `.venv`）：

```bash
git clone https://github.com/EZ-XLabs/lkrequest-py
cd lkrequest-py
uv sync --extra test --extra lint
```

## 快速开始

### 异步 API

```python
import asyncio
import lkrequest

async def main():
    client = lkrequest.Client.chrome_144()
    session = client.session()

    # GET 请求
    resp = await session.get("https://httpbin.org/get", params={"key": "value"})
    print(resp.status_code)  # 200
    print(resp.json())

    # POST JSON
    resp = await session.post("https://httpbin.org/post", json={"hello": "world"})
    print(resp.json())

    # 并发请求
    urls = [f"https://httpbin.org/get?id={i}" for i in range(5)]
    responses = await asyncio.gather(*[session.get(url) for url in urls])

asyncio.run(main())
```

### 同步 API

```python
from lkrequest.blocking import Client

client = Client.chrome_131()
session = client.session()

resp = session.get("https://httpbin.org/get")
print(resp.status_code)
print(resp.text())
print(resp.json())
```

### 所有 HTTP 方法

```python
session.get(url)
session.post(url, json={"key": "value"})
session.put(url, json={"key": "value"})
session.patch(url, json={"field": "new_value"})
session.delete(url)
session.head(url)
session.options(url)
```

### 认证

```python
# Bearer Token
resp = session.get("https://httpbin.org/bearer", bearer_auth="my-token")

# Basic Auth
resp = session.get(
    "https://httpbin.org/basic-auth/user/pass",
    basic_auth=("user", "pass"),
)
```

### 自定义客户端

```python
client = lkrequest.Client(
    tls_profile="chrome_144",
    h2_profile="chrome_144",
    tcp_fingerprint="chrome_win",
    default_headers={"Accept-Language": "zh-CN"},
    header_order=["Host", "User-Agent", "Accept"],
    total_timeout=30.0,
    tcp_connect_timeout=10.0,
    max_connections_per_session=16,
    h2_fallback_h1=True,
    proxy_fallback_direct=True,
)
```

### 重试策略

```python
# 指数退避重试
session = client.session(
    retry=lkrequest.ExponentialBackoff(max_retries=3, base_delay=0.5, max_delay=30.0, jitter=True)
)

# 固定间隔重试
session = client.session(
    retry=lkrequest.FixedInterval(max_retries=5, interval=1.0)
)

# 自定义重试策略 (callable)
def my_retry(attempt: int, error: str | None, status: int | None) -> float | None:
    if status == 429:
        return min(2 ** attempt, 30)
    if attempt < 3:
        return 1.0
    return None  # 放弃

session = client.session(retry=my_retry)
```

### 中间件

```python
def log_request(req_dict):
    print(f"{req_dict['method']} {req_dict['url']}")
    return req_dict

def log_response(resp_dict):
    print(f"  → {resp_dict['status']}")
    return resp_dict

# 客户端级中间件
client = lkrequest.Client(
    middleware=[lkrequest.Middleware("logger", on_request=log_request, on_response=log_response)]
)

# 会话级中间件
session = client.session(
    middleware=[lkrequest.Middleware("auth", on_request=inject_auth)]
)
```

### Event Hook

比中间件更轻量的回调机制，用于观察请求/响应而不修改它们。

```python
def on_req(method, url, headers):
    print(f"→ {method} {url}")

def on_resp(status_code, url, elapsed):
    print(f"← {status_code} {url} ({elapsed:.3f}s)")

# 创建会话时绑定
session = client.session(on_request=on_req, on_response=on_resp)

# 或动态添加
session.on_request(on_req)
session.on_response(on_resp)
```

### Cookie 管理

```python
# 基本操作
session.set_cookie("https://example.com", "token", "abc123")
val = session.get_cookie("https://example.com", "token")
cookies = session.get_cookies("https://example.com")
header = session.cookie_header("https://example.com")

# 带属性设置
session.set_cookie_with_attrs(
    "https://example.com", "secure_token", "xyz",
    path="/api", domain="example.com", secure=True, http_only=True,
)

# 删除与清空
session.remove_cookie("https://example.com", "token")
session.clear_cookies()

# 请求级 Cookie 覆盖
resp = session.get(url, cookie_override={"token": "override_value"})
```

### Multipart 文件上传

```python
mp = lkrequest.Multipart()
mp.text("title", "文件上传")
mp.file("document", "report.pdf", "application/pdf", pdf_bytes)
resp = session.post("https://example.com/upload", multipart=mp)
```

### 流式响应

```python
# 异步
stream = await session.send_streaming("GET", "https://example.com/large-file")
async for chunk in stream:
    process(chunk)

# 或一次性读取
body = await stream.bytes()
text = await stream.text()
```

### 连接预热

提前建立 TLS 连接，减少首次请求延迟。

```python
# 批量预热
results = await session.prefetch([
    "https://api.example.com",
    "https://cdn.example.com",
])
for r in results:
    print(f"{r['url']}: {'ok' if r['success'] else r['error']} ({r['duration_ms']:.0f}ms)")

# 单连接预热
await session.preconnect("https://api.example.com")

# 同步版本
session.preconnect("https://api.example.com")
results = session.prefetch(["https://api.example.com"])
```

### WebSocket

```python
# 异步
ws = await session.ws_connect("wss://echo.websocket.events")
await ws.send_text("hello")
msg = await ws.recv()
async for msg in ws:
    print(msg)
    break
await ws.close()

# 同步
ws = session.ws_connect("wss://echo.websocket.events")
ws.send_text("hello")
msg = ws.recv()
ws.close()
```

### 代理

```python
# 单个代理
session = client.session(proxy="socks5://user:pass@host:1080")

# 多跳代理链：client -> hop1 -> hop2 -> target
chain = lkrequest.ProxyConfig.parse_chain([
    "socks5://user:pass@hop1:1080",
    "socks5h://user:pass@hop2:1080",
])
session = client.session(proxy=chain, http3_with_fallback=True)

# 请求级代理覆盖
resp = await session.get("https://example.com", proxy="http://other-proxy:8080")

# 代理池
pool = lkrequest.ProxyPool(
    ["socks5://proxy1:1080", "socks5://proxy2:1080", "http://proxy3:8080"],
    rotation="round_robin",  # 或 "random"
    bad_proxy_config=lkrequest.BadProxyConfig(
        failure_threshold=5, window=120.0, cooldown_duration=300.0, max_cooldowns=5,
    ),
    health_check=lkrequest.HealthCheckConfig(
        interval=30.0, timeout=3.0, target_host="www.google.com", target_port=443,
    ),
)
proxy = await pool.acquire()
```

基于 TCP 的 HTTP 支持混合使用 HTTP CONNECT 与 SOCKS5 跳。QUIC/HTTP3 要求链中
每一跳都是 SOCKS5；链中含 HTTP 跳时，设置 `http3_with_fallback=True` 可回退 H2。

### 会话池

```python
# 异步
pool = lkrequest.SessionPool(client=client, proxies=[...], max_sessions=10)
guard = await pool.acquire()
async with guard as session:
    resp = await session.get("https://example.com")

# 同步
from lkrequest.blocking import Client, SessionPool
pool = SessionPool(client=client, proxies=[...])
with pool.acquire() as session:
    resp = session.get("https://example.com")
```

### 客户端池

在多个指纹之间自动轮换，降低指纹关联。

```python
pool = lkrequest.ClientPool(
    [lkrequest.Client.chrome_144(), lkrequest.Client.firefox_147(), lkrequest.Client.safari_26()],
    rotation="round_robin",  # 或 "random"
)
client = pool.acquire()
pool.add(lkrequest.Client.chrome_131())  # 动态添加
print(len(pool))  # 4
```

### 自定义指纹

完全可编程的 TLS、HTTP/2 和 TCP 指纹配置。

```python
# 自定义 TLS Profile
tls = lkrequest.TlsProfile(
    "my_browser",
    cipher_suites=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
    extensions=[
        lkrequest.ExtensionSpec(lkrequest.ExtType.SNI),
        lkrequest.ExtensionSpec(lkrequest.ExtType.ALPN),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_GROUPS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.KEY_SHARE),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SUPPORTED_VERSIONS),
        lkrequest.ExtensionSpec(lkrequest.ExtType.SIGNATURE_ALGORITHMS),
    ],
    alpn_protocols=["h2", "http/1.1"],
    grease=lkrequest.GreaseConfig(extensions=True, key_share=True),
    padding=lkrequest.PaddingStrategy.block_align(128, 512),
)

# 自定义 H2 Profile
h2 = lkrequest.H2Profile(
    [
        lkrequest.H2Setting("header_table_size", 65536),
        lkrequest.H2Setting("initial_window_size", 6291456),
        lkrequest.H2Setting("max_header_list_size", 262144),
    ],
    15663105,  # window_update
    ["method", "authority", "scheme", "path"],
    headers_priority=lkrequest.HeadersPriority(0, 255, True),
)

# 自定义 TCP Fingerprint
tcp = lkrequest.TcpFingerprint(window_size=65535, mss=1460, window_scale=8, ttl=128)

# 组合使用
client = lkrequest.Client(tls_profile=tls, h2_profile=h2, tcp_fingerprint=tcp)

# 序列化 / 反序列化
json_str = tls.to_json()
restored = lkrequest.TlsProfile.from_json(json_str)

# 指纹随机化
randomized = client.randomize_fingerprint(shuffle_extensions=True)

# 随机化策略（Randomize）：传给 Client(randomize=...)
# Tier 1（始终可用）：按连接置换 TLS 扩展顺序，漂移 JA3 但仍是真实浏览器
client = lkrequest.Client(tls_profile="chrome_146",
                          randomize=lkrequest.Randomize.extension_order())

# Tier 3a/3b（需 synthetic-fp feature）：每个 session 合成一个跨层唯一身份
#   from lkrequest import Randomize, Layers
#   client = lkrequest.Client(tls_profile="chrome_146",
#                             randomize=Randomize.recombine())                 # 全层
#   client = lkrequest.Client(tls_profile="chrome_146",
#                             randomize=Randomize.recombine_layers(Layers.TLS | Layers.H2))
```

### 指纹一致性验证

```python
result = lkrequest.validate_fingerprint_consistency(
    tls_profile="chrome_144", h2_profile="chrome_144", tcp_fingerprint="chrome_win",
)
print(result["valid"])     # True
print(result["warnings"])  # []
```

### 超时配置

```python
# 客户端级超时
client = lkrequest.Client(
    dns_timeout=5.0,
    tcp_connect_timeout=10.0,
    tls_handshake_timeout=10.0,
    ttfb_timeout=15.0,
    total_timeout=30.0,
)

# 请求级超时覆盖
resp = session.get("https://example.com", timeout=5.0)

# TimeoutConfig 对象
tc = lkrequest.TimeoutConfig(total=30.0, tcp_connect=10.0)

# ResourceLimits
rl = lkrequest.ResourceLimits(max_response_body_size=10*1024*1024, max_connections_per_session=16)
```

### AcceptEncoding 控制

```python
ae = lkrequest.AcceptEncoding

# 会话级
session = client.session(accept_encoding=ae.GZIP | ae.BR)

# 请求级
resp = session.get(url, accept_encoding=ae.GZIP)

# 禁用自动解压
resp = session.get(url, no_decompress=True)
```

### Header / Cookie 顺序

`header_order`（Header 发送顺序）和 `cookie_order`（`Cookie` 头内的排序）可在三个级别设置，下层覆盖上层：

```python
# 客户端级（对该客户端的所有会话生效）
client = lkrequest.Client(
    header_order=["host", "user-agent", "accept", "accept-encoding", "cookie"],
    cookie_order=["session_id", "csrf_token"],
)

# 会话级（覆盖客户端级）
session = client.session(
    header_order=["host", "user-agent", "accept"],
    cookie_order=["session_id", "csrf_token"],
)

# 请求级（覆盖会话级与客户端级）
resp = await session.get(
    url,
    header_order=["host", "user-agent", "accept"],
    cookie_order=["session_id", "csrf_token"],
)
```

### 有序 / 重复的 headers、params、data

`headers`、`params`、`data` 既可传 `dict`（保留插入顺序），也可传 `list[tuple[str, str]]`
（保留顺序且允许重复键，用于 `?tag=a&tag=b` 这类重复参数）：

```python
# 重复查询参数：?tag=a&tag=b
resp = session.get(url, params=[("tag", "a"), ("tag", "b")])

# 重复表单字段
resp = session.post(url, data=[("k", "1"), ("k", "2")])

# 显式控制 header 顺序（dict 同样按插入顺序发送）
resp = session.get(url, headers=[("user-agent", "..."), ("accept", "*/*")])
```

### base_url、通用 request()、连接池清理

```python
# base_url：相对路径自动拼接；传入绝对 URL 时覆盖 base_url
session = client.session(base_url="https://api.example.com")
resp = await session.get("/v1/users", params={"page": "1"})

# 通用 request()：显式指定方法（大小写均可）
resp = await session.request("PATCH", "/v1/users/1", json={"name": "x"})

# 仅允许重定向到 HTTPS；清空连接池
session = client.session(https_only=True)
session.pool_clear()
```

### HSTS / http→https 升级策略

浏览器会把已知 HSTS（或预加载）主机的 `http://` 请求在连接前升级为 `https://`。
默认（不传 `hsts`）为无状态“首次访问”，不做任何升级。主机匹配为后缀匹配
（等价于 HSTS 的 `includeSubDomains`）。

```python
# 会话内从响应的 Strict-Transport-Security 头动态学习 HSTS 主机（像长时间运行的浏览器）
session = client.session(hsts=lkrequest.Hsts.dynamic())

# 预置已知 HSTS 主机（例如回放上一段会话学到的状态）
session = client.session(hsts=lkrequest.Hsts.dynamic(seed=["example.com"]))

# 固定白名单；preloaded_tlds=True 同时升级 Chrome 完整预加载的 gTLD（.dev/.app/…）
session = client.session(hsts=lkrequest.Hsts.static_(["example.com"], preloaded_tlds=True))
```

### 请求级协议覆盖

```python
# 每个请求可覆盖会话级协议策略 / intent，以及 HTTP/3 专用 header 顺序
resp = await session.get(
    url,
    protocol_policy=lkrequest.ProtocolPolicy.chrome_conservative(),
    http_intent=lkrequest.HttpIntent.H2Only,
    h3_header_order=["host", "user-agent", "accept"],
)
```

`h3_header_order` 同样可在 `Client(...)` 与 `session(...)` 上设置（与 `header_order` 三级一致）。

### Prometheus 指标

```python
collector = lkrequest.enable_metrics()

# 执行请求后查看统计
stats = collector.snapshot()
print(collector.prometheus_text())
collector.reset()
```

### 请求诊断 & 运行指标

`response.diagnostics` 返回单次请求的分阶段计时（不依赖 OpenTelemetry，直接由 Rust 引擎采集）：

```python
resp = await session.get("https://example.com")
print(resp.diagnostics)
# {'dns_ms': 3, 'tcp_ms': 0, 'tls_ms': 423, 'ttfb_ms': 193, 'total_ms': 621,
#  'remote_addr': '93.184.216.34:443', 'protocol': 'h2', 'cipher_suite': '0x1301'}
# 复用连接时 dns_ms/tcp_ms/tls_ms 为 None（未经历该阶段）
```

`metrics_snapshot()` 拉取进程级运行计数器，供你喂进自己的 Prometheus / OTel 管线：

```python
snap = lkrequest.metrics_snapshot()
# {'bytes_in': ..., 'bytes_out': ..., 'requests_total': ...,
#  'requests_failed': ..., 'active_connections': ..., 'total_connections': ...}
```

> 计数器默认全为 0；构建时加 `telemetry` feature（`maturin build --features telemetry`）才会启用传输层字节计数。

### 证书管理

```python
client = lkrequest.Client(ca_cert="/path/to/ca.pem")       # 文件路径
client = lkrequest.Client(ca_cert_pem=pem_bytes)            # PEM bytes
client = lkrequest.Client(ca_cert_der=der_bytes)            # DER bytes
client = lkrequest.Client(verify=False)                      # 禁用验证（仅开发）
client = lkrequest.Client(use_native_certs=True)             # 系统证书
client = lkrequest.Client(ech_config=ech_bytes)              # ECH 支持
```

### 零拷贝 Response

```python
resp = session.get("https://example.com")

mv = memoryview(resp)       # 零拷贝访问 body
text = resp.text()          # 首次解码后缓存
data = resp.json()          # 首次解析后缓存
```

### 日志

```python
lkrequest.set_log_level("info")                          # 全局级别
lkrequest.set_log_level("lkrequest=debug,lktls=trace")   # 模块过滤
lkrequest.set_log_level("info", format="compact")        # 日志格式
lkrequest.set_log_level("off")                           # 关闭
```

### 错误处理

```python
try:
    resp = session.get(url, timeout=10.0)
    resp.error_for_status()
except lkrequest.LkTimeoutError:
    print("超时")
except lkrequest.LkConnectionError:
    print("连接失败")
except lkrequest.TlsError:
    print("TLS 错误")
except lkrequest.HttpStatusError as e:
    print(f"HTTP 错误: {e}")
except lkrequest.TooManyRedirectsError:
    print("重定向过多")
except lkrequest.RequestError as e:
    print(f"请求错误: {e}")
```

## 可用浏览器指纹

| 方法 | TLS | HTTP/2 | TCP |
|------|-----|--------|-----|
| `Client.chrome_131()` | Chrome 131 | Chrome 131 | Chrome |
| `Client.chrome_144()` | Chrome 144 | Chrome 144 | Chrome |
| `Client.chrome_145()` | Chrome 145 | Chrome 145 | Chrome |
| `Client.chrome_146()` | Chrome 146 | Chrome 146 | Chrome |
| `Client.chrome_147()` | Chrome 147 | Chrome 147 | Chrome |
| `Client.chrome_148()` | Chrome 148 | Chrome 148 | Chrome |
| `Client.chrome_149()` | Chrome 149 | Chrome 149 | Chrome |
| `Client.chrome_150()` | Chrome 150 | Chrome 150 | Chrome |
| `Client.firefox_133()` | Firefox 133 | Firefox 133 | Firefox |
| `Client.firefox_147()` | Firefox 147 | Firefox 147 | Firefox |
| `Client.safari_18()` | Safari 18 | Safari 18 | Safari |
| `Client.safari_26()` | Safari 26 | Safari 26 | Safari |

TCP 指纹按操作系统细分：`chrome_win` / `chrome_linux` / `chrome_macos` / `firefox_win` / `firefox_linux` / `firefox_macos` / `safari`

## API 参考

### Client

| 参数 | 说明 |
|------|------|
| `tls_profile` | TLS 指纹（字符串名或 `TlsProfile` 对象） |
| `h2_profile` | HTTP/2 指纹（字符串名或 `H2Profile` 对象） |
| `tcp_fingerprint` | TCP 指纹（字符串名或 `TcpFingerprint` 对象） |
| `default_headers` | 默认请求头 |
| `header_order` | Header 发送顺序 |
| `cookie_order` | Cookie 发送顺序 |
| `dns_timeout` / `tcp_connect_timeout` / `tls_handshake_timeout` / `ttfb_timeout` / `total_timeout` / `quic_connect_timeout` | 超时控制 |
| `max_response_body_size` / `max_connections_per_session` / `max_header_count` / `max_header_size` / `max_headers_total_size` / `min_transfer_rate`(+ `min_transfer_rate_window`) | 资源限制 / 抗 DoS |
| `h2_fallback_h1` / `proxy_fallback_direct` / `retry_on_connection_close` | 容错选项 |
| `middleware` | 中间件列表 |
| `ca_cert` / `ca_cert_pem` / `ca_cert_der` / `verify` / `use_native_certs` | 证书配置 |
| `ech_config` | ECH 配置 |
| `dns` | 自定义 DNS |
| `keylog` | TLS key log 文件路径 |

| 方法 | 说明 |
|------|------|
| `session(...)` | 创建会话 |
| `fingerprint_info()` | 返回指纹信息 dict |
| `randomize_fingerprint(shuffle_extensions=True)` | 返回指纹随机化后的新 Client |

### Session

所有 HTTP 方法 (get/post/put/delete/head/patch/options) 支持：

| 参数 | 说明 |
|------|------|
| `headers` | 请求头 |
| `params` | URL 查询参数 |
| `json` / `data` / `body` / `multipart` | 请求体 |
| `cookies` / `cookie_override` | Cookie 控制 |
| `timeout` | 请求超时 (秒) |
| `bearer_auth` / `basic_auth` | 认证 |
| `proxy` | 请求级代理覆盖 |
| `no_decompress` / `accept_encoding` | 编码控制 |

| 方法 | 说明 |
|------|------|
| `send_streaming(method, url, ...)` | 流式请求 |
| `ws_connect(url, *, headers, protocols)` | WebSocket 连接 |
| `preconnect(url)` / `preconnect_many(urls)` / `prefetch(urls)` | 连接预热 |
| `pool_stats()` | 连接池统计 (`PoolStats`) |
| `on_request(callback)` / `on_response(callback)` | 注册 Event Hook |
| `set_cookie()` / `set_cookie_with_attrs()` / `set_cookie_raw()` | 设置 Cookie |
| `get_cookie()` / `get_cookies()` / `get_cookie_values()` / `cookie_header()` | 读取 Cookie |
| `remove_cookie()` / `clear_cookies()` | 删除 Cookie |

### Response

| 属性/方法 | 说明 |
|-----------|------|
| `status_code` | HTTP 状态码 |
| `ok` | 状态码 < 400 |
| `url` | 最终 URL |
| `version` | HTTP 版本 (`HttpVersion.H2` / `HttpVersion.HTTP11`) |
| `headers` | 响应头 (`HeaderMap`, 大小写不敏感) |
| `headers_list` | 响应头列表 (`list[tuple[str, str]]`) |
| `content` | 原始字节 |
| `content_length` | Content-Length |
| `text()` | UTF-8 文本（带缓存） |
| `json()` | 解析 JSON（带缓存） |
| `cookies` | 响应 Cookie |
| `encoding` | 字符编码 |
| `elapsed` | 请求耗时 (秒) |
| `diagnostics` | 分阶段计时 dict：`dns_ms`/`tcp_ms`/`tls_ms`/`ttfb_ms`/`total_ms` + `remote_addr`/`protocol`/`cipher_suite`（未测阶段为 None） |
| `was_redirected` | 是否经过重定向 |
| `history` | 重定向链 (`list[RedirectRecord]`) |
| `error_for_status()` | 4xx/5xx 抛出 `HttpStatusError` |
| `memoryview(resp)` | 零拷贝访问 body |
| `len(resp)` / `bool(resp)` | 长度 / 是否成功 |

### HeaderMap

| 方法 | 说明 |
|------|------|
| `headers["name"]` | 获取 header (KeyError if missing) |
| `headers.get("name", default)` | 获取 header (返回 default if missing) |
| `headers.get_all("name")` | 获取所有同名 header |
| `"name" in headers` | 检查是否存在 |
| `len(headers)` | header 数量 |
| `headers.keys()` / `values()` / `items()` | 遍历 |
| `headers.to_dict()` | 转换为 dict |

### 指纹配置

| 类 | 说明 |
|----|------|
| `TlsProfile` | TLS 指纹配置，支持预设 / 自定义 / JSON 序列化 |
| `H2Profile` | HTTP/2 指纹配置 |
| `TcpFingerprint` | TCP 指纹配置，支持 JA4T 格式 |
| `ExtType` | TLS 扩展类型常量 |
| `ExtensionSpec` | TLS 扩展规格 |
| `GreaseConfig` | GREASE 注入配置 |
| `PaddingStrategy` | Padding 策略 (`block_align` / `fixed_target` / `no_padding`) |
| `RandomizationConfig` | 指纹随机化配置 |
| `H2Setting` | HTTP/2 设置项（字符串名或整数 ID） |
| `HeadersPriority` | Headers 优先级 |
| `PriorityFrame` | Priority 帧 |
| `ClientPool` | 客户端池，多指纹轮换 |

### 模块函数

| 函数 | 说明 |
|------|------|
| `set_log_level(level, *, format="compact")` | 设置日志级别 |
| `enable_metrics()` | 启用 Prometheus 指标，返回 `MetricsCollector` |
| `metrics_snapshot()` | 拉取进程级运行计数器 dict（需 `telemetry` feature 才有真实数值） |
| `validate_fingerprint_consistency(...)` | 校验指纹组合一致性 |

### 异常

| 异常 | 说明 |
|------|------|
| `RequestError` | 基类 |
| `TlsError` | TLS 握手失败 |
| `ProxyError` | 代理连接失败 |
| `HttpStatusError` | HTTP 状态错误 (4xx/5xx) |
| `LkConnectionError` | 连接失败 |
| `LkTimeoutError` | 超时 |
| `TooManyRedirectsError` | 重定向过多 |
| `ResourceLimitError` | 资源限制超出 |

## 示例

`examples/` 目录包含所有功能的完整示例：

| 示例 | 说明 |
|------|------|
| `basic_requests.py` | GET/POST 同步异步基础用法、并发请求 |
| `http_methods.py` | GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS |
| `authentication.py` | Bearer Token / Basic Auth |
| `response_inspection.py` | Response 全属性、HeaderMap、memoryview、重定向历史 |
| `cookie_management.py` | Cookie CRUD、set_cookie_with_attrs、cookie_override |
| `multipart_upload.py` | Multipart 文本+文件上传、Part 精细控制 |
| `websocket.py` | 同步/异步 WebSocket、WsMessage 类型 |
| `middleware.py` | 请求/响应拦截、Header 注入、多层洋葱模型 |
| `retry_strategies.py` | ExponentialBackoff / FixedInterval / callable / lambda |
| `event_hooks.py` | on_request/on_response 回调 |
| `proxy_pool.py` | 单代理、多跳代理链、BadProxyConfig、HealthCheckConfig、ProxyPool |
| `session_pool.py` | SessionPool / BlockingSessionPool |
| `client_pool.py` | ClientPool 多指纹轮换 |
| `browser_fingerprints.py` | 6 种预设指纹、字符串指定、指纹随机化 |
| `custom_fingerprint.py` | TlsProfile / H2Profile / TcpFingerprint 完全自定义 |
| `fingerprint_validation.py` | validate_fingerprint_consistency |
| `streaming_response.py` | StreamingResponse 逐块/完整读取 |
| `connection_prewarming.py` | preconnect / preconnect_many / prefetch |
| `metrics.py` | enable_metrics / snapshot / prometheus_text |
| `timeout_config.py` | 超时配置、ResourceLimits |
| `accept_encoding.py` | AcceptEncoding 控制、no_decompress |
| `certificate_config.py` | CA 证书 PEM/DER/文件、verify、ECH |
| `logging_config.py` | set_log_level、过滤指令 |
| `error_handling.py` | 全部异常类型、通用错误处理模式 |
| `pool_stats.py` | PoolStats 连接池统计 |
| `redirect_history.py` | 重定向链、RedirectRecord |

运行示例：

```bash
maturin develop
python examples/basic_requests.py
```

## 测试

使用 venv 和 pip：

```bash
# 完成上面的开发环境初始化后，运行全部测试
just test

# 或手动
python -m pip install -e ".[test]"
python -m pytest tests/ -v

# 仅运行不依赖网络的单元测试
python -m pytest tests/ -v -k "not httpbin and not echo"
```

使用 uv：

```bash
uv sync --extra test --extra lint
just test
# 或：
uv run pytest tests/ -v
```

## Benchmark

```bash
maturin develop --release
python benchmarks/bench_latency.py     # 单请求延迟
python benchmarks/bench_throughput.py   # 并发吞吐量
python benchmarks/bench_memory.py      # 内存占用
python benchmarks/verify_fingerprint.py # TLS 指纹验证
```
