# lkrequest

Python HTTP 客户端，支持 TLS/HTTP2/TCP 指纹控制。基于 Rust 高性能实现。

[English](https://github.com/EZXLabs/lkrequest-py/blob/main/README.md) | [简体中文](https://github.com/EZXLabs/lkrequest-py/blob/main/README-zh.md)

## 特性

- **浏览器指纹模拟** — Chrome、Firefox、Safari 的 TLS/HTTP2/TCP 指纹预设
- **自定义指纹** — 完全可编程的 `TlsProfile` / `H2Profile` / `TcpFingerprint`，支持 JSON 序列化
- **指纹随机化** — `Client(randomize=Randomize.extension_order())` 按连接置换 TLS 扩展顺序（漂移 JA3、JA4 不变，仍是真实浏览器）；`client.randomize_fingerprint()` 生成唯一变体，降低关联风险
- **客户端池** — `ClientPool` 在多个指纹之间自动轮换
- **异步 & 同步 API** — 同时支持 `asyncio` 异步和传统同步调用
- **WebSocket** — 支持 wss:// 连接，保持指纹一致性
- **流式响应** — `send_streaming()` 逐块接收大文件
- **Cookie 管理** — 自动 Cookie Jar，支持手动管理、属性设置、覆盖
- **代理支持** — HTTP CONNECT / SOCKS5 代理、认证（用户名密码，或 `Bearer` 等静态 HTTP 凭证）和有序多跳代理链；全 SOCKS5 链支持 QUIC/H3
- **代理池 & 会话池** — 内置代理轮换、坏代理标记和会话管理
- **Multipart** — 文件上传支持
- **重试策略** — 指数退避 / 固定间隔 / 自定义 callable 重试
- **中间件** — 请求/响应拦截和修改（洋葱模型）
- **Event Hook** — 轻量级请求/响应回调
- **连接预热** — `preconnect()` / `prefetch()` 批量预建连接
- **Prometheus 指标** — 内置请求计数、延迟直方图、exposition format 导出
- **请求诊断** — `response.diagnostics` 暴露单请求分阶段计时（DNS/TCP/TLS/TTFB/total）+ remote_addr/protocol/cipher_suite，以及信任锚协商情况
- **运行指标快照** — `metrics_snapshot()` 拉取进程级 wire 字节 / 连接 / 请求计数（供宿主自采，需 `telemetry` feature 才有真实数值）
- **零拷贝 Response** — `bytes::Bytes` + PyBuffer 协议 + text/json 缓存
- **自动解压** — Brotli / gzip / deflate / zstd，可控 `AcceptEncoding`
- **证书管理** — 自定义 CA / 禁用验证 / 系统证书
- **ECH** — Encrypted Client Hello 支持，包括 TLS/QUIC HelloRetryRequest 处理
- **信任锚标识** — Chrome 152 及以后的预设会声明自己接受哪些根证书（扩展 `0xca34`）；`Client(trust_anchor_advertisement="trusted", trust_anchor_recovery="once")` 改为声明你信任的根证书，并在服务端指明可用的 ID 时再试一次
- **请求优先级** — `RequestPriority`（RFC 9218 urgency/incremental），`session.get(url, priority=...)`；`h2_priority_weight=` 设置 HTTP/2 HEADERS 帧里旧式优先级字段的权重（0–255），与 `priority` 请求头互相独立
- **协议策略** — `ProtocolPolicy` / `HttpIntent` 控制 H2/H3 选择、获取（含可调的 TCP/QUIC 竞速）、升级与回退（client / session / 请求级）
- **会话恢复控制** — `SessionResumptionConfig` 控制 TLS1.3 PSK / TLS1.2 ticket 恢复（指纹形态层）；`Client(tls_session_resumption_policy=..., tls_session_cache_partition_policy=...)` 控制 ticket 是否**存储**以及缓存如何分键，`session(network_partition_context=NetworkPartitionContext(top_level_site, frame_site))` 复现浏览器的按站点分区行为
- **H2 DATA 分帧** — `Client(h2_data_frame_policy=H2DataFramePolicy.BROWSER_DEFAULT / PEER_MAX_FRAME_SIZE / fixed_payload(n) / socket_write_aligned(n))` 选择请求体如何切分为 DATA 帧
- **流式上传** — `session.post(url, body_stream=..., content_length=...)` 不缓冲整个 body：可传 file-like 对象（`read(n)`）、任意 `bytes` 可迭代对象，异步客户端还可传异步可迭代对象。省略 `content_length` 即未知长度（HTTP/1.1 走 chunked，HTTP/2 / HTTP/3 走 DATA 帧）。源是**单次使用**的，因此无法用于自动重试、协议回落，或必须保留请求体的重定向
- **TLS close_notify** — `Client(require_close_notify=True)` 拒绝未收到 TLS close_notify 警报就被截断的响应体
- **HTTP/1.1 头名大小写** — `Client(http1_title_case_headers=False)` 让 HTTP/1.1 头名使用小写（`content-type`），但保留大写首字母的 `Host`；默认仍为 Title-Case（`Content-Type`）。自动生成的头、普通请求、流式请求、预连接和 WebSocket 握手都适用。HTTP/2 与 HTTP/3 的头名始终是小写
- **请求级协议覆盖** — `preferred_http_version` / `idempotency`（0-RTT 重放安全声明）
- **QUIC / HTTP3** — 可选 feature（`maturin develop --features quic-h3`）：`session(http3_only=True / http3_with_fallback=True / broken_quic_policy=BrokenQuicPolicy.Resilient)`，QUIC 连接失败后源站留在 TCP 上多久也可以自己定：`broken_quic_policy=BrokenQuicConfig(initial_cooldown=2.0, max_cooldown=30.0)`；`Client(quic_fingerprint=..., quic_profile="chrome_150", disable_http3=True)`；独立的 Chrome 146/150/151/152/153/154/155/156/157 `QuicProfile` 预设（仅 feature 开启时可用）。QUIC 专用的 ClientHello 是另一份 TLS profile——手工构造客户端时请传 `quic_fingerprint=TlsProfile.chrome_151_quic()`，否则 HTTP/3 会沿用主 TLS profile
- **HTTP/3 重试** — `session(h3_retry_mode=H3RetryMode.Chrome155ProtocolErrors)` 会像 Chrome 155 那样，在响应头到达之前对特定的 HTTP/3 协议错误最多重试两次。它会重放已缓冲的请求，**包括 POST**，也就是说服务器已经处理过的请求可能被再处理一次；用 `idempotency=Idempotency.NotIdempotent` 可以让单个请求退出。默认关闭（`H3RetryMode.Safe`）；非 `Safe` 的取值需要 `quic-h3` feature
- **MASQUE 代理（实验性）** — 可选 feature（`maturin develop --features masque`，隐含 `quic-h3`）：`session(proxy="masque://proxy:443", http3_only=True)` 把到目标的 QUIC 连接放进 RFC 9298 CONNECT-UDP 隧道；`Client(masque=MasqueConfig(...))` 配置到代理这一跳的信任，与 `verify` 相互独立；`HealthCheckConfig(tunnel_probe=True, masque=...)` 用真实隧道探测代理池中的 MASQUE 代理
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
git clone https://github.com/EZXLabs/lkrequest-py
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
git clone https://github.com/EZXLabs/lkrequest-py
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

如果回调还接受 `exception=` 参数，就会收到这次失败抛出的异常对象，带有[错误处理](#错误处理)一节列出的属性；按状态码重试时为 `None`：

```python
def retry_when_worth_it(attempt, error, status, exception=None):
    if exception is not None and exception.retryable and attempt < 3:
        return 1.0
    return None
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

### Session 生命周期与内存

连接、cookie 和事件钩子都属于 `Session`，而不是创建它的 `Client`。建议创建一次 Session 反复使用：复用的 Session 在请求之间保持连接，每个请求新建一个 Session 则每次都要重新做 TCP 和 TLS 握手。

不再需要某个 Session 时，用上下文管理器关闭它，或者手动关闭：

```python
with client.session() as session:          # BlockingClient
    session.get(url)

async with client.session() as session:    # Client
    await session.get(url)

session.close()                            # 效果相同，不需要代码块
```

`close()` 会中止池里的连接，放弃还在途的请求（它们抛出 `RuntimeError`），丢弃事件钩子和会话级中间件的回调，之后 Session 拒绝新的请求并抛出 `RuntimeError`。重复关闭没有副作用，`session.closed` 可以查询是否已关闭，cookie 仍可读取。只想断开连接、继续使用这个 Session 时，用 `session.pool_clear()`。

没有任何引用指向的 Session 会被自动释放，连接一并释放。有几点需要了解：

- **钩子可以引用它的持有者。** 在持有 `self.session` 的类里写 `session.on_response(self.log)` 会形成引用环，Python 的循环垃圾回收器会回收它。回收器是周期性运行的，不是立即回收，在它运行之前这个 Session 的连接仍然开着；`close()` 会立即释放。
- **中间件的回调是例外。** 它们由 Rust 侧持有，回收器看不到，所以回调如果引用了自己所在的 Session 或 Client（对它的闭包、持有它的对象的方法），不会被自动回收。`session.close()` 会释放会话级中间件的回调；`Client(middleware=...)` 的回调与 Client 同生命周期，这样的 Client 请创建一次复用，不要每个请求新建一个。
- **连接池默认没有上限。** 空闲连接 300 秒后会被丢弃，但只在这个 Session 下一次被使用时才清理；在此之前，访问过很多不同主机的 Session 会为每个主机保留一条连接，每条约占 100 KB 的量级。`client.session(max_connections=..., idle_timeout=...)` 和 `Client(max_connections_per_session=...)` 可以设置上限，`close()` 或 `pool_clear()` 会立即释放。
- **释放的内存不一定还给操作系统。** 连接都没了之后，进程的常驻内存可能仍停在峰值：分配器把这些页留着复用。这不是泄漏。

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
session.set_cookie_raw("https://example.com", "sid=abc; Path=/; Secure; SameSite=Lax")

# 删除与清空
session.remove_cookie("https://example.com", "token")
session.clear_cookies()

# 请求级 Cookie 覆盖
resp = session.get(url, cookie_override={"token": "override_value"})
```

读回属性 —— `get_cookies()` 返回的是 `(name, value)`，无法区分同名但 path 不同的两条 cookie：

```python
for cookie in session.get_cookies_with_attrs("https://example.com/api"):
    print(cookie.name, cookie.value, cookie.path, cookie.domain,
          cookie.secure, cookie.http_only, cookie.same_site, cookie.expires)

# 整个 jar（跨所有域）—— 用于持久化，或交给浏览器
for cookie in session.get_all_cookies():
    if cookie.is_persistent:       # 有过期时间；会话 cookie 没有
        save(cookie)
```

`Cookie` 可哈希，所以两个 jar 可以用集合运算做差。`get_all_cookies()` 按创建顺序从旧到新
返回，而 `Cookie` 头按 Chrome 的规则排序（path 长的在前，同 path 下旧的在前），因此把存下来的
jar 写回一个新 session，线上发出的 `Cookie` 头能逐字还原。

### Multipart 文件上传

```python
mp = lkrequest.Multipart()
mp.text("title", "文件上传")
mp.file("document", "report.pdf", "application/pdf", pdf_bytes)
# Part 能表达 text() 和 file() 表达不了的内容，比如不带文件名的二进制字段
mp.part(lkrequest.Part("checksum", digest_bytes))
resp = session.post("https://example.com/upload", multipart=mp)
```

### 流式上传

上传时不把整个 body 留在内存里。已知精确大小时传 `content_length`，未知长度则省略。

```python
# 磁盘文件，已知精确长度
with open("archive.zip", "rb") as f:
    resp = await session.post(
        "https://example.com/upload",
        body_stream=f,
        content_length=os.path.getsize("archive.zip"),
    )

# 分块生成器，未知长度（HTTP/1.1 走 chunked，H2/H3 走 DATA 帧）
def chunks():
    for block in blocks:
        yield block

resp = await session.post("https://example.com/upload", body_stream=chunks())

# 异步可迭代对象 —— 不缓冲地转发另一个响应
async def relay():
    stream = await session.send_streaming("GET", src)
    async for chunk in stream:
        yield chunk

resp = await session.post(dst, body_stream=relay())
```

传入的 `content_length` 是**精确值**：源提前结束或超出都会让请求失败。源是**单次使用**的，
所以自动重试、协议回落，以及必须保留请求体的重定向都无法重放它 —— 需要重建源再发一次。
阻塞客户端接受 file-like 对象或同步可迭代对象；异步可迭代对象只能用于异步客户端。

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

另一个任务（同步客户端则是另一个线程）正在 `recv()` 里等消息时，也可以调用 `send_text()`、`send_binary()` 和 `close()`；关闭时，那个正在等待的 `recv()` 会拿到关闭握手。连接关闭之后，对它的任何操作都抛 `RuntimeError`，迭代则直接结束。

```python
ws = await session.ws_connect(url, protocols=["chat"], extensions=["x-my-extension"])
await ws.ping(b"heartbeat")    # pong 会从 recv() 返回；载荷最多 125 字节
await ws.pong()                # 主动发送的 pong
ws.url                         # close() 之后仍可读取
```

`extensions` 会写进升级请求的 `Sec-WebSocket-Extensions` 头，这个头本身就是浏览器握手特征的一部分。但帧始终按未压缩的格式读写，所以只能使用不改变帧格式的扩展：服务器一旦接受 `permessage-deflate`（Chrome 会提供的压缩扩展），它发来的每条压缩消息都会接收失败。

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
async with await pool.acquire() as lease:
    session = client.session(proxy=lease.proxy)  # ProxyConfig，含凭据
    resp = await session.get("https://example.com")
    if resp.status_code == 403:
        lease.mark_bad()
```

无法解析的代理 URL 无论交给哪里——`session(proxy=...)`、请求级的 `proxy=`、`ProxyConfig(...)` 还是代理池的列表——都会抛 `ValueError`，写错一个字不会让会话悄悄改成直连。

`acquire()` 返回 `ProxyLease`。它占着池里 `max_proxies`（默认 100）个名额中的一个，直到被释放：调用 `release()`、`with` 或 `async with` 块结束，或者被垃圾回收。所以 `max_proxies` 限制的是同时在用的代理数，`pool.max_concurrent` 可以读回这个值。对 lease 调用 `mark_bad()`，或调用 `pool.mark_bad(proxy.identity())`，会计入池的失败计数；`acquire_fresh(lease)` 会先做这一步，再释放旧 lease、租用另一个代理。

只要代理池里有代理，就不会返回“没有代理”（调用方会把它当成直连）：所有代理都在冷却时，`await pool.acquire()` 会一直等，需要限时的话用 `asyncio.wait_for` 包一层。只有用空列表创建的池，返回的 lease 的 `proxy` 才是 `None`。

代理池也可以不传列表，改传一个函数，每发出一个代理就调用一次。按用户名里的 session id 选出口的代理网关就这样用：

```python
pool = lkrequest.ProxyPool(
    lambda: f"http://user-session-{uuid.uuid4().hex[:8]}:pass@gateway.example:7777",
    max_proxies=50,
    proxy_buffer=20,  # 可选：预先生成 20 个代理备用
)
```

函数返回 URL 或 `ProxyConfig`，必须是普通函数，不能是 `async def`。函数抛出的异常会从调用它的那次 `acquire()` 抛出；返回的 URL 无法解析时，同样由这次 `acquire()` 抛 `ValueError`。函数给出的每个代理都是新的，所以 `rotation`、`bad_proxy_config`、`health_check` 对它不起作用：不冷却，也不做健康检查。异步的池在工作线程上调用它，线程要等它返回，所以函数要快；`proxy_buffer=n` 会在单独的线程上预先生成 `n` 个代理，那里出错只记日志，一秒后再调用。

`lkrequest.blocking.ProxyPool` 参数相同，它的 `acquire()` 是阻塞调用，返回同样的 `ProxyLease`，用 `release()` 或 `with` 块释放。

不建池、只检查单个代理时，让客户端经它建一条隧道，返回建隧道用的时间：

```python
latency = await client.check_proxy("socks5://user:pass@host:1080")   # 秒
latency = blocking_client.check_proxy(proxy, "example.com", 443, timeout=3.0)
```

隧道里不发送任何东西。默认值与池的健康检查相同（`www.google.com:443`，5 秒），域名按客户端的方式解析，`dns=` 也生效。代理拒绝或连不上时抛 `ProxyError`，太慢则抛 `TimeoutError`。

`ProxyConfig` 可以读出 `host`、`port`（连向目标的那一跳）和 `forbids_direct_fallback`：MASQUE 路由为真，失败后绝不回退直连。

基于 TCP 的 HTTP 支持混合使用 HTTP CONNECT 与 SOCKS5 跳。QUIC/HTTP3 要求链中
每一跳都是 SOCKS5；链中含 HTTP 跳时，设置 `http3_with_fallback=True` 可回退 H2。

URL 中 `user:pass` 以外的凭证在 `ProxyConfig` 上设置，每个 setter 都返回新对象：

```python
proxy = (
    lkrequest.ProxyConfig("http://gateway:8080")
    .with_http_auth("Bearer", "token")      # scheme 之后原样发送
    .with_auth_header("authorization")      # 默认 "proxy-authorization"
)
proxy = lkrequest.ProxyConfig("http://gateway:8080").with_user_pass("user", "pass")
proxy = lkrequest.ProxyConfig("http://gateway:8080").with_custom_auth(
    "account-1",                          # 稳定、不含机密，参与 identity()
    lambda: f"Bearer {tokens.fresh()}",   # 每次建连都会调用
)
```

凭据需要每次建连时现算的，用 `with_custom_auth()`。函数返回认证头的值或 `None`，在建连的线程上运行，该线程会等它返回；函数抛异常时这次连接不带凭据，并记一条 warning 日志。

### MASQUE 代理（实验性）

> **实验性功能。** MASQUE 支持在上游和本绑定中都处于实验阶段：`MasqueConfig`、
> `masque=` / `tunnel_probe=` 参数以及 `masque://` 路由的行为，可能在任何版本中
> 变更且不经过弃用期；互通性目前只在测试代理上验证过，尚未对独立的生产环境 MASQUE
> 部署做过验证。如需依赖请固定版本。

需要 `masque` feature。`masque://` 代理（默认端口 443）通过到代理的 HTTP/3 连接，
把到目标的 QUIC 连接放进 RFC 9298 CONNECT-UDP 隧道。目标写在隧道请求里，所以 DNS
在代理侧解析，与 `socks5h` 相同。

```python
masque = lkrequest.MasqueConfig(
    ca_cert="proxy-ca.pem",      # 或 ca_cert_pem=b"...", ca_cert_der=b"...", server_name="proxy.example"
    tunnel_idle_timeout=120.0,   # None：空闲隧道永不回收
    max_idle_tunnels=256,        # 0：不设上限
)
client = lkrequest.Client(quic_profile="chrome_153", masque=masque)
session = client.session(proxy="masque://proxy.example:443", http3_only=True)

# 用真实 CONNECT-UDP 隧道探测代理池中的 MASQUE 代理。不开 tunnel_probe 时
# 健康检查会跳过它们（TCP 连得上说明不了什么）。
health = lkrequest.HealthCheckConfig(tunnel_probe=True, masque=masque)
```

- 到代理这一跳的信任只在 `MasqueConfig` 里配置：客户端的 `verify` / `ca_cert*`
  只管到源站的连接，不会被继承。`MasqueConfig(verify=False)` 仅供开发调试——此时
  任何在代理地址上应答的一方都能看到每条隧道的目标。
- 只支持 UDP：经 MASQUE 代理的 HTTP/1.1、HTTP/2 请求会抛 `ProxyError`；隧道失败也
  绝不回退直连，即便设置了 `proxy_fallback_direct=True`。MASQUE 代理不能作为链中的一跳。
- 到代理的连接不是浏览器指纹，隧道内到源站的连接才是。MASQUE 路由上拿不到通过 DNS
  发现的 ECH 配置与 H3 提示（显式传入的 `ech_config` 仍然生效）。

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

两个会话池都和 `ProxyPool` 一样接受 `rotation=`、`bad_proxy_config=`、`health_check=`、`proxy_buffer=`，也可以用函数代替列表；`max_sessions` 相当于 `ProxyPool` 的 `max_proxies`。

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
    tls_client_hello_style="chromium_boringssl",  # TLS 栈自有的规则：generic（默认）、chromium_boringssl、firefox_nss 等
    ech=lkrequest.EchMode.grease(payload_length_min=128, payload_length_max=224),  # 按 Chrome 的方式发 ECH GREASE；另有 EchMode.real(config_list)、EchMode.disabled()
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
    initial_stream_id=1,  # 第一个请求所用的流：奇数，多数浏览器是 1，Firefox 156 是 3
)
h2.validate()  # 违反 HTTP/2 规则时抛 ValueError；其他地方不会检查

# 自定义 TCP Fingerprint。这些是库向操作系统请求的 socket 设置，作用于新的直连以及到第一个
# 代理的那一跳；SYN 包仍由系统生成，所以窗口大小/缩放只影响接收缓冲区，MSS 仅在 Linux 上生效。
tcp = lkrequest.TcpFingerprint(window_size=65535, mss=1460, window_scale=8, ttl=128)
# SYN 的选项顺序（JA4T 第二段，用 kind 数字表示）只是描述目标，体现在 to_ja4t() 里；
# keep-alive 则会真正设到 socket 上。
tcp = lkrequest.TcpFingerprint(
    window_size=64240, tcp_options=[2, 1, 3, 1, 1, 4], mss=1460, window_scale=8,
    keepalive_idle=30.0, keepalive_interval=5.0,
)
tcp.to_ja4t()   # "64240_2-1-3-1-1-4_1460_8"
tcp.to_dict()   # 全部设置，交给系统决定的为 None
lkrequest.TcpFingerprint.safari_ios(), lkrequest.TcpFingerprint.none()

# 组合使用
client = lkrequest.Client(tls_profile=tls, h2_profile=h2, tcp_fingerprint=tcp)

# 序列化 / 反序列化
json_str = tls.to_json()
restored = lkrequest.TlsProfile.from_json(json_str)

# 指纹随机化：得到一个副本，其 TLS profile 按连接打乱扩展顺序；客户端的其他配置全部保留
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
# 从响应的 Strict-Transport-Security 头动态学习 HSTS 主机（像长时间运行的浏览器）
hsts = lkrequest.Hsts.dynamic()
session = client.session(hsts=hsts)
other = client.session(hsts=hsts)     # 与 session 共享学到的主机，像同一个浏览器配置文件
hsts.should_upgrade("example.com")    # 会话此刻会怎么判断

# 预置已知 HSTS 主机（例如回放上一段会话学到的状态）
session = client.session(hsts=lkrequest.Hsts.dynamic(seed=["example.com"]))

# 固定白名单；preloaded_tlds=True 同时升级 Chrome 完整预加载的 gTLD（.dev/.app/…）
session = client.session(hsts=lkrequest.Hsts.static_(["example.com"], preloaded_tlds=True))

# 自定义策略；record_sts(host, header) 可选
session = client.session(hsts=lkrequest.Hsts.custom(lambda host: host.endswith(".internal")))
```

`Hsts.custom()` 的函数在执行请求的线程上运行，该线程会等它们返回：每个 `http://` URL 调一次 `should_upgrade`；经 HTTPS 从非 IP 主机收到 `Strict-Transport-Security` 头时调 `record_sts`。两者都必须是普通函数；抛异常时记一条 warning 日志，URL 不升级。

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

一个策略有四个维度：intent、新连接如何获取、是否升级到 HTTP/3、是否从 HTTP/3 回退。每个维度都能读出来，也能在副本上替换：

```python
policy = (
    lkrequest.ProtocolPolicy.chrome_conservative()
    .with_acquisition(lkrequest.RacePolicy(tcp_delay=0.1))   # 或 AcquisitionPolicy.EstablishBestAvailable
    .with_upgrade(lkrequest.UpgradePolicy.ProbeOnly)
    .with_fallback(lkrequest.FallbackPolicy.NoFallback)
)
policy.acquisition, policy.upgrade, policy.fallback
```

`RacePolicy` 让 TCP 与 QUIC 竞速；没给的参数沿用 `RacePolicy.chrome_like()`：QUIC 立即开始，TCP 晚 0.3 秒，只对公告过 HTTP/3 的源站竞速。相互矛盾的组合（例如只用 H3 却允许回退、TCP 和 QUIC 都不参与的竞速）会由 `policy.validate()` 抛 `ValueError`；交给 client、session 或单个请求时也一样，都在发出任何东西之前抛出。

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

`diagnostics["trust_anchor"]` 记录请求新建的 TLS 连接上的[信任锚标识](#信任锚标识)协商，复用连接时为 `None`。

`metrics_snapshot()` 拉取进程级运行计数器，供你喂进自己的 Prometheus / OTel 管线：

```python
snap = lkrequest.metrics_snapshot()
# {'bytes_in': ..., 'bytes_out': ..., 'requests_total': ...,
#  'requests_failed': ..., 'active_connections': ..., 'total_connections': ...}
```

> 计数器默认全为 0；构建时加 `telemetry` feature（`maturin build --features telemetry`）才会启用传输层字节计数。

### 关闭前收尾

事件循环关闭后才返回的结果没有接收方，会被直接丢弃。如果拆掉循环时可能仍有请求在跑，先等它们收干净：

```python
await lkrequest.drain_pending()            # 一直等
await lkrequest.drain_pending(timeout=5)   # 超时未收完返回 False
lkrequest.pending_requests()               # 当前仍在途的数量
lkrequest.blocking_drain_pending(5)        # 同上，用于非异步场景
```

计数是进程级的，覆盖所有异步调用而不只是请求。取消某个请求会立即释放它——底层工作被丢弃，而不是等它跑完。

### 证书管理

```python
client = lkrequest.Client(ca_cert="/path/to/ca.pem")       # 文件路径
client = lkrequest.Client(ca_cert_pem=pem_bytes)            # PEM bytes
client = lkrequest.Client(ca_cert_der=der_bytes)            # DER bytes
client = lkrequest.Client(verify=False)                      # 禁用验证（仅开发）
client = lkrequest.Client(use_native_certs=True)             # 系统证书
client = lkrequest.Client(ech_config=ech_bytes)              # ECH 支持
```

### 信任锚标识

Chrome 152 及以后的版本会告诉服务端自己接受哪些根证书：把它们的 ID 放进 ClientHello 的 `trust_anchors` 扩展（`0xca34`，draft-ietf-tls-trust-anchor-ids），服务端据此挑一条终止于其中某个根证书的证书链。`Client.chrome_155()` 到 `Client.chrome_157()`（默认指纹也在其中）和对应版本的 Chrome 一样，按固定的排序顺序发出 28 个 ID；Chrome 152 到 154 的预设每次握手都会打乱顺序。三个客户端选项可以改变发什么、以及之后怎么做：

```python
root = open("private-root.der", "rb").read()
client = lkrequest.Client(
    tls_profile="chrome_157",
    h2_profile="chrome_157",
    ca_cert_der=root,
    trust_anchor_advertisement="trusted",  # 改为发出本客户端信任的根证书的 ID（已排序）
    trust_anchor_recovery="once",          # 服务端指明可用的 ID 时再试一次
    trust_anchor_bindings={"81fd5901": lkrequest.trust_anchor_identity(root)},
)
```

- `trust_anchor_advertisement`：`"profile"`（默认）按 TLS profile 列出的顺序发出它的 ID；`"trusted"` 改为发出本客户端信任的根证书的 ID（已排序）：Chrome 157 根证书库里自带 ID 的那些根证书，加上 `trust_anchor_bindings`。
- `trust_anchor_recovery`：设为 `"once"` 后，如果服务端列出了它能提供的 ID，随后证书链校验失败或服务端中止握手，客户端会再建一条连接，请求这些 ID 中第一个本客户端信任的。每个请求最多发生一次，被拒的那条连接上不发任何 HTTP 字节，并会关闭 0-RTT；需要开启 `verify`，不能与 `proxy_fallback_direct=True` 同用。默认是 `"disabled"`。
- `trust_anchor_bindings`：为你自己的根证书提供 `{id: anchor_identity}`，ID 是你的 CA 分配的十六进制值，绑定到 `lkrequest.trust_anchor_identity(root_der)` 的结果。根证书本身仍需通过 `ca_cert*` 加载。

这些 ID 不会改变信任哪些证书。只有带这个扩展的 profile（Chrome 152–157）接受 `"trusted"` 或 `"once"`，TLS 合成（`Randomize.recombine()` / `Randomize.full()`）也不能与它们同用；上游拒绝的设置会抛 `ValueError`。`diagnostics["trust_anchor"]` 记录新建连接请求了哪些 ID、服务端提供了哪些、由哪个根证书校验通过，以及恢复之后的首次尝试。

### DNS

```python
client = lkrequest.Client(dns="cloudflare")         # 或 "google"、"quad9"、"cloudflare_https" 等
client = lkrequest.Client(dns="192.168.1.1")        # 自己的 DNS 服务器，端口 53
client = lkrequest.Client(dns="[2606:4700::1111]:53")
```

`dns` 默认为 `"system"`，即操作系统的解析器。几个公共解析器名通过 UDP 查询（应答较长时改用 TCP），`*_https` 版本走 DNS-over-HTTPS（需要 `doh` 构建 feature）。其他取值都当作 DNS 服务器地址：`"ip"` 表示端口 53，也可以写 `"ip:port"`，带端口的 IPv6 地址要加方括号。与系统解析器不同，DNS 服务器还能查 HTTPS 记录，客户端正是从这里得知站点的 ECH 配置和 HTTP/3 支持。

`dns` 也可以是一段负责解析域名的 Python 代码：

```python
def resolve(host: str, port: int) -> list[str]:
    return ["192.0.2.10"]        # 每项是一个 IP，或写成 "ip:port" 改连别的端口

client = lkrequest.Client(dns=resolve)

class Resolver:                  # 也可以是对象，它还能回答 HTTPS 记录
    def resolve(self, host, port):
        return ["192.0.2.10"]

    def lookup_https(self, host):   # 可选；没有记录时返回 None
        return {"alpn": ["h3", "h2"], "ech_config_list": ech_bytes}

client = lkrequest.Client(dns=Resolver())
```

记录可以包含 `alpn`、`no_default_alpn`、`target`、`port`、`ech_config_list`、`ipv4_hints`、`ipv6_hints`。代码必须是同步的（`async def` 会抛 `TypeError`），在运行时的阻塞线程池里执行，所以一次慢查询不会拖住其他请求。`dns_timeout` 限制每次调用的时长，`ip_family` 会过滤返回的地址。`resolve` 抛出的异常会成为请求所抛 `ConnectionError` 的 `__cause__`，traceback 里能看到它在哪一行出错；`lookup_https` 出错只记日志，当作没有记录。

### 地址族

双栈机器上操作系统解析器把 IPv6 排在前面，所以只要 IPv6 通，有 AAAA 记录的目标就会走
IPv6。`ip_family` 用来钉住它 —— 当一个会话必须对目标呈现单一源地址、而不是从两个地址族
分别出去时，这一点很关键：

```python
client = lkrequest.Client(ip_family="ipv4")   # 绝不走 IPv6
client = lkrequest.Client(ip_family="ipv6")   # 绝不走 IPv4
client = lkrequest.Client(ip_family="any")    # 解析器自己的顺序（默认）
```

不在该地址族内的地址会**报错**而不是回退 —— 即便设置了 `proxy_fallback_direct=True`
也不会回退直连 —— 所以这个设置不会被静默绕过。`"ipv6"` 还会拒绝 IPv4-mapped 地址
（`::ffff:a.b.c.d`）。它管的是**本进程自己**选定的所有地址：

| 场景 | `ip_family="ipv4"` 时 |
|---|---|
| 直连 | 只走 IPv4；没有 A 记录的目标会失败 |
| 代理自身的地址、SOCKS5 UDP relay | 只走 IPv4 |
| `socks5://` 的目标（本地解析） | 只走 IPv4 |
| HTTP `CONNECT`、`socks5h://`、MASQUE 且目标是域名 | 由代理解析，代理到目标仍可能走 IPv6 |
| 解析器自身的 DNS / DoH 查询 | 不受限制 |

要决定代理拨向哪个地址，用 `connect_to` 把源站映射到指定地址：

```python
client = lkrequest.Client(
    ip_family="ipv4",
    connect_to={"example.com:443": "192.0.2.1:443"},  # IPv6 写成 "[2001:db8::1]:443"
)
session = client.session(proxy="http://proxy.example:8080")
# 代理收到的是 `CONNECT 192.0.2.1:443`；TLS SNI、证书校验、Host 头和 Cookie
# 仍然使用 example.com。
```

映射是固定的，不会重新解析或刷新。它对直连、经代理和 HTTP/3 连接都生效，优先于
Alt-Svc / SVCB 给出的端点，但不会替换代理自身的地址。它决定的是代理拨向的目标，
不能保证代理供应商的公网出口地址；经代理时 `diagnostics["remote_addr"]` 是代理的地址，
出口地址请用目标服务的回显来确认。

### 零拷贝 Response

```python
resp = session.get("https://example.com")

mv = memoryview(resp)       # 零拷贝访问 body
text = resp.text()          # 首次解码后缓存
data = resp.json()          # 首次解析后缓存
```

### 文本解码

`text()` 按 `Content-Type` 声明的 charset 解码，响应未声明时回落 UTF-8。无法解码的字节
转为 U+FFFD 而不是抛异常，一个坏字节不会让你丢掉整个 body —— 需要精确字节时用 `content`。

```python
resp = session.get("https://example.com")   # Content-Type: text/html; charset=gbk
resp.encoding                               # 'gbk'
resp.text()                                 # 按 GBK 解码

resp.text(encoding="latin-1")               # 覆盖缺失或错误的 charset 声明
```

header 里的 charset 按浏览器的方式解析，依据 WHATWG Encoding Standard。而 `encoding=`
参数查的是 Python 自己的 codec 注册表，所以 Web 标准里没有的 Python 写法
（`latin-1`、`utf-8-sig`、`cp936`）照写即可。

开头的 BOM 会被剥离；BOM 与 header 声明冲突时以 BOM 为准 —— 同样是浏览器的规则。所以
`charset=gbk` 但 body 以 UTF-8 BOM 开头的响应会按 UTF-8 解码，而 `text()` 也不会把那个
看不见的 U+FEFF 交给你（它会让 `json.loads`、`startswith` 静默失效）。

流式响应的 `text()` 解码方式完全相同，也接受同样的 `encoding=` 参数（异步客户端写作
`await stream.text(encoding="gbk")`）。

### 日志

```python
lkrequest.set_log_level("info")                          # 全局级别
lkrequest.set_log_level("lkrequest=debug,lktls=trace")   # 模块过滤
lkrequest.set_log_level("info", format="compact")        # 日志格式
lkrequest.set_log_level("off")                           # 关闭
lkrequest.set_log_level("debug", format="logging")       # 交给 Python 的 logging
```

一个进程里只有第一次调用生效，之后的调用返回 `False`。`"compact"`、`"full"`、`"json"` 输出到 stderr。`"logging"` 把通过级别过滤的每个事件交给 Python 的 `logging`，logger 名为 `lkrequest.` 加上事件的 Rust target（如 `lkrequest.lkrequest.session`、`lkrequest.lktls.handshake`），所以配置 `logging.getLogger("lkrequest")` 就能管住全部。这里给的级别决定哪些事件会被转发，按需设得窄一些；logger 自己的级别和 handler 是在这之后才起作用的。事件先进队列，由单独的线程转发，请求不会因为写日志去等 GIL；队列满了会丢弃事件。

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

每个 `RequestError` 还带着 Rust 库对这次失败掌握的信息：

```python
except lkrequest.RequestError as e:
    e.phase             # "tcp_connect"、"proxy_tunnel"、"tls_handshake" 等，未知时为 None
    e.retryable         # 重试是否可能成功
    e.safe_to_replay    # 服务器是否肯定没处理过这个请求，即使是 POST 也能重发
    e.status_code       # HttpStatusError：状态码
    e.proxy_error_kind  # ProxyError："authentication_required"、"tunnel_refused" 等
    e.tls_alert         # TlsError：握手因哪个告警结束，如 "handshake_failure"
    e.diagnostics       # 到失败为止的耗时与传输信息，格式同 Response.diagnostics
```

不适用的属性为 `None`（两个布尔值为 `False`），手动构造的异常也是如此。HTTP 方法和 `request()` 失败时、以及 `error_for_status()` 抛出的异常带有 `diagnostics`；流式请求、WebSocket 和 `preconnect()` 的异常不带。

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
| `Client.chrome_151()` | Chrome 151 | Chrome 151 | Chrome |
| `Client.chrome_152()` | Chrome 152 | Chrome 152 | Chrome |
| `Client.chrome_153()` | Chrome 153 | Chrome 153 | Chrome |
| `Client.chrome_154()` | Chrome 154 | Chrome 154 | Chrome |
| `Client.chrome_155()` | Chrome 155 | Chrome 155 | Chrome |
| `Client.chrome_156()` | Chrome 156 | Chrome 156 | Chrome |
| `Client.chrome_157()` | Chrome 157 | Chrome 157 | Chrome |
| `Client.firefox_133()` | Firefox 133 | Firefox 133 | Firefox |
| `Client.firefox_147()` | Firefox 147 | Firefox 147 | Firefox |
| `Client.firefox_156()` | Firefox 156 | Firefox 156 | Firefox |
| `Client.safari_18()` | Safari 18 | Safari 18 | Safari |
| `Client.safari_26()` | Safari 26 | Safari 26 | Safari |

不传 `tls_profile=` / `h2_profile=` 构建的客户端（直接 `Client()`）使用 Chrome 155 的 TLS 和 HTTP/2 指纹，不带 TCP 指纹，也不带 QUIC / HTTP3 配置。默认值可能随版本更新而变化，如果介意，请显式指定版本。

TCP 指纹按操作系统细分：`chrome_win` / `chrome_linux` / `chrome_macos` / `firefox_win` / `firefox_linux` / `firefox_macos` / `safari`

Firefox 156 的第一个 HTTP/2 请求使用流 3，导航请求的 HEADERS 权重为 41；其余预设都从流 1 开始。

只有 Chrome 预设带 QUIC / HTTP3 指纹（需开启 `quic-h3` feature）。Firefox 和 Safari 预设会关闭 HTTP/3，开启 `quic-h3` 构建也不会改变这一点。

预设只设置请求头的**顺序**，不设置请求头的值：`Client.chrome_155()` 发出的请求不会自带 `User-Agent`、`Accept` 等浏览器请求头，需要自己通过 `default_headers=` 或逐个请求设置。

## API 参考

### Client

| 参数 | 说明 |
|------|------|
| `tls_profile` | TLS 指纹（字符串名或 `TlsProfile` 对象） |
| `h2_profile` | HTTP/2 指纹（字符串名或 `H2Profile` 对象） |
| `tcp_fingerprint` | TCP 指纹（字符串名或 `TcpFingerprint` 对象） |
| `default_headers` | 默认请求头，`dict` 或 `(名, 值)` 二元组列表；`header_order` 没有指定位置的头按给定顺序发送。跟随重定向离开原来的源时，默认的 `Authorization`、`Cookie`、`Host` 不会带过去；从 https 跳到 http 时，默认的 `Referer` 也会去掉 |
| `header_order` | Header 发送顺序 |
| `cookie_order` | Cookie 发送顺序 |
| `http1_title_case_headers` | HTTP/1.1 头名的大小写：`True`（默认）发 `Content-Type`，`False` 发 `content-type`，但保留大写首字母的 `Host`，自动生成的头也一样。不保留调用时传入的原始拼写；HTTP/2 与 HTTP/3 的头名始终是小写 |
| `dns_timeout` / `tcp_connect_timeout` / `tls_handshake_timeout` / `ttfb_timeout` / `total_timeout` / `quic_connect_timeout` | 超时控制 |
| `max_response_body_size` / `max_connections_per_session` / `max_header_count` / `max_header_size` / `max_headers_total_size` / `min_transfer_rate`(+ `min_transfer_rate_window`) | 资源限制 / 抗 DoS |
| `max_pending_h2_requests` | 限制等待 HTTP/2 流槽位的排队请求数（默认不限）|
| `h2_fallback_h1` / `proxy_fallback_direct` / `retry_on_connection_close` | 容错选项 |
| `h2_dispatch_batch_size` | 合并进同一次 driver 写轮次的就绪 HTTP/2 请求数（默认 1）|
| `h2_data_frame_policy` | 请求体如何切分为 HTTP/2 DATA 帧（`H2DataFramePolicy`） |
| `require_close_notify` | 拒绝未收到 TLS close_notify 就被截断的响应体（默认 `False`） |
| `tls_session_resumption_policy` / `tls_session_cache_partition_policy` | TLS ticket 是否存储，以及 ticket 缓存如何分键 |
| `middleware` | 中间件列表 |
| `ca_cert` / `ca_cert_pem` / `ca_cert_der` / `verify` / `use_native_certs` | 证书配置 |
| `trust_anchor_advertisement` / `trust_anchor_recovery` / `trust_anchor_bindings` | [信任锚标识](#信任锚标识)：发出哪些 ID、按服务端指明的 ID 再试一次、为自己的根证书绑定 ID |
| `ech_config` | ECH 配置 |
| `dns` | 在哪里解析域名：`"system"`（默认）、`"google"`、`"cloudflare"`、`"quad9"`、对应的 `"*_https"` DoH 版本、写成 `"ip"` / `"ip:port"` 的 DNS 服务器，或一段 Python 代码；见 [DNS](#dns) |
| `ip_family` | 限定连接使用的地址族：`"any"`（默认）、`"ipv4"`、`"ipv6"` |
| `connect_to` | 为源站指定固定的拨号地址，`{"host:port": "ip:port"}`；TLS、`Host` 和 Cookie 仍用原域名 |
| `system_dns_cache_ttl` / `system_dns_cache_max_entries` | 缓存系统解析器的成功查询 `ttl` 秒（TTL `0` 关闭缓存但保留并发查询合并；不能与 `dns` 同时使用）|
| `keylog` | 按 Wireshark 能读的 NSS key log 格式输出 TLS 密钥：传文件路径则追加写入，传函数则在执行握手的线程上逐行调用 |
| `masque` | 到 `masque://` 代理这一跳的 `MasqueConfig`（需要 `masque` feature） |

| 方法 | 说明 |
|------|------|
| `session(...)` | 创建会话（`network_partition_context=...` 按站点分区 TLS ticket 缓存；`h3_retry_mode=...` 选择 HTTP/3 重试，见“特性”） |
| `fingerprint_info()` | 返回指纹信息 dict |
| `randomize_fingerprint(shuffle_extensions=True)` | 返回 Client 的副本，其 TLS profile 按连接打乱扩展顺序，其他配置全部保留 |
| `get(url, **kwargs)` / `post` / `put` / `delete` / `head` / `patch` / `options` | 等同 `session().get(url, **kwargs)` 等：每次调用临时建一个会话，用完即弃，调用之间不复用连接、不保留 Cookie。要发多个请求请先建会话 |
| `check_proxy(proxy, target_host="www.google.com", target_port=443, timeout=5.0)` | 经代理建一条隧道，返回所用秒数；见 [代理](#代理) |
| `tls_profile` / `h2_profile` / `tcp_fingerprint` / `default_headers` / `header_order` / `h3_header_order` / `cookie_order` / `timeouts` / `resource_limits` / `protocol_policy` / `verify` / `ip_family` / `h2_fallback_h1` / `proxy_fallback_direct` / `max_pending_h2_requests` / `ech_config` | 只读：客户端最终生效的配置（含预设与默认值），大多与设置它的构造参数同名。`timeouts`、`resource_limits` 是以这些参数名为键的 dict |

### Session

所有 HTTP 方法 (get/post/put/delete/head/patch/options) 支持：

| 参数 | 说明 |
|------|------|
| `headers` | 请求头 |
| `params` | URL 查询参数 |
| `json` / `data` / `body` / `multipart` | 请求体 |
| `cookies` / `cookie_override` | 本次请求的 Cookie，`dict` 或 `(名, 值)` 二元组列表。按给定顺序排在会话自己的 Cookie 之后，覆盖项最后；`cookie_override` 会去掉会话里同名的 Cookie，`cookies` 里同名给两次就发两个 |
| `timeout` | 请求超时 (秒) |
| `bearer_auth` / `basic_auth` | 认证 |
| `proxy` | 请求级代理覆盖 |
| `no_decompress` / `accept_encoding` | 编码控制 |
| `priority` / `h2_priority_weight` | RFC 9218 请求优先级 / HTTP/2 HEADERS 帧旧式优先级字段的权重（0–255） |

| 方法 | 说明 |
|------|------|
| `send_streaming(method, url, ...)` | 流式请求，参数与上面的 HTTP 方法相同 |
| `ws_connect(url, *, headers, protocols)` | WebSocket 连接 |
| `preconnect(url)` / `preconnect_many(urls)` / `prefetch(urls)` | 连接预热 |
| `pool_stats()` / `pool_clear()` | 连接池统计 (`PoolStats`) / 关闭池中所有连接，Session 仍可继续使用 |
| `close()` / `closed` | 关闭 Session 并释放它持有的资源；也可用 `with session`（阻塞版）和 `async with session`，见 [Session 生命周期与内存](#session-生命周期与内存) |
| `on_request(callback)` / `on_response(callback)` | 注册 Event Hook |
| `set_cookie()` / `set_cookie_with_attrs()` / `set_cookie_raw()` | 设置 Cookie |
| `get_cookie()` / `get_cookies()` / `get_cookie_values()` / `cookie_header()` | 读取 Cookie 名与值 |
| `get_cookies_with_attrs()` / `get_all_cookies()` | 以 `Cookie` 对象读取，带完整属性 |
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
| `text(encoding=None)` | 按声明的 charset 解码文本（带缓存） |
| `json()` | 解析 JSON（带缓存）；失败抛 `JsonDecodeError` |
| `cookies` | 响应 Cookie |
| `encoding` | `Content-Type` 中声明的 charset |
| `elapsed` | 请求耗时 (秒) |
| `diagnostics` | 分阶段计时 dict：`dns_ms`/`tcp_ms`/`tls_ms`/`ttfb_ms`/`total_ms` + `remote_addr`/`protocol`/`cipher_suite`（未测阶段为 None）+ `trust_anchor`，即请求新建连接上的信任锚协商 |
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
| `H2Profile` | HTTP/2 指纹配置（SETTINGS、窗口更新、伪头顺序、优先级、`initial_stream_id`） |
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
| `features()` | 本构建启用了哪些可选 feature，按 Cargo 名返回 `{"quic-h3": True, ...}`；PyPI 上的 wheel 全部启用 |
| `list_presets()` | 浏览器预设列表，每项形如 `{"name": "chrome_155", "browser": "chrome", "http3": True}`；`name` 即 `Client.<name>()`、`tls_profile=`、`h2_profile=` 接受的名字 |
| `trust_anchor_identity(der)` | DER 根证书的标识，用于在 `Client(trust_anchor_bindings=...)` 里绑定信任锚 ID |

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
| `JsonDecodeError` | `json()` 遇到非 JSON body（同时也是 `json.JSONDecodeError`） |

它们都带有 `phase`、`retryable`、`safe_to_replay`、`status_code`、`proxy_error_kind`、`tls_alert`、`diagnostics` 属性，见[错误处理](#错误处理)。

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
| `proxy_pool.py` | 单代理、多跳代理链、BadProxyConfig、HealthCheckConfig、ProxyPool、用函数生成代理 |
| `session_pool.py` | SessionPool / BlockingSessionPool |
| `client_pool.py` | ClientPool 多指纹轮换 |
| `browser_fingerprints.py` | 6 种预设指纹、字符串指定、指纹随机化 |
| `custom_fingerprint.py` | TlsProfile / H2Profile / TcpFingerprint 完全自定义 |
| `fingerprint_validation.py` | validate_fingerprint_consistency |
| `streaming_response.py` | StreamingResponse 逐块/完整读取 |
| `streaming_upload.py` | body_stream 的 file-like / 生成器 / 异步可迭代源，content_length |
| `connection_prewarming.py` | preconnect / preconnect_many / prefetch |
| `metrics.py` | enable_metrics / snapshot / prometheus_text |
| `timeout_config.py` | 客户端级与请求级超时、资源限制 |
| `accept_encoding.py` | AcceptEncoding 控制、no_decompress |
| `certificate_config.py` | CA 证书 PEM/DER/文件、verify、ECH |
| `ip_family.py` | `ip_family=` 地址族选择，离线演示 + 打真实双栈域名 |
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
