"""
Multipart 文件上传示例

演示使用 Multipart 和 Part 进行文件上传。
"""

from lkrequest.blocking import Client
import lkrequest


def main():
    client = Client.chrome_144()
    session = client.session()

    # === 使用 Multipart 上传 ===
    print("=== Multipart 上传 ===")
    mp = lkrequest.Multipart()

    # 添加文本字段
    mp.text("title", "测试上传")
    mp.text("description", "这是一个文件上传测试")

    # 添加文件
    mp.file(
        "document",
        "hello.txt",
        "text/plain",
        b"Hello, World! This is the file content.",
    )

    resp = session.post("https://httpbin.org/post", multipart=mp)
    data = resp.json()
    print(f"状态码: {resp.status_code}")
    print(f"表单字段: {data.get('form', {})}")
    print(f"文件: {list(data.get('files', {}).keys())}")

    # === 多文件上传 ===
    print("\n=== 多文件上传 ===")
    mp2 = lkrequest.Multipart()
    mp2.text("batch_id", "batch-001")
    mp2.file("file1", "data.csv", "text/csv", b"name,age\nAlice,30\nBob,25")
    mp2.file("file2", "config.json", "application/json", b'{"debug": true}')

    resp = session.post("https://httpbin.org/post", multipart=mp2)
    data = resp.json()
    print(f"上传文件数: {len(data.get('files', {}))}")
    for name, content in data.get("files", {}).items():
        print(f"  {name}: {content[:50]}...")

    # === 使用 Part 精细控制 ===
    print("\n=== Part 精细控制 ===")
    part = lkrequest.Part("attachment", b"\x89PNG\r\n\x1a\n...")
    part.filename("image.png")
    part.content_type("image/png")
    mp3 = lkrequest.Multipart()
    mp3.part(part)
    # 不带文件名的二进制字段，text() / file() 表达不了
    mp3.part(lkrequest.Part("checksum", b"\x00\x01\x02\x03"))

    resp = session.post("https://httpbin.org/post", multipart=mp3)
    data = resp.json()
    print(f"文件: {list(data.get('files', {}).keys())}")
    print(f"表单字段: {list(data.get('form', {}).keys())}")


if __name__ == "__main__":
    main()
