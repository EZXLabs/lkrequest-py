"""
HTTP/1.1 header-name casing

Prints the request heads lkrequest actually puts on the wire, read from the raw
bytes a local server receives, for the cases worth telling apart:

1. A browser preset such as ``Client.chrome_156()``: Title-Case. The preset
   methods take no arguments, so they cannot switch it off.
2. ``Client(...)`` with the Chrome 156 profiles and no casing option: the
   default, Title-Case.
3. The same with ``http1_title_case_headers=False``: every name in lowercase
   except ``Host``, which keeps its capital, the headers lkrequest adds itself
   (``content-length``) included.
4. Through an HTTP proxy: the CONNECT request lkrequest writes for the proxy
   keeps ``Host`` and ``Proxy-Authorization`` in Title-Case whatever the
   setting; the request sent inside the tunnel follows it.
5. With ``--online``: what httpbin.org/headers reports for the lowercase
   client. httpbin builds its answer from the WSGI environ, where the spelling
   of a header name is already gone, so an echo service like it cannot show
   the casing; only the raw bytes can.

Run: python examples/http1_header_case.py [--online]
"""

from __future__ import annotations

import socket
import sys
import threading

from lkrequest.blocking import Client

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
CONNECTED = b"HTTP/1.1 200 Connection established\r\n\r\n"
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/156.0.0.0",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}


class CaptureServer:
    """Records the head of every request it receives, exactly as sent.

    A CONNECT is answered with 200 and the request that then arrives inside
    the tunnel is recorded too, so the same server stands in for a proxy.
    """

    def __init__(self) -> None:
        self.heads: list[str] = []
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def take(self) -> list[str]:
        heads, self.heads = self.heads, []
        return heads

    def _serve(self) -> None:
        while True:
            conn, _ = self._sock.accept()
            with conn:
                conn.settimeout(5)
                try:
                    self._handle(conn)
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        buffer = b""
        while True:
            head, buffer = self._read_head(conn, buffer)
            if head is None:
                return
            self.heads.append(head)
            if head.startswith("CONNECT "):
                conn.sendall(CONNECTED)
                continue  # the tunneled request comes next on this connection
            length = 0
            for line in head.split("\r\n")[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "content-length":
                    length = int(value)
            while len(buffer) < length:
                buffer += conn.recv(65536)
            conn.sendall(OK)
            return

    @staticmethod
    def _read_head(conn: socket.socket, buffer: bytes) -> tuple[str | None, bytes]:
        while b"\r\n\r\n" not in buffer:
            chunk = conn.recv(65536)
            if not chunk:
                return None, buffer
            buffer += chunk
        head, _, rest = buffer.partition(b"\r\n\r\n")
        return head.decode("latin-1"), rest


def show(title: str, heads: list[str]) -> None:
    print(f"== {title} ==")
    for head in heads:
        request_line, *lines = head.split("\r\n")
        print(f"  {request_line}")
        for line in lines:
            name = line.partition(":")[0]
            mark = "" if name == name.lower() else "   <- not lowercase"
            print(f"    {line}{mark}")
        print()


def send(client: Client, url: str, **session_options) -> None:
    session = client.session(**session_options)
    session.post(url, headers={"X-Custom-Header": "Value"}, body=b"hello")


def main() -> None:
    server = CaptureServer()
    target = f"{server.url}/headers"
    chrome_156 = {"tls_profile": "chrome_156", "h2_profile": "chrome_156"}

    send(Client.chrome_156(), target)
    show("1. Client.chrome_156() (preset)", server.take())

    send(Client(**chrome_156, default_headers=BROWSER_HEADERS), target)
    show("2. Client(chrome_156 profiles), casing left at its default", server.take())

    lowercase = Client(
        **chrome_156,
        default_headers=BROWSER_HEADERS,
        http1_title_case_headers=False,
    )
    send(lowercase, target)
    show(
        "3. Client(chrome_156 profiles, http1_title_case_headers=False)", server.take()
    )

    # The capture server plays the proxy: the first head is the CONNECT written
    # for the proxy, the second the request sent through the tunnel.
    proxy = f"http://YOUR_PROXY_USER:YOUR_PROXY_PASS@proxy.example.com:1080:{server.port}"
    send(lowercase, "http://example.test/headers", proxy=proxy)
    show("4. The same client through an HTTP proxy", server.take())

    if "--online" in sys.argv:
        session = lowercase.session(http1_only=True)
        names = list(session.get("https://httpbin.org/headers").json()["headers"])
        print("== 5. httpbin.org/headers, asked by the lowercase client ==")
        print(f"  header names it reports: {names}")
        print("  (compare with case 3, which shows what this client puts on the wire)")


if __name__ == "__main__":
    main()
