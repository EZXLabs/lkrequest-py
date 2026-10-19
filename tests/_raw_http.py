"""A plain HTTP/1.1 server that answers with bytes the test chooses and records
what it received.

Some inputs cannot be produced through a real framework: a `Location` in raw
UTF-8, a `Set-Cookie` with an empty `Max-Age`, a `deflate` body no encoder would
write, a proxy that refuses a CONNECT. This server writes whatever bytes the
test hands it and then closes the connection, and it keeps the headers of every
request exactly as they arrived. It runs on a thread of its own.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from dataclasses import dataclass

MAX_HEAD = 64 * 1024


@dataclass
class Received:
    method: str
    target: str
    # Header names are lower-cased; values and order are as they arrived.
    headers: list[tuple[str, str]]

    def values(self, name: str) -> list[str]:
        return [value for key, value in self.headers if key == name.lower()]


class RawHttpServer:
    """Answers each request with `reply(request)`, written in `chunk_size`-byte
    pieces when given, then closes the connection."""

    def __init__(
        self,
        reply: Callable[[Received], bytes],
        *,
        chunk_size: int | None = None,
    ) -> None:
        self.requests: list[Received] = []
        self.port = 0
        self._reply = reply
        self._chunk_size = chunk_size
        self._writers: set[asyncio.StreamWriter] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.AbstractServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        started = threading.Event()

        def run() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            self._server = loop.run_until_complete(
                asyncio.start_server(self._handle, "127.0.0.1", 0, limit=MAX_HEAD)
            )
            self.port = self._server.sockets[0].getsockname()[1]
            started.set()
            loop.run_forever()
            loop.close()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert started.wait(10), "the raw HTTP server did not start"

    def stop(self) -> None:
        async def shutdown() -> None:
            self._server.close()
            for writer in list(self._writers):
                writer.close()
            handlers = [
                t for t in asyncio.all_tasks() if t is not asyncio.current_task()
            ]
            for handler in handlers:
                handler.cancel()
            await asyncio.gather(*handlers, return_exceptions=True)
            self._loop.stop()

        asyncio.run_coroutine_threadsafe(shutdown(), self._loop)
        self._thread.join(5)

    async def _handle(self, reader, writer) -> None:
        self._writers.add(writer)
        try:
            request = await self._read_request(reader)
            if request is None:
                return
            self.requests.append(request)
            await self._write(writer, self._reply(request))
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    async def _read_request(self, reader) -> Received | None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            return None  # a connection opened and closed without a request
        lines = head.decode("latin-1").split("\r\n")
        method, target, _version = lines[0].split(" ", 2)
        headers = []
        for line in lines[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers.append((name.strip().lower(), value.strip()))
        request = Received(method, target, headers)
        # Read the body so closing the connection does not reset a client that
        # is still sending it.
        length = int((request.values("content-length") or ["0"])[0])
        if length:
            await reader.readexactly(length)
        return request

    async def _write(self, writer, data: bytes) -> None:
        if not self._chunk_size:
            writer.write(data)
            await writer.drain()
            return
        for start in range(0, len(data), self._chunk_size):
            writer.write(data[start : start + self._chunk_size])
            await writer.drain()
            await asyncio.sleep(0.001)
