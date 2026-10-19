"""Decoding a `Content-Encoding: deflate` body.

RFC 9110 says `deflate` is the zlib format (RFC 1950), but plenty of servers send
a bare deflate stream (RFC 1951) instead, so the client accepts both. Telling
them apart by the first two bytes is not enough: a raw stored block can start
with `0x78 0x9c`, which reads as a valid zlib header.
"""

from __future__ import annotations

import zlib

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

PAYLOAD = bytes(index % 251 for index in range(100_000))

# A raw RFC 1951 stream: a non-final stored block of 156 bytes whose first two
# bytes are a valid zlib header, then an empty final block.
COLLIDING_RAW = b"\x78\x9c\x00\x63\xff" + b"A" * 156 + b"\x01\x00\x00\xff\xff"


def raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def deflated(body: bytes):
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)
    )
    return lambda request: response


def new_session():
    return BlockingClient(tls_profile="chrome_152", h2_profile="chrome_152").session()


def test_a_raw_deflate_stream_that_looks_like_zlib_is_decoded(raw_http):
    server = raw_http(deflated(COLLIDING_RAW))
    assert new_session().get(f"{server.url}/").content == b"A" * 156


def test_the_same_stream_is_decoded_when_it_arrives_one_byte_at_a_time(raw_http):
    server = raw_http(deflated(COLLIDING_RAW), chunk_size=1)
    stream = new_session().send_streaming("GET", f"{server.url}/")
    decoded = b""
    while (chunk := stream.chunk_decoded()) is not None:
        decoded += chunk
    assert decoded == b"A" * 156


def test_a_longer_raw_stream_behind_the_same_prefix_is_decoded(raw_http):
    body = COLLIDING_RAW[:-5] + raw_deflate(PAYLOAD)
    server = raw_http(deflated(body))
    assert new_session().get(f"{server.url}/").content == b"A" * 156 + PAYLOAD


@pytest.mark.parametrize(
    "encode",
    [zlib.compress, raw_deflate],
    ids=["zlib", "raw"],
)
def test_both_forms_of_deflate_are_decoded(raw_http, encode):
    server = raw_http(deflated(encode(PAYLOAD)))
    assert new_session().get(f"{server.url}/").content == PAYLOAD


def test_a_zlib_stream_with_a_bad_checksum_is_an_error(raw_http):
    compressed = bytearray(zlib.compress(PAYLOAD))
    compressed[-1] ^= 0x01
    server = raw_http(deflated(bytes(compressed)))
    with pytest.raises(lkrequest.RequestError):
        new_session().get(f"{server.url}/")


def test_a_truncated_deflate_body_is_an_error(raw_http):
    server = raw_http(deflated(zlib.compress(PAYLOAD)[:-10]))
    with pytest.raises(lkrequest.RequestError):
        new_session().get(f"{server.url}/")


def test_a_truncated_deflate_body_is_an_error_when_streamed(raw_http):
    server = raw_http(deflated(zlib.compress(PAYLOAD)[:-10]))
    stream = new_session().send_streaming("GET", f"{server.url}/")
    with pytest.raises(lkrequest.RequestError):
        while stream.chunk_decoded() is not None:
            pass
