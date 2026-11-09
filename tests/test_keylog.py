"""`keylog=`: the TLS secrets of every handshake, in the NSS key log format
Wireshark reads, appended to a file or handed to a function line by line.
"""

from __future__ import annotations

import pathlib

import pytest

import lkrequest
from lkrequest.blocking import Client as BlockingClient

# What a TLS 1.3 handshake logs, besides anything else.
TLS13_SECRETS = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
}


def options(keylog) -> dict:
    return {
        "tls_profile": "chrome_152",
        "h2_profile": "chrome_152",
        "verify": False,
        "keylog": keylog,
    }


def assert_one_handshake(lines: list[str]) -> None:
    labels, randoms = set(), set()
    for line in lines:
        label, client_random, secret = line.split(" ")
        labels.add(label)
        randoms.add(client_random)
        assert len(client_random) == 64 and int(secret, 16) >= 0
    assert TLS13_SECRETS <= labels
    assert len(randoms) == 1


def test_a_function_is_given_each_line(server_url):
    lines: list[str] = []
    BlockingClient(**options(lines.append)).session().get(f"{server_url}/get")
    # Every line is in by the time the request returns.
    assert_one_handshake(lines)


async def test_an_async_client_hands_them_over_too(server_url):
    lines: list[str] = []
    session = lkrequest.Client(**options(lines.append)).session()
    await session.get(f"{server_url}/get")
    assert_one_handshake(lines)


def test_a_function_that_raises_leaves_the_request_alone(server_url):
    def broken(line: str) -> None:
        raise RuntimeError("disk full")

    response = BlockingClient(**options(broken)).session().get(f"{server_url}/get")
    assert response.status_code == 200


@pytest.mark.parametrize("as_path", [str, pathlib.Path], ids=["str", "pathlike"])
def test_a_file_gets_the_lines_appended(server_url, tmp_path, as_path):
    log = tmp_path / "keys.log"
    log.write_text("# earlier\n")
    BlockingClient(**options(as_path(log))).session().get(f"{server_url}/get")
    first, *lines = log.read_text().splitlines()
    assert first == "# earlier"
    assert_one_handshake(lines)


def test_what_is_neither_is_refused(tmp_path):
    async def keylog(line: str) -> None:
        pass

    with pytest.raises(TypeError, match="not an async one"):
        BlockingClient(keylog=keylog)
    with pytest.raises(TypeError, match="a file path or a function"):
        lkrequest.Client(keylog=42)
    with pytest.raises(OSError, match="Failed to open keylog file"):
        BlockingClient(keylog=str(tmp_path / "missing" / "keys.log"))
