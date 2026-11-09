"""`set_log_level(..., format="logging")` hands the library's log events to
Python's `logging`.

A process gets one log setup, the first one asked for, so each test runs its
script in a fresh interpreter.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

import lkrequest

# Records what reaches `logging`, after leasing a proxy from a blocking pool,
# which logs `proxy_pool.acquire` (debug), and marking it bad, which logs
# `proxy_pool.mark_bad` (info).
SCRIPT = """
import json, logging, time
import lkrequest, lkrequest.blocking

records = []

class Keep(logging.Handler):
    def emit(self, record):
        records.append(record)

root = logging.getLogger("lkrequest")
root.addHandler(Keep())
root.setLevel(logging.{python_level})
print(json.dumps({{"installed": lkrequest.set_log_level("{level}", format="logging")}}))
pool = lkrequest.blocking.ProxyPool(["http://127.0.0.1:1"])
pool.acquire().release()
pool.mark_bad("some-proxy")

deadline = time.monotonic() + {wait}
while not any("proxy_pool.mark_bad" in r.getMessage() for r in records):
    if time.monotonic() > deadline:
        break
    time.sleep(0.02)
print(json.dumps([
    {{"name": r.name, "level": r.levelno, "message": r.getMessage()}}
    for r in records if r.getMessage().startswith("proxy_pool.")
]))
"""


def run(
    level: str, python_level: str = "DEBUG", wait: float = 5.0
) -> tuple[bool, list[dict]]:
    script = SCRIPT.format(level=level, python_level=python_level, wait=wait)
    done = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    # Exiting with the forwarding thread still there is clean.
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    installed, records = done.stdout.splitlines()
    return json.loads(installed)["installed"], json.loads(records)


def test_events_reach_logging_under_lkrequest():
    installed, records = run("debug")
    assert installed
    assert {
        "name": "lkrequest._lkrequest.proxy",
        "level": 20,
        # The fields follow the message as name=value.
        "message": "proxy_pool.mark_bad proxy=some-proxy",
    } in records
    assert any(r["message"].startswith("proxy_pool.acquire") for r in records)
    assert {r["level"] for r in records} == {10, 20}


def test_the_level_given_decides_what_is_passed_on():
    _, records = run("info")
    assert [r["message"] for r in records] == ["proxy_pool.mark_bad proxy=some-proxy"]


def test_the_loggers_own_level_still_applies():
    _, records = run("debug", python_level="WARNING", wait=0.5)
    assert records == []


def test_an_unknown_format_names_logging_among_the_choices():
    with pytest.raises(ValueError, match="logging"):
        lkrequest.set_log_level("info", format="syslog")
