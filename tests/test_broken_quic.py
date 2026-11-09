"""How long a session keeps an origin whose QUIC connection failed on TCP: a
`BrokenQuicPolicy` preset, or a `BrokenQuicConfig` with the cooldowns
themselves.

The cooldown a session uses shows in what the Rust library logs when it keeps
an origin on TCP. A process gets one log setup, so those tests run their
script in a fresh interpreter.
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from urllib.parse import urlsplit

import pytest

import lkrequest
from lkrequest import BrokenQuicConfig, BrokenQuicPolicy
from lkrequest.blocking import Client as BlockingClient

STRICT = {
    "initial_cooldown": 300.0,
    "max_cooldown": 3600.0,
    "failure_escalation_threshold": 4,
    "route_cooldown": 1800.0,
    "max_entries": 1024,
    "max_route_entries": 256,
}


def settings(config: BrokenQuicConfig) -> dict:
    return {name: getattr(config, name) for name in STRICT}


def test_what_is_left_out_keeps_stricts_value():
    assert settings(BrokenQuicConfig()) == STRICT
    config = BrokenQuicConfig(initial_cooldown=2.0, max_entries=8)
    assert settings(config) == {**STRICT, "initial_cooldown": 2.0, "max_entries": 8}


def test_a_config_is_a_value():
    given = {
        "initial_cooldown": 1.5,
        "max_cooldown": 60.0,
        "failure_escalation_threshold": 2,
        "route_cooldown": 5.0,
        "max_entries": 8,
        "max_route_entries": 2,
    }
    config = BrokenQuicConfig(**given)
    assert settings(config) == given
    assert config == BrokenQuicConfig(**given)
    assert config != BrokenQuicConfig(**{**given, "max_route_entries": 3})
    assert repr(config) == (
        "BrokenQuicConfig(initial_cooldown=1.5, max_cooldown=60.0, "
        "failure_escalation_threshold=2, route_cooldown=5.0, max_entries=8, "
        "max_route_entries=2)"
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"initial_cooldown": -1.0}, "Duration must be"),
        ({"max_cooldown": float("inf")}, "Duration must be"),
        ({"route_cooldown": float("nan")}, "Duration must be"),
        (
            {"initial_cooldown": 10.0, "max_cooldown": 5.0},
            r"initial_cooldown \(10.0 s\) must not exceed max_cooldown \(5.0 s\)",
        ),
        # Above Strict's max_cooldown, which it keeps.
        ({"initial_cooldown": 4000.0}, "must not exceed max_cooldown"),
        (
            {"failure_escalation_threshold": 0},
            "failure_escalation_threshold must be at least 1",
        ),
        ({"max_entries": 0}, "max_entries must be at least 1"),
        ({"max_route_entries": 0}, "max_route_entries must be at least 1"),
    ],
)
def test_settings_that_make_no_sense_are_refused(kwargs, message):
    with pytest.raises(ValueError, match=message):
        BrokenQuicConfig(**kwargs)


@pytest.mark.parametrize(
    "policy",
    [
        BrokenQuicPolicy.Strict,
        BrokenQuicPolicy.Resilient,
        BrokenQuicPolicy.Disabled,
        BrokenQuicConfig(initial_cooldown=1.0),
    ],
)
def test_a_session_takes_a_preset_or_a_config(policy):
    lkrequest.Client().session(broken_quic_policy=policy)
    BlockingClient().session(broken_quic_policy=policy)


def test_a_session_refuses_anything_else():
    with pytest.raises(TypeError, match="BrokenQuicPolicy or a BrokenQuicConfig"):
        BlockingClient().session(broken_quic_policy="resilient")


# Asks for HTTP/3 to a name the server's certificate does not cover, which fails
# the QUIC handshake, and prints what was logged when the origin was kept on TCP.
SCRIPT = """
import logging, time
import lkrequest
from lkrequest.blocking import Client

messages = []

class Keep(logging.Handler):
    def emit(self, record):
        messages.append(record.getMessage())

logging.getLogger("lkrequest").addHandler(Keep())
logging.getLogger("lkrequest").setLevel(logging.WARNING)
lkrequest.set_log_level("warn", format="logging")

client = Client(
    tls_profile="chrome_146",
    h2_profile="chrome_146",
    quic_profile="chrome_146",
    ca_cert_pem={ca!r},
    connect_to={{{origin!r}: "127.0.0.1:{port}"}},
)
session = client.session(http3_only=True, broken_quic_policy={policy})
try:
    session.get("https://{origin}/get", timeout=5.0)
except lkrequest.RequestError:
    pass
deadline = time.monotonic() + 5.0
while time.monotonic() < deadline:
    marked = [m for m in messages if m.startswith("quic.origin_marked_broken")]
    if marked:
        print(marked[0])
        break
    time.sleep(0.02)
"""


def logged_cooldown(h3_server_url: str, server_ca: bytes, policy: str) -> int:
    """The cooldown in seconds a session given `policy` keeps the origin for."""
    port = urlsplit(h3_server_url).port
    script = SCRIPT.format(
        ca=server_ca, origin=f"uncovered.example.test:{port}", port=port, policy=policy
    )
    done = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    found = re.search(r"\bcooldown_secs=(\d+)", done.stdout)
    assert found, f"nothing logged: {done.stdout!r}"
    return int(found.group(1))


@pytest.mark.skipif(
    not hasattr(lkrequest, "QuicProfile"), reason="built without the quic-h3 feature"
)
@pytest.mark.parametrize(
    ("policy", "seconds"),
    [
        ("None", 300),
        ("lkrequest.BrokenQuicPolicy.Strict", 300),
        ("lkrequest.BrokenQuicPolicy.Resilient", 1),
        ("lkrequest.BrokenQuicConfig(initial_cooldown=7.0, max_cooldown=9.0)", 7),
        ("lkrequest.BrokenQuicConfig()", 300),
    ],
)
def test_the_session_keeps_the_origin_on_tcp_for_its_cooldown(
    h3_server_url, server_ca, policy, seconds
):
    assert logged_cooldown(h3_server_url, server_ca, policy) == seconds
