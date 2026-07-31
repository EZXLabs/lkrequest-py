"""
Extract TLS and HTTP/2 fingerprint profiles from pcap files.

Requires ``dpkt`` (install with ``pip install dpkt``).

Usage::

    from lkrequest.pcap import profiles_from_pcap

    for tls, h2 in profiles_from_pcap("capture.pcap"):
        print(tls.name, tls.cipher_suites)
"""

from __future__ import annotations

import struct
from typing import Optional

from lkrequest import TlsProfile, H2Profile


def _extract_client_hellos(pcap_path: str) -> list[bytes]:
    """Parse a pcap file and extract raw TLS ClientHello messages."""
    try:
        import dpkt
    except ImportError:
        raise ImportError(
            "dpkt is required for pcap parsing. Install with: pip install dpkt"
        )

    hellos: list[bytes] = []
    with open(pcap_path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for _, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.NeedData, dpkt.UnpackError):
                continue

            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            payload = bytes(tcp.data)
            if len(payload) < 6:
                continue

            # TLS record: content_type=22 (handshake), version 0x03xx
            if payload[0] != 0x16 or payload[1] != 0x03:
                continue
            record_len = struct.unpack("!H", payload[3:5])[0]
            if len(payload) < 5 + record_len:
                continue
            handshake = payload[5 : 5 + record_len]
            if len(handshake) < 1:
                continue
            # Handshake type 1 = ClientHello
            if handshake[0] == 0x01:
                hellos.append(payload)

    return hellos


def _extract_h2_preface_and_frames(pcap_path: str) -> list[bytes]:
    """Extract raw HTTP/2 connection preface + initial frames from a pcap."""
    try:
        import dpkt
    except ImportError:
        raise ImportError(
            "dpkt is required for pcap parsing. Install with: pip install dpkt"
        )

    H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    results: list[bytes] = []
    streams: dict[tuple, bytearray] = {}

    with open(pcap_path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for _, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.NeedData, dpkt.UnpackError):
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            payload = bytes(tcp.data)
            if not payload:
                continue

            key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            if key not in streams:
                if payload.startswith(H2_PREFACE):
                    streams[key] = bytearray(payload)
                continue

            streams[key].extend(payload)

    for data in streams.values():
        if len(data) > len(H2_PREFACE):
            results.append(bytes(data))

    return results


def profiles_from_pcap(
    path: str,
    *,
    name: str = "pcap_capture",
) -> list[tuple[TlsProfile, Optional[H2Profile]]]:
    """Extract TLS and H2 profiles from a pcap file.

    Parameters
    ----------
    path : str
        Path to the pcap or pcapng file.
    name : str
        Name to assign to extracted TLS profiles.

    Returns
    -------
    list[tuple[TlsProfile, Optional[H2Profile]]]
        List of (TlsProfile, H2Profile or None) tuples for each
        ClientHello found in the capture.
    """
    results: list[tuple[TlsProfile, Optional[H2Profile]]] = []

    hellos = _extract_client_hellos(path)
    h2_data_list = _extract_h2_preface_and_frames(path)

    h2_profile: Optional[H2Profile] = None
    if h2_data_list:
        try:
            h2_profile = H2Profile.from_h2_frames(h2_data_list[0])
        except Exception:
            pass

    for i, hello_data in enumerate(hellos):
        suffix = f"_{i}" if len(hellos) > 1 else ""
        try:
            tls = TlsProfile.from_client_hello(hello_data, name=f"{name}{suffix}")
            results.append((tls, h2_profile))
        except Exception:
            continue

    return results
