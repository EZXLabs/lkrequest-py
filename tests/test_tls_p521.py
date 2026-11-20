"""P-521, which the Firefox presets and `safari_18` offer: a server certificate
on the curve, over TLS 1.3 (signed with `ecdsa_secp521r1_sha512`) and TLS 1.2
(signed with the client's first ECDSA scheme, SHA-256, which TLS 1.2 allows on
any curve), and a key exchange on it. Each failed on the client until the Rust
library implemented P-521; Chrome offers none of it, and is still refused.

The servers are local Python ones over TLS. A P-256 CA signs their
certificates, so the chain verifies whatever the leaf, and only the handshake
is on P-521.
"""

from __future__ import annotations

import datetime
import ipaddress
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import lkrequest
from lkrequest.blocking import Client as BlockingClient

OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
VERSIONS = [ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2]
VERSION_IDS = ["tls13", "tls12"]
OFFER_P521 = ["firefox_156", "safari_18"]


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> tuple[bytes, dict]:
    """A P-256 CA, and certificates for 127.0.0.1 on P-521 and P-256."""
    now = datetime.datetime.now(datetime.timezone.utc)
    validity = (now - datetime.timedelta(days=1), now + datetime.timedelta(days=30))
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name("lkrequest test CA"))
        .issuer_name(name("lkrequest test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(validity[0])
        .not_valid_after(validity[1])
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("p521")
    leaves = {}
    for label, curve in (("p521", ec.SECP521R1()), ("p256", ec.SECP256R1())):
        key = ec.generate_private_key(curve)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name("127.0.0.1"))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(validity[0])
            .not_valid_after(validity[1])
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_file = directory / f"{label}.pem"
        key_file = directory / f"{label}.key"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        leaves[label] = (cert_file, key_file)
    return ca.public_bytes(serialization.Encoding.PEM), leaves


def serve(raw_http, pki, leaf: str, version: ssl.TLSVersion, curve: str | None = None):
    """A server with the `leaf` certificate, over one TLS version, and with a
    key exchange on `curve` alone when one is given."""
    _, leaves = pki
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*leaves[leaf])
    context.set_alpn_protocols(["http/1.1"])
    context.minimum_version = context.maximum_version = version
    if curve is not None:
        context.set_ecdh_curve(curve)
    return raw_http(lambda request: OK, ssl=context)


def get(pki, server, preset: str) -> lkrequest.Response:
    ca_pem, _ = pki
    client = BlockingClient(tls_profile=preset, ca_cert_pem=ca_pem, disable_http3=True)
    return client.session().get(f"{server.url}/")


@pytest.mark.parametrize("version", VERSIONS, ids=VERSION_IDS)
@pytest.mark.parametrize("preset", OFFER_P521)
def test_a_p521_certificate(raw_http, pki, preset, version):
    server = serve(raw_http, pki, "p521", version)
    assert get(pki, server, preset).status_code == 200


@pytest.mark.parametrize("version", VERSIONS, ids=VERSION_IDS)
@pytest.mark.parametrize("preset", OFFER_P521)
def test_a_p521_key_exchange(raw_http, pki, preset, version):
    # Over TLS 1.3 the presets send no P-521 key share, so the server asks for
    # one with a HelloRetryRequest.
    server = serve(raw_http, pki, "p256", version, curve="secp521r1")
    assert get(pki, server, preset).status_code == 200


@pytest.mark.parametrize("version", VERSIONS, ids=VERSION_IDS)
def test_chrome_offers_no_p521(raw_http, pki, version):
    # The server finds nothing it can use and ends the handshake. (An asyncio
    # server drops the alert it would send, so only the failure is checked.)
    server = serve(raw_http, pki, "p521", version)
    with pytest.raises(lkrequest.TlsError) as caught:
        get(pki, server, "chrome_158")
    assert caught.value.phase == "tls_handshake"
