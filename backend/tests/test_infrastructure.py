import asyncio
import ipaddress
import ssl
from datetime import datetime, timedelta, timezone

import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import models as m
from app.services.analysis import analyze
from app.services.assessments import scope_for
from app.services.infrastructure import DNS_TYPES, certificate_details, collect_dns, collect_tls
from app.services.network import NetworkRun
from app.services.store import rows


def make_certificate(expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WebScope loopback fixture")])
    instant = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(instant - timedelta(days=3))
        .not_valid_after(instant + timedelta(days=-1 if expired else 2))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("allowed.test")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


async def test_all_dns_types_ttl_resolver_and_errors(db, make_assessment):
    item = make_assessment("http://allowed.test", max_requests=10)

    class Record:
        def to_text(self):
            return "dev.allowed.test."

    class Answer(list):
        rrset = type("RRSet", (), {"ttl": 120})()
        nameserver = "127.0.0.1"

    class Resolver:
        nameservers = ["127.0.0.1"]
        calls = []

        async def resolve(self, host, kind, **kwargs):
            self.calls.append((host, kind))
            return Answer([Record()])

    resolver = Resolver()
    run = NetworkRun(db, item.id, scope_for(db, item))
    await collect_dns(run, resolver)
    found = rows(db, m.DNSRecord, item.id)
    assert {r.record_type for r in found} == set(DNS_TYPES)
    assert all(r.ttl == 120 and r.resolver == "127.0.0.1" for r in found)
    assert run.count == 7
    assert all("timestamp" in e.data for e in rows(db, m.Evidence, item.id) if e.type == "DNS_RESPONSE")

    class FailingResolver(Resolver):
        async def resolve(self, *args, **kwargs):
            raise dns.resolver.NXDOMAIN()

    await collect_dns(run, FailingResolver())
    assert any(e.type == "DNS_FAILED" for e in rows(db, m.Evidence, item.id))
    assert any(e.type == "BUDGET_EXHAUSTED" for e in rows(db, m.Evidence, item.id))


def test_certificate_fields_validity_hostname_and_key():
    _, cert = make_certificate(expired=True)
    details = certificate_details(cert.public_bytes(serialization.Encoding.DER), "denied.test")
    assert details["expired"] is True and details["hostname_matches"] is False
    assert details["public_key_bits"] == 2048 and details["signature_hash"] == "sha256"
    assert details["subject"] and details["issuer"] and details["sans"]
    assert details["fingerprint_sha256"]


async def test_tls_verification_failure_has_evidence_and_findings(db, make_assessment):
    item = make_assessment("https://127.0.0.1:9998", max_requests=5)
    _, cert = make_certificate(expired=True)
    calls = []

    def connector(address, port, host, timeout, verify):
        calls.append(verify)
        if verify:
            error = ssl.SSLCertVerificationError("expired")
            error.verify_message = "certificate has expired"
            raise error
        der = cert.public_bytes(serialization.Encoding.DER)
        return {
            "leaf": der,
            "chain": [der],
            "chain_collection": "fixture",
            "tls_version": "TLSv1.2",
            "cipher": ["fixture", "TLSv1.2", 256],
        }

    run = NetworkRun(db, item.id, scope_for(db, item))
    await collect_tls(run, connector)
    analyze(db, item)
    assert calls == [True, False] and run.count == 2
    stored = rows(db, m.TLSCertificate, item.id)[0]
    assert stored.details["chain"] and stored.details["verified"] is False
    assert {"WS-TLS-001", "WS-TLS-003"} <= {f.rule_id for f in rows(db, m.Finding, item.id)}


async def test_real_loopback_tls_handshake(db, make_assessment, tmp_path, monkeypatch):
    key, cert = make_certificate()
    cert_path, key_path = tmp_path / "fixture-cert.pem", tmp_path / "fixture-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    connections = []
    accepted = asyncio.Event()

    async def accept(reader, writer):
        connections.append(writer.get_extra_info("peername"))
        accepted.set()
        try:
            await reader.read(1)
        except ConnectionResetError:
            connections.append("collector closed after certificate inspection")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionResetError:
                pass  # Certificate-only collectors may close without an application exchange.

    server = await asyncio.start_server(accept, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    default_context = ssl.create_default_context
    monkeypatch.setattr(ssl, "create_default_context", lambda: default_context(cafile=str(cert_path)))
    try:
        item = make_assessment(f"https://127.0.0.1:{port}")
        run = NetworkRun(db, item.id, scope_for(db, item))
        await collect_tls(run)
        await asyncio.wait_for(accepted.wait(), 1)
        result = rows(db, m.TLSCertificate, item.id)[0].details
        assert result["verified"] and result["hostname_matches"]
        assert result["tls_version"] in ("TLSv1.2", "TLSv1.3")
        assert result["chain"] and isinstance(connections[0], tuple)
    finally:
        server.close()
        await server.wait_closed()


async def test_passive_dns_tls_cannot_network(db, make_assessment):
    item = make_assessment("https://allowed.test")
    item.config = {**item.config, "mode": "PASSIVE"}

    class Resolver:
        nameservers = []

        async def resolve(self, *args, **kwargs):
            raise AssertionError("Passive DNS must not send")

    def connector(*args, **kwargs):
        raise AssertionError("Passive TLS must not connect")

    run = NetworkRun(db, item.id, scope_for(db, item))
    await collect_dns(run, Resolver())
    await collect_tls(run, connector)
    assert run.count == 0
    assert all(e.type == "PASSIVE_MODE" for e in rows(db, m.Evidence, item.id))


async def test_dns_txt_redacted_in_observation_table_not_only_api(db, make_assessment):
    item = make_assessment("http://allowed.test")

    class Record:
        def to_text(self):
            return '"API_KEY=DNS_SENTINEL"'

    class Answer(list):
        rrset = type("RRSet", (), {"ttl": 30})()
        nameserver = "127.0.0.1"

    class Resolver:
        nameservers = ["127.0.0.1"]

        async def resolve(self, host, kind, **kwargs):
            return Answer([Record()]) if kind == "TXT" else Answer([])

    await collect_dns(NetworkRun(db, item.id, scope_for(db, item)), Resolver())
    assert "DNS_SENTINEL" not in str([r.records for r in rows(db, m.DNSRecord, item.id)])
    assert "DNS_SENTINEL" not in str([e.data for e in rows(db, m.Evidence, item.id)])


async def test_weak_negotiated_protocol_and_hostname_rules_use_fixture_evidence(db, make_assessment):
    item = make_assessment("https://mismatch.test")
    _, cert = make_certificate()
    der = cert.public_bytes(serialization.Encoding.DER)

    async def resolver(host):
        return ["127.0.0.1"]

    def connector(address, port, host, timeout, verify):
        if verify:
            error = ssl.SSLCertVerificationError("hostname mismatch")
            error.verify_message = "hostname mismatch"
            raise error
        return {
            "leaf": der,
            "chain": [der],
            "chain_collection": "synthetic connector fixture",
            "tls_version": "TLSv1.1",
            "cipher": ["fixture", "TLSv1.1", 128],
        }

    await collect_tls(NetworkRun(db, item.id, scope_for(db, item), resolver=resolver), connector)
    analyze(db, item)
    found = rows(db, m.Finding, item.id)
    assert {"WS-TLS-002", "WS-TLS-003", "WS-TLS-004"} <= {f.rule_id for f in found}
    assert all(f.status == "NEW" and f.evidence_id for f in found)
