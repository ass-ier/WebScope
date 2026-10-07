from app import models as m
from app.schemas import AssessmentCreate, Configuration, ScopeInput
from app.services import assessments
from app.services.analysis import analyze
from app.services.store import event, evidence


def infrastructure_example(db):
    target = "https://synthetic.example.invalid/"
    item = assessments.create(
        db,
        AssessmentCreate(
            name="Synthetic DNS and TLS observations",
            description="Entirely synthetic infrastructure fixtures. No DNS queries or TLS connections were made.",
            target=target,
            scope=ScopeInput(allowed_hosts=["synthetic.example.invalid"]),
            config=Configuration(),
            authorized=False,
        ),
    )
    item.data_origin = "SYNTHETIC"
    host_ev = evidence(
        db,
        item.id,
        "ENDPOINT",
        target,
        "Synthetic host fixture",
        {"hostname": "synthetic.example.invalid", "addresses": ["192.0.2.10"], "synthetic": True},
    )
    db.add(
        m.Host(
            assessment_id=item.id,
            evidence_id=host_ev.id,
            hostname="synthetic.example.invalid",
            addresses=["192.0.2.10"],
        )
    )
    answers = {
        "A": ["192.0.2.10"],
        "AAAA": ["2001:db8::10"],
        "CNAME": ["edge.synthetic.example.invalid."],
        "MX": ["10 mail.synthetic.example.invalid."],
        "TXT": ['"v=spf1 -all"'],
        "NS": ["ns.synthetic.example.invalid."],
        "SOA": [
            "ns.synthetic.example.invalid. admin.synthetic.example.invalid. 2026100701 3600 600 86400 300"
        ],
    }
    for kind, values in answers.items():
        ev = evidence(
            db,
            item.id,
            "DNS_RESPONSE",
            target,
            f"Synthetic DNS {kind}",
            {
                "record_type": kind,
                "records": values,
                "ttl": 300,
                "resolver": "fixture (no network)",
                "timestamp": m.now(),
                "synthetic": True,
                "observation": "Illustrative record only; an unusual DNS value is not a vulnerability.",
            },
        )
        db.add(
            m.DNSRecord(
                assessment_id=item.id,
                evidence_id=ev.id,
                hostname="synthetic.example.invalid",
                record_type=kind,
                ttl=300,
                resolver="fixture (no network)",
                records=values,
            )
        )
        event(db, item.id, "SYNTHETIC_DNS_LOADED", f"Loaded {kind} fixture", {"evidence_id": ev.id})
    details = {
        "subject": "CN=synthetic.example.invalid",
        "issuer": "CN=WebScope synthetic CA (not a real certificate)",
        "sans": ["different.example.invalid"],
        "not_before": "2024-01-01T00:00:00+00:00",
        "not_after": "2025-01-01T00:00:00+00:00",
        "expired": True,
        "not_yet_valid": False,
        "hostname_matches": False,
        "signature_algorithm": "1.2.840.113549.1.1.5",
        "signature_hash": "sha1",
        "public_key_type": "RSAPublicKey",
        "public_key_bits": 1024,
        "fingerprint_sha256": "0" * 64,
        "pem": "No PEM: synthetic observation, not an actual certificate",
        "tls_version": "TLSv1.1",
        "cipher": ["synthetic illustrative cipher", "TLSv1.1", 128],
        "verified": False,
        "verification_error": "Synthetic expired, mismatched, untrusted certificate fixture",
        "chain_collection": "synthetic illustrative chain",
        "chain": [
            {"subject": "CN=synthetic.example.invalid", "issuer": "CN=WebScope synthetic CA"},
            {"subject": "CN=WebScope synthetic CA", "issuer": "CN=WebScope synthetic CA"},
        ],
        "protocol_scope": "Synthetic demonstration, not a negotiated connection or a protocol-support claim.",
        "synthetic": True,
    }
    ev = evidence(
        db, item.id, "TLS_CERTIFICATE", target, "Synthetic weak TLS certificate observation", details
    )
    db.add(
        m.TLSCertificate(
            assessment_id=item.id, evidence_id=ev.id, hostname="synthetic.example.invalid", details=ev.data
        )
    )
    analyze(db, item)
    item.status = "COMPLETED"
    event(db, item.id, "SYNTHETIC_DATA_LOADED", "DNS/TLS examples loaded offline; every value is synthetic.")
    return item
