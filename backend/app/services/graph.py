from urllib.parse import urlsplit

from app import models as m
from app.services.store import rows


def graph(db, assessment_id):
    nodes, edges = {}, {}

    def node(id, label, kind, **extra):
        nodes[id] = {"id": id, "label": label, "kind": kind, **extra}

    def edge(source, target, label):
        key = f"{source}|{label}|{target}"
        edges[key] = {"id": key, "source": source, "target": target, "label": label}

    endpoints = rows(db, m.Endpoint, assessment_id)
    by_url = {e.url: e.id for e in endpoints}
    for host in rows(db, m.Host, assessment_id):
        hid = "host:" + host.hostname
        node(hid, host.hostname, "host", evidence_id=host.evidence_id)
        for address in host.addresses:
            aid = "ip:" + address
            node(aid, address, "ip", evidence_id=host.evidence_id)
            edge(hid, aid, "resolves_to")
    for item in endpoints:
        host = urlsplit(item.url).hostname
        hid = "host:" + host
        if hid not in nodes:
            node(hid, host, "host" if item.in_scope else "external")
        kind = "external" if not item.in_scope else item.details.get("kind", "endpoint")
        node(
            item.id,
            f"{item.method} {urlsplit(item.url).path}",
            kind,
            url=item.url,
            evidence_id=item.evidence_id,
        )
        edge(hid, item.id, "hosts" if item.in_scope else "references")
    for item in endpoints:
        source = by_url.get(item.details.get("source_url"))
        if source and source != item.id:
            edge(source, item.id, item.details.get("relation", "declares"))
    for tech in rows(db, m.Technology, assessment_id):
        node(tech.id, f"{tech.name} ({tech.confidence})", "technology", evidence_id=tech.evidence_id)
        if tech.endpoint_id:
            edge(tech.endpoint_id, tech.id, "uses")
    for finding in rows(db, m.Finding, assessment_id):
        node(finding.id, finding.title, "finding", evidence_id=finding.evidence_id)
        if finding.endpoint_id:
            edge(finding.endpoint_id, finding.id, "has_observation")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}
