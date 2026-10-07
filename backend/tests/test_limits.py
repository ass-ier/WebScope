import asyncio
import gzip
import time

import httpx
import pytest

from app import models as m
from app.services import assessments
from app.services.assessments import scope_for
from app.services.network import NetworkRun
from app.services.store import rows


class WireStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


async def test_gzip_expansion_bounded_before_persistence(db, make_assessment):
    item = make_assessment(max_body_bytes=1024)
    compressed = gzip.compress(b"a" * 2_000_000)
    run = NetworkRun(
        db,
        item.id,
        scope_for(db, item),
        httpx.MockTransport(
            lambda r: httpx.Response(
                200,
                headers={"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                stream=WireStream([compressed]),
            )
        ),
    )
    tx = await run.request("http://127.0.0.1:9998/")
    assert tx.response["truncated"] and len(tx.response["body"]) == 1024
    assert tx.response["wire_body_hash"]


async def test_malformed_compression_explicit_failure(db, make_assessment):
    item = make_assessment()
    run = NetworkRun(
        db,
        item.id,
        scope_for(db, item),
        httpx.MockTransport(
            lambda r: httpx.Response(
                200,
                headers={"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                stream=WireStream([b"not gzip"]),
            )
        ),
    )
    assert await run.request("http://127.0.0.1:9998/") is None
    assert any(e.type == "HTTP_FAILED" for e in rows(db, m.Evidence, item.id))


async def test_trickle_body_total_timeout(db, make_assessment):
    item = make_assessment(timeout_seconds=0.1)

    class Trickle(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(20):
                await asyncio.sleep(0.04)
                yield b"a"

    run = NetworkRun(
        db, item.id, scope_for(db, item), httpx.MockTransport(lambda r: httpx.Response(200, stream=Trickle()))
    )
    started = time.monotonic()
    assert await run.request("http://127.0.0.1:9998/") is None
    assert time.monotonic() - started < 0.4
    assert any(e.type == "HTTP_TIMEOUT" for e in rows(db, m.Evidence, item.id))


async def test_budget_covers_redirects_robots_sitemap_and_resources(db, make_assessment):
    item = make_assessment(max_requests=5)
    actual_sends = []

    def handler(request):
        actual_sends.append((request.url.path, time.monotonic()))
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/landing"})
        if request.url.path == "/landing":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="""
            <a href="/first">first</a><a href="/second">second</a><script src="/script.js"></script>""",
            )
        return httpx.Response(200, text="fixture")

    await assessments.collect(db, item, transport=httpx.MockTransport(handler))
    assert [p for p, _ in actual_sends] == ["/", "/landing", "/robots.txt", "/sitemap.xml", "/first"]
    assert all(b[1] - a[1] >= 0.1 for a, b in zip(actual_sends, actual_sends[1:]))
    assert any(e.type == "BUDGET_EXHAUSTED" for e in rows(db, m.Evidence, item.id))


async def test_run_duration_and_authority_headers_stop_before_send(db, make_assessment):
    item = make_assessment(max_duration_seconds=1)
    called = []
    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(lambda r: called.append(r)))
    assert await run.request("http://127.0.0.1:9998/", headers={"Host": "evil.test"}) is None
    assert not called
    run.started -= 2
    assert await run.request("http://127.0.0.1:9998/") is None
    assert not called
    assert any(e.type == "RUN_TIMEOUT" for e in rows(db, m.Evidence, item.id))


@pytest.mark.parametrize(
    "field,value",
    [
        ("components", []),
        ("security", {}),
        ("paths", []),
        ("servers", "http://evil.test"),
        ("servers", [{"url": 42}]),
        ("servers", [{"url": "http://{host}", "variables": {"host": []}}]),
    ],
)
def test_openapi_malformed_shapes_do_not_crash(client, payload, field, value):
    aid = client.post("/api/assessments", json=payload).json()["id"]
    document = {"openapi": "3.0.3", "paths": {}, field: value}
    response = client.post(f"/api/assessments/{aid}/openapi", json={"document": document})
    assert response.status_code == 400


def test_api_body_cap_and_null_guards(client, payload):
    response = client.post("/api/assessments", content=b" " * 2_100_001)
    assert response.status_code == 413
    aid = client.post("/api/assessments", json=payload).json()["id"]
    assert client.patch(f"/api/assessments/{aid}", json={"config": None}).status_code == 400
    assert client.patch(f"/api/assessments/{aid}", json={"name": None}).status_code == 400


async def test_explicit_http_https_and_methods_inventory(db, make_assessment):
    item = make_assessment(availability=True, methods=True, robots=False, sitemap=False, links=False)
    sends = []

    def handler(request):
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        sends.append((request.method, request.url.scheme, port))
        return httpx.Response(200, text="fixture", headers={"Allow": "GET, HEAD, OPTIONS, POST"})

    await assessments.collect(db, item, transport=httpx.MockTransport(handler))
    assert sends == [
        ("GET", "http", 9998),
        ("OPTIONS", "http", 9998),
        ("HEAD", "http", 80),
        ("HEAD", "https", 443),
    ]
    assert not any(method == "POST" for method, _, _ in sends)
    assert any(
        e.details.get("allowed_methods_observed") == "GET, HEAD, OPTIONS, POST"
        for e in rows(db, m.Endpoint, item.id)
    )


def test_production_spa_deep_links_and_unknown_api(engine, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app

    (tmp_path / "index.html").write_text("<html><body>WebScope fixture shell</body></html>")
    monkeypatch.setenv("WEBSCOPE_FRONTEND_DIR", str(tmp_path))
    with TestClient(create_app(engine)) as client:
        assert "WebScope fixture shell" in client.get("/assessments/new").text
        assert client.get("/api/not-a-real-route").status_code == 404


async def test_unexpected_parser_failure_retains_attempt_and_source_evidence(
    db, make_assessment, monkeypatch
):
    item = make_assessment()

    def fail_parser(*args):
        raise RuntimeError("Synthetic parser failure")

    monkeypatch.setattr("app.services.assessments.harvest", fail_parser)
    with pytest.raises(RuntimeError, match="Synthetic parser"):
        await assessments.collect(
            db, item, transport=httpx.MockTransport(lambda r: httpx.Response(200, text="fixture"))
        )
    assert db.get(m.Assessment, item.id).status == "FAILED"
    assert any(e.type == "HTTP_RESPONSE" for e in rows(db, m.Evidence, item.id))
    assert any(e.event == "NETWORK_ATTEMPT" for e in rows(db, m.TimelineEvent, item.id))
    assert any(e.event == "EXECUTION_FAILED" for e in rows(db, m.TimelineEvent, item.id))


async def test_variable_persistence_delay_cannot_compress_actual_send_spacing(
    db, make_assessment, monkeypatch
):
    item = make_assessment()
    original_commit = db.commit
    commits = 0
    sends = []

    def variable_commit():
        nonlocal commits
        commits += 1
        if commits == 2:
            time.sleep(0.05)
        original_commit()

    def handler(request):
        sends.append(time.monotonic())
        return httpx.Response(200, text="fixture")

    monkeypatch.setattr(db, "commit", variable_commit)
    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(handler))
    await run.request("http://127.0.0.1:9998/first")
    await run.request("http://127.0.0.1:9998/second")
    assert sends[1] - sends[0] >= 0.1
