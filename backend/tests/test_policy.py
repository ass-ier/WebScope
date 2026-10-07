import asyncio
import time

import httpx
import pytest

from app import models as m
from app.schemas import Configuration, ScopeInput
from app.services.assessments import scope_for
from app.services.network import NetworkRun
from app.services.scope import PolicyError, Scope
from app.services.store import rows


@pytest.mark.parametrize(
    "url",
    [
        "http://allowed.test.evil.test/",
        "http://allowed.test@denied.test/",
        "http://denied.test/",
        "http://allowed.test/admin",
        "http://allowed.test/%61dmin/private",
        "http://allowed.test/a/../admin/private",
        "http://allowed.test/a/%2e%2e/admin",
        "http://allowed.test/%2561dmin/private",
        "http://allowed.test//admin/private",
        "http://allowed.test/admin;session/foo",
        "http://allowed.test/%2fadmin/private",
        "http://allowed.test/%255cadmin",
        "http://allowed.test:8888/",
        "http://allowed.test/%00",
        "file:///etc/passwd",
        "http://allowed.test\\@denied.test/",
    ],
)
async def test_blocked_destinations_never_resolve_or_send(db, make_assessment, url):
    item = make_assessment("http://allowed.test")
    calls = []

    async def resolver(host):
        calls.append(("resolve", host))
        raise AssertionError("Blocked URL reached DNS")

    def send(request):
        calls.append(("send", request.url))
        raise AssertionError("Blocked URL reached HTTP")

    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(send), resolver)
    assert await run.request(url) is None
    assert calls == []
    assert any(
        e.type.endswith("BLOCKED") or e.type.startswith("INVALID") for e in rows(db, m.Evidence, item.id)
    )


async def test_blocked_redirect_no_follow(db, make_assessment):
    item = make_assessment()
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://evil.test/private?token=REDIRECT_SECRET"})

    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(handler))
    await run.request("http://127.0.0.1:9998/")
    assert len(calls) == 1
    blocked = [e for e in rows(db, m.Evidence, item.id) if e.type == "REDIRECT_BLOCKED"]
    assert len(blocked) == 1 and "REDIRECT_SECRET" not in str(blocked[0].data)


async def test_redirects_share_budget_and_rate(db, make_assessment):
    item = make_assessment(max_requests=3, max_redirects=5)
    times = []

    def handler(request):
        times.append(time.monotonic())
        return httpx.Response(302, headers={"location": "/hop" + str(len(times))})

    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(handler))
    await run.request("http://127.0.0.1:9998/")
    assert len(times) == 3 and run.count == 3
    assert all(b - a >= 0.095 for a, b in zip(times, times[1:]))
    assert any(e.type == "BUDGET_EXHAUSTED" for e in rows(db, m.Evidence, item.id))


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1"]
)
async def test_private_addresses_never_send_without_optin(db, make_assessment, address):
    item = make_assessment("http://allowed.test")
    item.config = {**item.config, "allow_private_network": False}
    sent = []

    async def resolver(host):
        return [address]

    run = NetworkRun(
        db, item.id, scope_for(db, item), httpx.MockTransport(lambda r: sent.append(r)), resolver
    )
    await run.request("http://allowed.test/")
    assert not sent


async def test_dns_pinning_preserves_host_and_no_reresolution(db, make_assessment):
    item = make_assessment("http://allowed.test")
    resolved, sent = [], []

    async def resolver(host):
        resolved.append(host)
        return ["127.0.0.1"]

    def handler(request):
        sent.append(request)
        return httpx.Response(200, text="ok")

    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(handler), resolver)
    await run.request("http://allowed.test/")
    await run.request("http://allowed.test/second")
    assert resolved == ["allowed.test"]
    assert all(r.url.host == "127.0.0.1" and r.headers["host"] == "allowed.test" for r in sent)
    assert all(r.extensions["sni_hostname"] == "allowed.test" for r in sent)
    assert run.count == 3


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "CONNECT", "TRACE"])
async def test_unsafe_methods_never_send(db, make_assessment, method):
    item = make_assessment()
    sent = []
    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(lambda r: sent.append(r)))
    assert await run.request("http://127.0.0.1:9998/", method=method) is None
    assert sent == []


async def test_timeout_is_recorded(db, make_assessment):
    item = make_assessment(timeout_seconds=0.1)

    async def slow(request):
        await asyncio.sleep(1)
        return httpx.Response(200, text="too late")

    run = NetworkRun(db, item.id, scope_for(db, item), httpx.MockTransport(slow))
    assert await run.request("http://127.0.0.1:9998/") is None
    assert any(e.type == "HTTP_TIMEOUT" for e in rows(db, m.Evidence, item.id))


async def test_size_cap(db, make_assessment):
    item = make_assessment(max_body_bytes=512)
    run = NetworkRun(
        db, item.id, scope_for(db, item), httpx.MockTransport(lambda r: httpx.Response(200, text="a" * 50000))
    )
    tx = await run.request("http://127.0.0.1:9998/")
    assert tx.response["truncated"] and len(tx.response["body"]) == 512


def test_exact_normalization_and_explicit_network_authorization():
    scope = Scope(
        "https://Allowed.Test.",
        ScopeInput(allowed_hosts=["allowed.test"], excluded_paths=["/admin"]),
        Configuration(),
        False,
    )
    assert scope.validate("https://ALLOWED.test.:443/a") == "https://allowed.test/a"
    with pytest.raises(PolicyError, match="authorization"):
        scope.network_allowed("https://allowed.test/")
    with pytest.raises(PolicyError):
        scope.address("::ffff:127.0.0.1")
