"""WebScope Test Application — FOR LOCAL SECURITY TESTING ONLY.

Bind only to loopback. All routes are read-only and contain synthetic data.
"""
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

app = FastAPI(title="WebScope Test Application — FOR LOCAL SECURITY TESTING ONLY")
REQUESTS = []


@app.middleware("http")
async def record_request(request, call_next):
    REQUESTS.append(request.url.path)
    return await call_next(request)


@app.get("/")
def home():
    response = HTMLResponse("""<!doctype html><html><head>
    <title>WebScope Test Application</title><meta name="generator" content="WebScope Fixture">
    </head><body><h1>FOR LOCAL SECURITY TESTING ONLY</h1>
    <a href="/login">Login fixture</a><a href="/api/users">Synthetic API</a>
    <a href="/verbose">Verbose error</a><a href="/redirect-blocked">Blocked redirect</a>
    <a href="/admin/private">Excluded fixture</a><a href="https://outside.invalid/resource">External (never fetch)</a>
    <form action="/session" method="POST"><input name="username"><input name="password" value="FORM_DUMMY_SECRET"></form>
    <script src="/assets/react.production.js"></script></body></html>""")
    response.headers.append("Set-Cookie", "session=COOKIE_DUMMY_SECRET; Path=/; SameSite=None")
    response.headers.append("Set-Cookie", "preferences=PREFERENCE_DUMMY_SECRET; Path=/; Secure; HttpOnly; SameSite=Lax")
    response.headers["X-Powered-By"] = "Express"
    return response


@app.get("/login")
def login():
    return HTMLResponse("<html><title>Login fixture</title><body>No authentication is implemented or tested.</body></html>")


@app.get("/assets/react.production.js")
def javascript():
    return Response('/* Synthetic technology marker, not React code. */\nfetch("/api/profile");\n//# sourceMappingURL=app.js.map',
                    media_type="application/javascript")


@app.get("/api/users")
def users():
    return JSONResponse({"users": [{"id": 1, "name": "Synthetic Analyst"}], "api_token": "API_DUMMY_SECRET"},
                        headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})


@app.get("/cors")
def cors():
    return JSONResponse({"public": "synthetic fixture only"},
                        headers={"Access-Control-Allow-Origin": "https://webscope.invalid",
                                 "Access-Control-Allow-Credentials": "true", "Vary": "Origin"})


@app.get("/verbose")
def verbose():
    return Response("Traceback (most recent call last):\nFixtureError: synthetic diagnostic only",
                    status_code=500, media_type="text/plain")


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin/private\nAllow: /api/docs\n", media_type="text/plain")


@app.get("/sitemap.xml")
def sitemap():
    return Response('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/catalog</loc></url></urlset>',
                    media_type="application/xml")


@app.get("/.env")
def env():
    return Response("APP_NAME=WebScopeFixture\nAPI_KEY=ENV_DUMMY_SECRET\n", media_type="text/plain")


@app.get("/.git/")
def git_metadata():
    return Response("ref: refs/heads/fixture-only", media_type="text/plain")


@app.get("/debug")
def debug():
    return HTMLResponse("<title>Index of /debug</title><p>Synthetic directory listing</p>")


@app.get("/redirect-blocked")
def redirect():
    return RedirectResponse("http://localhost:9989/never-requested")


@app.get("/admin/private")
def excluded():
    return Response("This excluded route must never be collected.", media_type="text/plain")


@app.get("/fixture-requests")
def requests():
    return REQUESTS
