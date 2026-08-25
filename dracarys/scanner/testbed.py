"""Built-in testbed: intentionally-vulnerable apps used by `dracarys scan-selftest`.

Used to prove the scanner GENERALIZES.

These deliberately use different endpoint names, parameter names, shapes (HTML vs
JSON) and stacks than the DRACARYS BANK lab. The generic detectors were not
written against them — if the scanner finds their flaws, detection is real.
All data is synthetic.
"""
from __future__ import annotations

import sqlite3

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.c2lnbmF0dXJlZXhhbXBsZXMxMjM0NQ"


def _posts_db() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.execute("CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    c.executemany("INSERT INTO posts VALUES (?,?,?)",
                  [(1, "Hello World", "first post"), (2, "Second", "another post")])
    c.commit()
    return c


def build_blog_app() -> FastAPI:
    """A blog with reflected XSS, error-based SQLi, open redirect, exposed .env."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    db = _posts_db()

    @app.get("/", response_class=HTMLResponse)
    def home():
        return (
            '<html><body><h1>DevBlog</h1>'
            '<form action="/search" method="get"><input name="q"></form>'
            '<a href="/post?id=1">post 1</a> <a href="/about">about</a>'
            '<a href="/go?url=/home">home</a></body></html>'
        )

    @app.get("/about", response_class=HTMLResponse)
    def about():
        return "<html><body>About DevBlog</body></html>"

    # Reflected XSS: q echoed unescaped into HTML.
    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = ""):
        return f"<html><body>Results for: {q}</body></html>"

    # Error-based SQL injection: id concatenated (numeric context, errors surface).
    @app.get("/post", response_class=HTMLResponse)
    def post(id: str = "1"):
        try:
            row = db.execute(f"SELECT title, body FROM posts WHERE id = {id}").fetchone()
        except sqlite3.Error as exc:
            return HTMLResponse(f"<html><body>DB error: {exc}</body></html>", status_code=500)
        if not row:
            return "<html><body>Not found</body></html>"
        return f"<html><body><h2>{row[0]}</h2><p>{row[1]}</p></body></html>"

    # Open redirect: blindly redirects to url.
    @app.get("/go")
    def go(url: str = "/"):
        return RedirectResponse(url, status_code=302)

    # Exposed environment file leaking a secret.
    @app.get("/.env", response_class=PlainTextResponse)
    def env():
        return f"APP_ENV=production\nAWS_ACCESS_KEY_ID={FAKE_AWS_KEY}\nDEBUG=0\n"

    return app


def _items_db() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    c.executemany("INSERT INTO items VALUES (?,?)",
                  [(1, "apple"), (2, "apricot"), (3, "banana")])
    c.commit()
    return c


def build_api_app() -> FastAPI:
    """A JSON API with boolean-based SQLi, exposed schema, secret leak, and IDOR."""
    app = FastAPI(title="NotesAPI", version="2.0")  # openapi.json is exposed by default
    db = _items_db()
    tokens = {"tok-user1": "user1", "tok-user2": "user2"}
    notes = {1001: {"id": 1001, "owner": "user2", "text": "user2 private note"}}

    def _user(request: Request) -> str | None:
        auth = request.headers.get("authorization", "")
        return tokens.get(auth[7:]) if auth.lower().startswith("bearer ") else None

    # Boolean-based SQLi: errors swallowed, so only the boolean oracle can confirm.
    @app.get("/api/v2/items")
    def items(filter: str = "a"):
        try:
            rows = db.execute(
                f"SELECT id, name FROM items WHERE name LIKE '%{filter}%'").fetchall()
        except sqlite3.Error:
            rows = []
        return {"results": [{"id": r[0], "name": r[1]} for r in rows]}

    # IDOR: returns any note to any authenticated user (no ownership check).
    @app.get("/api/v2/notes/{note_id}")
    def get_note(note_id: int, request: Request):
        if _user(request) is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        note = notes.get(note_id)
        return note or JSONResponse({"error": "not found"}, status_code=404)

    # Secret leak in a config response.
    @app.get("/api/v2/config")
    def config():
        return {"service": "notes", "session_signing_jwt": FAKE_JWT}

    return app


# ── Ground truth for the evaluation harness ─────────────────────────────
# (app, expected VulnCategory value, locator)
FIXTURE_GROUND_TRUTH = {
    "blog": [
        ("xss", "q"),
        ("sql_injection", "id"),
        ("open_redirect", "url"),
        ("exposed_resource", "/.env"),
        ("sensitive_data", "/.env"),
        ("security_misconfig", "headers"),
    ],
    "api": [
        ("sql_injection", "filter"),
        ("sensitive_data", "/api/v2/config"),
        ("idor", "/api/v2/notes/1001"),
        ("info_disclosure", "schema"),
    ],
}


def build_safe_app() -> FastAPI:
    """A hardened app (parameterized SQL, output encoding, headers, no exposed files).

    The scanner must NOT raise injection/XSS/redirect/IDOR findings here — this is
    the false-positive control.
    """
    import html as _html

    from starlette.middleware.base import BaseHTTPMiddleware

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    db = _posts_db()

    class SecHeaders(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            resp = await call_next(request)
            resp.headers["Content-Security-Policy"] = "default-src 'self'"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Referrer-Policy"] = "no-referrer"
            return resp

    app.add_middleware(SecHeaders)

    @app.get("/", response_class=HTMLResponse)
    def home():
        return ('<html><body><form action="/search" method="get"><input name="q">'
                '</form><a href="/post?id=1">post</a></body></html>')

    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = ""):
        return f"<html><body>Results for: {_html.escape(q)}</body></html>"

    @app.get("/post", response_class=HTMLResponse)
    def post(id: str = "1"):
        try:
            row = db.execute("SELECT title, body FROM posts WHERE id = ?", (id,)).fetchone()
        except sqlite3.Error:
            return HTMLResponse("<html><body>Bad request</body></html>", status_code=400)
        return f"<html><body>{_html.escape(row[0]) if row else 'Not found'}</body></html>"

    @app.get("/go")
    def go(url: str = "/"):
        # Only ever redirect to a fixed internal path (ignores user input).
        return RedirectResponse("/", status_code=302)

    return app
